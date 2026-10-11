// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package concentrator is a DLMS/COSEM data concentrator (DCU): the head
// end reaches it over the wrapper on TCP, and it serves two modes at once.
//
// Gateway mode (IEC 62056-5-3:2023 annex C): a request carrying the gateway
// prefix (header E6, network ID, physical device address) goes to the end
// device at that network and address, and its answer comes back with the
// prefix (header E7). The prefix is outside the application layer's
// protection, so associations and security stay end to end between the head
// end and each meter. Meters' pushes are forwarded to the head end with the
// prefix.
//
// Logical-device mode: a request without the prefix goes to the logical
// device at the server SAP (wPort) the head end addressed, as with a
// concentrator that presents its meters, or its own management device, as
// logical devices of one physical device (IEC 62056-6-2 logical devices).
//
// End devices and logical devices are Downstream: a server of package
// server in the same process (Local), any gosem transport to a meter on
// the concentrator's local network (Transport: HDLC on a serial bus or
// through a converter, the wrapper to IP meters, NB-IoT), or anything else
// that answers APDUs. Each head-end connection keeps a session per meter,
// client SAP and server SAP, and every session runs on its own, so a slow
// meter does not hold the others up.
package concentrator

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/gateway"
	"github.com/cB-Sigma/dlms/wrapper"
)

// Downstream is a meter (or a logical device) the concentrator serves.
type Downstream interface {
	// Open starts a session for a client SAP and the server SAP the head
	// end addressed. An error drops the requests (the head end times out),
	// as for a meter the local network cannot reach.
	Open(client, server uint16) (Session, error)
}

// Session carries one client's APDUs to a downstream device.
type Session interface {
	// Exchange sends one APDU and returns the answer (nil: none, as for an
	// unconfirmed service).
	Exchange(apdu []byte) ([]byte, error)
	Close() error
}

// ErrUnreachable is returned by a Downstream the local network cannot
// reach now.
var ErrUnreachable = errors.New("the end device is not reachable")

// Meter is an end device behind the gateway.
type Meter struct {
	// Network is the network ID (0 when the concentrator has one local
	// network); Address the physical device address as that network
	// writes it.
	Network byte
	Address []byte
	Device  Downstream
}

// Stats counts what the concentrator did.
type Stats struct {
	Accepts     int            // head-end connections
	Routed      map[string]int // requests passed on, by address (hex)
	Logical     int            // requests to logical devices
	Unknown     int            // prefixed requests for an address no meter has
	Unreachable int            // requests a downstream device did not take
	Pushes      int            // pushes forwarded to the head end
}

// Concentrator is a data concentrator. Set the fields, then Listen or
// Serve.
type Concentrator struct {
	// Meters are the end devices behind the gateway (Add and Remove change
	// them while serving).
	Meters []Meter
	// Logical are the logical devices by server SAP, served to requests
	// without the prefix.
	Logical map[uint16]Downstream
	// ResponsePrefix, when set, gives the prefix of an answer from the
	// request's (default: header E7 with the request's network and
	// address). Some concentrators put their own address there.
	ResponsePrefix func(request gateway.Prefix) gateway.Prefix
	// PushHeader is the header of forwarded pushes: gateway.Request (E6,
	// the default, as annex C has it for data-notifications) or
	// gateway.Response (E7, which some concentrators send).
	PushHeader byte
	// Strict drops requests without the prefix for a server SAP that has
	// no logical device. By default such a request goes to the meter the
	// same client and server SAPs last reached with the prefix on that
	// connection: some clients prefix the AARQ but not the ciphered APDUs
	// after it.
	Strict bool
	// Logf, when set, receives events.
	Logf func(format string, args ...any)

	mu      sync.Mutex
	lns     []net.Listener
	conns   map[*headEnd]bool
	stats   Stats
	closing bool
}

func (c *Concentrator) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Add puts a meter behind the gateway (one at the same network and
// address is replaced).
func (c *Concentrator) Add(m Meter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Meters {
		if c.Meters[i].Network == m.Network && string(c.Meters[i].Address) == string(m.Address) {
			c.Meters[i] = m
			return
		}
	}
	c.Meters = append(c.Meters, m)
}

// Remove takes a meter away.
func (c *Concentrator) Remove(network byte, address []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Meters {
		if c.Meters[i].Network == network && string(c.Meters[i].Address) == string(address) {
			c.Meters = append(c.Meters[:i], c.Meters[i+1:]...)
			return
		}
	}
}

func (c *Concentrator) meter(network byte, address []byte) Downstream {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.Meters {
		if m.Network == network && string(m.Address) == string(address) {
			return m.Device
		}
	}
	return nil
}

// Stats returns the counters so far.
func (c *Concentrator) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.stats
	out.Routed = map[string]int{}
	for k, v := range c.stats.Routed {
		out.Routed[k] = v
	}
	return out
}

func (c *Concentrator) count(f func(*Stats)) {
	c.mu.Lock()
	if c.stats.Routed == nil {
		c.stats.Routed = map[string]int{}
	}
	f(&c.stats)
	c.mu.Unlock()
}

// Listen serves the head end over the wrapper on TCP at addr until Close,
// and returns the address listened on.
func (c *Concentrator) Listen(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.lns = append(c.lns, ln)
	c.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = c.Serve(conn)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// Close stops listening, drops the head end's connections and closes the
// sessions with downstream devices.
func (c *Concentrator) Close() error {
	c.mu.Lock()
	lns, conns := c.lns, c.conns
	c.lns, c.conns = nil, nil
	c.mu.Unlock()
	var first error
	for _, l := range lns {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	for h := range conns {
		h.close()
	}
	return first
}

// headEnd is one head-end connection.
type headEnd struct {
	c        *Concentrator
	rw       io.ReadWriter
	wmu      sync.Mutex
	mu       sync.Mutex
	sessions map[sessionKey]*worker
	last     map[[2]uint16]gateway.Prefix // the last prefix per client and server SAP
	done     chan struct{}
	once     sync.Once
}

type sessionKey struct {
	logical bool
	network byte
	address string
	client  uint16
	server  uint16
}

// worker runs one session's requests in order.
type worker struct {
	in   chan request
	dev  Downstream
	sess Session // nil after a failure: the next request opens another
}

type request struct {
	h        wrapper.Header
	pre      gateway.Prefix
	prefixed bool
	sticky   bool // routed by the last prefix: answered without one
	apdu     []byte
}

func (h *headEnd) close() {
	h.once.Do(func() {
		close(h.done)
		if cl, ok := h.rw.(io.Closer); ok {
			_ = cl.Close()
		}
		h.mu.Lock()
		h.sessions = nil
		h.mu.Unlock()
	})
}

func (h *headEnd) write(b []byte) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	if conn, ok := h.rw.(net.Conn); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	_, err := h.rw.Write(b)
	return err
}

// Serve answers the head end on one connection (TCP, or a stream someone
// else opened) until it ends.
func (c *Concentrator) Serve(rw io.ReadWriter) error {
	h := &headEnd{c: c, rw: rw, sessions: map[sessionKey]*worker{}, done: make(chan struct{})}
	c.mu.Lock()
	if c.conns == nil {
		c.conns = map[*headEnd]bool{}
	}
	c.conns[h] = true
	c.mu.Unlock()
	c.count(func(s *Stats) { s.Accepts++ })
	defer func() {
		h.close()
		c.mu.Lock()
		delete(c.conns, h)
		c.mu.Unlock()
	}()
	for {
		hdr, apdu, err := wrapper.ReadWPDU(rw)
		if errors.Is(err, wrapper.ErrVersion) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		pre, inner, prefixed, err := gateway.Parse(apdu)
		if err != nil {
			c.logf("a request with a broken gateway prefix: %v", err)
			continue
		}
		k := sessionKey{client: hdr.Src, server: hdr.Dst}
		var dev Downstream
		c.mu.Lock()
		_, isLogical := c.Logical[hdr.Dst]
		c.mu.Unlock()
		sticky := false
		if !prefixed && !isLogical && !c.Strict {
			// Some clients (Gurux's, seen with gurux-dlms 1.0.203) leave
			// the prefix off ciphered APDUs after a prefixed AARQ: such
			// a request goes to the meter the same client and server SAPs
			// last reached through the gateway.
			if p, ok := h.lastPrefix(hdr.Src, hdr.Dst); ok {
				pre, prefixed, inner, sticky = p, true, apdu, true
			}
		}
		if prefixed {
			h.notePrefix(hdr.Src, hdr.Dst, pre)
			if dev = c.meter(pre.Network, pre.Address); dev == nil {
				c.count(func(s *Stats) { s.Unknown++ })
				c.logf("no meter at %v", pre)
				continue
			}
			k.network, k.address = pre.Network, string(pre.Address)
			c.count(func(s *Stats) { s.Routed[gateway.FormatAddress(pre.Address)]++ })
		} else {
			c.mu.Lock()
			dev = c.Logical[hdr.Dst]
			c.mu.Unlock()
			if dev == nil {
				continue
			}
			k.logical, inner = true, apdu
			c.count(func(s *Stats) { s.Logical++ })
		}
		w, err := h.worker(k, dev)
		if err != nil {
			c.count(func(s *Stats) { s.Unreachable++ })
			c.logf("session for %v client %d: %v", pre, hdr.Src, err)
			continue
		}
		select {
		case w.in <- request{h: hdr, pre: pre, prefixed: prefixed, sticky: sticky, apdu: append([]byte(nil), inner...)}:
		case <-h.done:
			return nil
		}
	}
}

func (h *headEnd) notePrefix(client, server uint16, p gateway.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		h.last = map[[2]uint16]gateway.Prefix{}
	}
	h.last[[2]uint16{client, server}] = p
}

func (h *headEnd) lastPrefix(client, server uint16) (gateway.Prefix, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.last[[2]uint16{client, server}]
	return p, ok
}

func (h *headEnd) worker(k sessionKey, dev Downstream) (*worker, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if w := h.sessions[k]; w != nil {
		return w, nil
	}
	if h.sessions == nil {
		return nil, errors.New("the connection is closing")
	}
	s, err := dev.Open(k.client, k.server)
	if err != nil {
		return nil, err
	}
	w := &worker{in: make(chan request, 16), dev: dev, sess: s}
	h.sessions[k] = w
	go h.run(k, w)
	return w, nil
}

// run sends a session's requests to its device one at a time and writes
// the answers back with the prefix.
func (h *headEnd) run(k sessionKey, w *worker) {
	c := h.c
	defer func() {
		if w.sess != nil {
			_ = w.sess.Close()
		}
	}()
	for {
		var r request
		select {
		case r = <-w.in:
		case <-h.done:
			return
		}
		var err error
		if w.sess == nil {
			if w.sess, err = w.dev.Open(k.client, k.server); err != nil {
				w.sess = nil
				c.count(func(s *Stats) { s.Unreachable++ })
				c.logf("%v client %d: %v", r.pre, r.h.Src, err)
				continue
			}
		}
		resp, err := w.sess.Exchange(r.apdu)
		if err != nil {
			c.count(func(s *Stats) { s.Unreachable++ })
			c.logf("%v client %d: %v", r.pre, r.h.Src, err)
			if !errors.Is(err, ErrUnreachable) {
				// The session is broken: the next request opens another.
				_ = w.sess.Close()
				w.sess = nil
			}
			continue
		}
		if resp == nil || r.h.Dst == wrapper.AllStation {
			continue
		}
		if r.prefixed && !r.sticky {
			p := gateway.Prefix{Header: gateway.Response, Network: r.pre.Network, Address: r.pre.Address}
			if c.ResponsePrefix != nil {
				p = c.ResponsePrefix(r.pre)
			}
			if resp, err = gateway.Encode(p, resp); err != nil {
				c.logf("%v: %v", r.pre, err)
				continue
			}
		}
		out, err := wrapper.Encode(r.h.Dst, r.h.Src, resp)
		if err != nil {
			continue
		}
		if err := h.write(out); err != nil {
			h.close()
			return
		}
	}
}

// pushFrame is a meter's push as the concentrator forwards it.
func (c *Concentrator) pushFrame(network byte, address []byte, client uint16, apdu []byte) ([]byte, error) {
	hdr := c.PushHeader
	if hdr == 0 {
		hdr = gateway.Request
	}
	b, err := gateway.Encode(gateway.Prefix{Header: hdr, Network: network, Address: address}, apdu)
	if err != nil {
		return nil, err
	}
	return wrapper.Encode(wrapper.ManagementDevice, client, b)
}

// Forward sends a meter's push (a data-notification APDU, protected as the
// meter protected it) to the head end on every open connection, with the
// prefix of the meter's network and address, from the management device
// SAP to the client SAP the push setup names.
func (c *Concentrator) Forward(network byte, address []byte, client uint16, apdu []byte) error {
	out, err := c.pushFrame(network, address, client, apdu)
	if err != nil {
		return err
	}
	c.mu.Lock()
	var hs []*headEnd
	for h := range c.conns {
		hs = append(hs, h)
	}
	c.mu.Unlock()
	if len(hs) == 0 {
		return errors.New("the head end has no connection open to the concentrator")
	}
	var first error
	for _, h := range hs {
		if err := h.write(out); err != nil && first == nil {
			first = err
		}
	}
	if first == nil {
		c.count(func(s *Stats) { s.Pushes++ })
	}
	return first
}

// ForwardTo sends a meter's push to the head end's push listener at addr
// over TCP, for a concentrator that knows where the head end listens.
func (c *Concentrator) ForwardTo(addr string, network byte, address []byte, client uint16, apdu []byte) error {
	out, err := c.pushFrame(network, address, client, apdu)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(out); err != nil {
		return err
	}
	c.count(func(s *Stats) { s.Pushes++ })
	return nil
}

// Func is a Downstream from a function that opens sessions.
type Func func(client, server uint16) (Session, error)

// Open calls f.
func (f Func) Open(client, server uint16) (Session, error) { return f(client, server) }

// SessionFunc is a Session from a function that answers APDUs (Close does
// nothing).
type SessionFunc func(apdu []byte) ([]byte, error)

// Exchange calls f.
func (f SessionFunc) Exchange(apdu []byte) ([]byte, error) { return f(apdu) }

// Close does nothing.
func (f SessionFunc) Close() error { return nil }
