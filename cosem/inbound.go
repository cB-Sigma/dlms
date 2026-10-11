package cosem

// Meter-initiated connections. A meter on 4G behind carrier NAT has no
// address a head end can dial; it opens the TCP connection itself (IEC
// 62056-9-7 lets either side open it). InboundConn carries both what the
// meter sends unasked (its pushes) and the client's associations on that
// one socket, told apart by their wPorts (IEC 62056-4-7): WPDUs for an
// open association go to its transport (Deliver), everything else is a
// push for the caller. Until the caller has proven which meter called
// (an authenticated push, or an HLS association opened on the socket),
// its pushes can be held (HoldUnlessBound) and handed over or dropped
// once the proof is in.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/wrapper"
)

// InboundConn is a meter-initiated TCP connection. The push listener
// reads it; WPDUs for an open association go to that association's
// transport, everything else is handled as a push.
type InboundConn struct {
	Conn net.Conn
	wmu  sync.Mutex // one WPDU written at a time

	mu     sync.Mutex
	subs   map[uint32]*inboundTransport // by client<<16 | server wPort
	closed bool
	state  int8            // 0 unbound, 1 proving the identity, 2 bound
	held   []*Notification // pushes waiting for the proof, in order of arrival
}

// maxHeld bounds the pushes held while an identity is proven.
const maxHeld = 32

// HoldUnlessBound keeps a push while the connection's identity is not
// proven yet (it is neither mapped nor counted); false when bound.
func (ic *InboundConn) HoldUnlessBound(n *Notification) bool {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.state == 2 && len(ic.held) == 0 {
		return false
	}
	if len(ic.held) < maxHeld {
		ic.held = append(ic.held, n)
	}
	return true
}

// TakeHeldOrBind returns the held pushes, or binds the connection when
// none are left, so pushes arriving meanwhile keep their order.
func (ic *InboundConn) TakeHeldOrBind() []*Notification {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	h := ic.held
	ic.held = nil
	if len(h) == 0 && !ic.closed {
		ic.state = 2
	}
	return h
}

// SetState moves the connection from one binding state to another.
func (ic *InboundConn) SetState(from, to int8) bool {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.state != from || ic.closed {
		return false
	}
	ic.state = to
	return true
}

// DropHeld forgets the pushes held for the proof (an impostor's: never
// mapped, never counted).
func (ic *InboundConn) DropHeld() {
	ic.mu.Lock()
	ic.held = nil
	ic.mu.Unlock()
}

// NewInboundConn wraps a connection a meter opened; the caller reads it
// (wrapper.ReadWPDU) and hands each WPDU to Deliver.
func NewInboundConn(c net.Conn) *InboundConn {
	return &InboundConn{Conn: c, subs: map[uint32]*inboundTransport{}}
}

func subKey(client, server uint16) uint32 { return uint32(client)<<16 | uint32(server) }

// Deliver hands a WPDU to the association it answers, if one is open.
func (ic *InboundConn) Deliver(h wrapper.Header, apdu []byte) bool {
	if len(apdu) > 0 && apdu[0] == 0x0F {
		return false // a data-notification is a push, whatever its wPorts
	}
	ic.mu.Lock()
	t := ic.subs[subKey(h.Dst, h.Src)]
	ic.mu.Unlock()
	if t == nil {
		return false
	}
	t.receive(apdu)
	return true
}

// Shut marks the connection closed and closes the socket.
func (ic *InboundConn) Shut() {
	ic.mu.Lock()
	ic.closed = true
	ic.mu.Unlock()
	_ = ic.Conn.Close()
}

// IsClosed reports whether Shut closed the connection.
func (ic *InboundConn) IsClosed() bool {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.closed
}

func (ic *InboundConn) write(b []byte, timeout time.Duration) error {
	ic.wmu.Lock()
	defer ic.wmu.Unlock()
	_ = ic.Conn.SetWriteDeadline(time.Now().Add(timeout))
	for n := 0; n < len(b); {
		k, err := ic.Conn.Write(b[n:])
		n += k
		if err != nil {
			return err
		}
	}
	return nil
}

// inboundTransport is one association's wrapper transport over an
// inbound connection (a gosem transport). Disconnect ends the association's
// use of the socket without closing it.
type inboundTransport struct {
	ic      *InboundConn
	timeout time.Duration

	mu        sync.Mutex
	client    uint16
	server    uint16
	connected bool
	dc        gdlms.DataChannel
	logger    *log.Logger
}

// Transport is a gosem transport for an association of client with
// server on the connection; timeout bounds each request (default 10s).
func (ic *InboundConn) Transport(client, server int, timeout time.Duration) gdlms.Transport {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &inboundTransport{ic: ic, timeout: timeout, client: uint16(client), server: uint16(server)}
}

// ErrInboundClosed is the error of a request on a closed connection.
var ErrInboundClosed = errors.New("the meter's inbound connection is closed")

func (t *inboundTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connected {
		return nil
	}
	t.ic.mu.Lock()
	defer t.ic.mu.Unlock()
	if t.ic.closed {
		return ErrInboundClosed
	}
	k := subKey(t.client, t.server)
	if t.ic.subs[k] != nil {
		return fmt.Errorf("client wPort %d already has an association on the meter's connection", t.client)
	}
	t.ic.subs[k] = t
	t.connected = true
	return nil
}

func (t *inboundTransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected {
		return nil
	}
	t.ic.mu.Lock()
	if k := subKey(t.client, t.server); t.ic.subs[k] == t {
		delete(t.ic.subs, k)
	}
	t.ic.mu.Unlock()
	t.connected = false
	return nil
}

func (t *inboundTransport) Close() {
	_ = t.Disconnect()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
		t.dc = nil
	}
}

func (t *inboundTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && !t.ic.IsClosed()
}

func (t *inboundTransport) SetAddress(client, server int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client, t.server = uint16(client), uint16(server)
}

func (t *inboundTransport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
	}
	t.dc = dc
}

func (t *inboundTransport) SetLogger(l *log.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logger = l
}

func (t *inboundTransport) Send(apdu []byte) error {
	t.mu.Lock()
	ok, client, server := t.connected, t.client, t.server
	t.mu.Unlock()
	if !ok {
		return errors.New("not connected")
	}
	if t.ic.IsClosed() {
		return ErrInboundClosed
	}
	b, err := wrapper.Encode(client, server, apdu)
	if err != nil {
		return err
	}
	if err := t.ic.write(b, t.timeout); err != nil {
		t.ic.Shut()
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// SendBroadcast sends an unconfirmed APDU as an ordinary WPDU.
func (t *inboundTransport) SendBroadcast(apdu []byte) error { return t.Send(apdu) }

// receive passes an APDU on; held under t.mu so Close cannot close the
// channel under it, and never blocking the connection's reader (the
// reception channel is drained by the security layer, secure.go).
func (t *inboundTransport) receive(apdu []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.logger != nil {
		t.logger.Printf("inbound RX %d→%d % X", t.server, t.client, apdu)
	}
	if t.dc == nil {
		return
	}
	select {
	case t.dc <- append([]byte(nil), apdu...):
	case <-time.After(t.timeout):
	}
}

// Bound reports whether the caller's identity is proven.
func (ic *InboundConn) Bound() bool {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.state == 2
}
