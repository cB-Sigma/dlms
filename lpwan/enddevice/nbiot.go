// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enddevice

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/wrapper"
)

// NBIoT is a meter on NB-IoT (or LTE-M) behind carrier NAT that sleeps in
// power saving mode.
type NBIoT struct {
	Handler Handler
	// ServerAddress is the logical device's SAP (default 1).
	ServerAddress uint16
	// Server is the head end's host:port.
	Server string
	// Local is the address the meter sends from (default "127.0.0.1:0" when
	// Server is on the loopback, else ":0"): a fresh port each wake, as a
	// NAT rebinding shows it.
	Local string
	// ActiveTime is how long it listens after its last datagram (T3324;
	// default 2 s).
	ActiveTime time.Duration

	mu     sync.Mutex
	calls  int
	served int
	awake  bool
}

// Call wakes the meter: it sends push (a data-notification APDU) to the
// client SAP, serves the head end until it has been idle for ActiveTime,
// and returns when the meter sleeps again.
func (n *NBIoT) Call(client uint16, push []byte) error {
	done, err := n.CallAsync(client, push)
	if err != nil {
		return err
	}
	<-done
	return nil
}

// CallAsync is Call returning at once; the channel closes when the meter
// sleeps.
func (n *NBIoT) CallAsync(client uint16, push []byte) (<-chan struct{}, error) {
	if n.Handler == nil {
		return nil, errors.New("enddevice: NBIoT needs a Handler")
	}
	if n.ActiveTime == 0 {
		n.ActiveTime = 2 * time.Second
	}
	if n.ServerAddress == 0 {
		n.ServerAddress = 1
	}
	srv, err := net.ResolveUDPAddr("udp", n.Server)
	if err != nil {
		return nil, err
	}
	local := n.Local
	if local == "" {
		local = ":0"
		if srv.IP.IsLoopback() {
			local = "127.0.0.1:0"
		}
	}
	pc, err := net.ListenPacket("udp", local)
	if err != nil {
		return nil, err
	}
	first, err := wrapper.Encode(n.ServerAddress, client, push)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	if _, err := pc.WriteTo(first, srv); err != nil {
		_ = pc.Close()
		return nil, err
	}
	n.mu.Lock()
	n.calls++
	n.awake = true
	n.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer pc.Close()
		defer func() { n.mu.Lock(); n.awake = false; n.mu.Unlock() }()
		buf := make([]byte, 65536)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(n.ActiveTime))
			k, from, err := pc.ReadFrom(buf)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return // asleep
			}
			if err != nil {
				return
			}
			if from.String() != srv.String() {
				continue
			}
			h, req, err := wrapper.ParseDatagram(buf[:k])
			if err != nil || !n.Handler.Serves(h.Dst) {
				if dr, ok := n.Handler.(Dropper); ok {
					dr.Drop()
				}
				continue
			}
			resp := n.Handler.Handle(h.Src, append([]byte(nil), req...))
			if resp == nil || h.Dst == wrapper.AllStation {
				continue
			}
			out, err := wrapper.Encode(n.ServerAddress, h.Src, resp)
			if err != nil {
				continue
			}
			n.mu.Lock()
			n.served++
			n.mu.Unlock()
			_, _ = pc.WriteTo(out, srv)
		}
	}()
	return done, nil
}

// Calls is how many times the meter woke.
func (n *NBIoT) Calls() int { n.mu.Lock(); defer n.mu.Unlock(); return n.calls }

// Served is how many requests it answered.
func (n *NBIoT) Served() int { n.mu.Lock(); defer n.mu.Unlock(); return n.served }

// Awake reports whether it is listening now.
func (n *NBIoT) Awake() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.awake }
