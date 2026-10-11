// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package concentrator

import (
	"errors"
	"fmt"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/server"
	"github.com/cB-Sigma/dlms/wrapper"
)

// Local serves a server of package server in the same process: a meter
// the concentrator emulates, or the concentrator's own management logical
// device. Requests for another server SAP than the server's Address
// (default 1) are dropped, except in logical-device mode, where the SAP
// already chose the device.
func Local(s *server.Server) Downstream {
	return Func(func(client, sap uint16) (Session, error) {
		ss, err := s.NewSession(client)
		if err != nil {
			return nil, err
		}
		want := s.Address
		if want == 0 {
			want = 1
		}
		return SessionFunc(func(apdu []byte) ([]byte, error) {
			if sap != want && sap != wrapper.AllStation && sap != 0 {
				return nil, nil
			}
			return ss.Handle(apdu), nil
		}), nil
	})
}

// LogicalDevice serves a server of package server as a logical device: the
// server SAP the head end addressed is taken as the server's.
func LogicalDevice(s *server.Server) Downstream {
	return Func(func(client, _ uint16) (Session, error) {
		ss, err := s.NewSession(client)
		if err != nil {
			return nil, err
		}
		return SessionFunc(func(apdu []byte) ([]byte, error) { return ss.Handle(apdu), nil }), nil
	})
}

// Transport reaches a meter over a gosem transport on the concentrator's
// local network: HDLC (package hdlc) on a serial bus or a converter, the
// wrapper (package wrapper) to an IP meter, DLMS over NB-IoT (package
// lpwan), or any other.
type Transport struct {
	// Dial opens a transport for a client SAP and the meter's server SAP
	// (not yet connected).
	Dial func(client, server int) (gdlms.Transport, error)
	// Timeout bounds the wait for an answer (default 30 s). Unconfirmed
	// requests are not waited for.
	Timeout time.Duration
	// Push, when set, receives APDUs the meter sends unasked
	// (data-notifications); a concentrator forwards them with Forward.
	Push func(client uint16, apdu []byte)
}

// Open dials the meter for one client.
func (t *Transport) Open(client, server uint16) (Session, error) {
	if t.Dial == nil {
		return nil, errors.New("concentrator: Transport needs Dial")
	}
	tr, err := t.Dial(int(client), int(server))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if err := tr.Connect(); err != nil {
		tr.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	s := &transportSession{t: t, tr: tr, client: client, in: make(gdlms.DataChannel, 16), done: make(chan struct{})}
	tr.SetReception(s.in)
	go s.read()
	return s, nil
}

type transportSession struct {
	t      *Transport
	tr     gdlms.Transport
	client uint16
	in     gdlms.DataChannel
	mu     sync.Mutex
	wait   chan []byte
	done   chan struct{}
	once   sync.Once
}

// read takes everything the meter sends: the answer waited for, or a push.
func (s *transportSession) read() {
	for {
		select {
		case b, ok := <-s.in:
			if !ok {
				return
			}
			// A data-notification is a push; anything else answers the
			// request waited for, or, with none waited for, is a push
			// (a protected data-notification).
			s.mu.Lock()
			w := s.wait
			answer := w != nil && (len(b) == 0 || b[0] != 0x0F)
			if answer {
				s.wait = nil
			}
			s.mu.Unlock()
			if answer {
				w <- b
				continue
			}
			if s.t.Push != nil && len(b) > 0 {
				s.t.Push(s.client, append([]byte(nil), b...))
			}
		case <-s.done:
			return
		}
	}
}

// unconfirmed says whether a request expects no answer: a get, set or
// action request with the service class bit clear, or an unconfirmed
// write.
func unconfirmed(apdu []byte) bool {
	if len(apdu) >= 3 && (apdu[0] == 0xC0 || apdu[0] == 0xC1 || apdu[0] == 0xC3) {
		return apdu[2]&0x40 == 0
	}
	return len(apdu) > 0 && apdu[0] == 0x16
}

func (s *transportSession) Exchange(apdu []byte) ([]byte, error) {
	if unconfirmed(apdu) {
		return nil, s.tr.Send(apdu)
	}
	w := make(chan []byte, 1)
	s.mu.Lock()
	s.wait = w
	s.mu.Unlock()
	if err := s.tr.Send(apdu); err != nil {
		return nil, err
	}
	timeout := s.t.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	select {
	case b := <-w:
		return b, nil
	case <-time.After(timeout):
		s.mu.Lock()
		s.wait = nil
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: no answer in %v", ErrUnreachable, timeout)
	case <-s.done:
		return nil, errors.New("the session is closed")
	}
}

func (s *transportSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.tr.Disconnect()
		s.tr.Close()
	})
	return nil
}
