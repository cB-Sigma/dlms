// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package enddevice is the meter end of DLMS/COSEM over LoRaWAN and
// NB-IoT, the other side of package lpwan's head-end links.
//
// LoRaWAN: the device end of SCHC (RFC 8724, RFC 9011) on a LoRaWAN
// radio. Uplinks are compressed with the head end's rules and fragmented
// with ACK-on-Error when they do not fit one frame; downlinks are
// reassembled (ACK-Always) and acknowledged; as a class A device the meter
// can only be reached in the receive window after one of its uplinks, so
// it sends an empty frame every Poll. Settings (FPorts, header, rules)
// must be the head end's: the DLMS UA LoRaWAN profile is not public, so
// its choices are settings here as in package lpwan.
//
// NB-IoT: a meter behind carrier NAT that sleeps in power saving mode. It
// wakes, sends a push over UDP with the wrapper to the head end from a
// fresh source port, answers the head end's requests until it has been
// idle for ActiveTime (T3324), then sleeps and cannot be reached.
//
// Both serve a Handler: a server of package server (ServerHandler), or
// any other meter model.
package enddevice

import (
	"sync"

	"github.com/cB-Sigma/dlms/server"
)

// Handler answers APDUs for the end device's logical device.
type Handler interface {
	// Serves reports whether the device answers a destination SAP (its
	// logical device, or the all-station address, which it never
	// answers).
	Serves(server uint16) bool
	// Handle answers one APDU from a client SAP (nil: nothing).
	Handle(client uint16, apdu []byte) []byte
}

// Dropper is a Handler told about requests dropped for their SAP.
type Dropper interface {
	Drop()
}

// ServerHandler serves a server of package server: a session per client
// SAP, kept until Reset.
func ServerHandler(s *server.Server) *SessionHandler {
	return &SessionHandler{s: s, sessions: map[uint16]*server.Session{}}
}

// SessionHandler is a Handler over a server of package server.
type SessionHandler struct {
	s        *server.Server
	mu       sync.Mutex
	sessions map[uint16]*server.Session
}

// Serves reports the server's own SAP (Address, default 1) and the
// all-station address.
func (h *SessionHandler) Serves(sap uint16) bool {
	a := h.s.Address
	if a == 0 {
		a = 1
	}
	return sap == a || sap == 0x7F
}

// Handle answers one APDU in the client's session.
func (h *SessionHandler) Handle(client uint16, apdu []byte) []byte {
	h.mu.Lock()
	ss := h.sessions[client]
	if ss == nil {
		var err error
		if ss, err = h.s.NewSession(client); err != nil {
			h.mu.Unlock()
			return nil
		}
		h.sessions[client] = ss
	}
	h.mu.Unlock()
	return ss.Handle(apdu)
}

// Reset forgets the sessions (a meter that rebooted).
func (h *SessionHandler) Reset() {
	h.mu.Lock()
	h.sessions = map[uint16]*server.Session{}
	h.mu.Unlock()
}
