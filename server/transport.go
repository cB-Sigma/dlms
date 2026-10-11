// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// The supporting layers: the wrapper over TCP and UDP (IEC 62056-4-7) and
// HDLC (IEC 62056-46, the station of package hdlc), each client address a
// session of its own; and general block transfer above them.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/wrapper"
)

// answer runs an APDU through the session and, when general block
// transfer was negotiated and the answer is longer than the client takes,
// sends it in blocks.
func (ss *session) answer(apdu []byte) []byte {
	resp := ss.handle(apdu)
	if len(resp) > 0 && resp[0] != 0xE0 && !ss.fits(len(resp)-30) && ss.conf&gbtBit != 0 && ss.associated {
		return ss.startGBT(resp)
	}
	return resp
}

// gbt takes a general-block-transfer APDU: a block of the client's
// request, or its acknowledgement of one of ours.
func (ss *session) gbt(apdu []byte) []byte {
	if ss.conf&gbtBit == 0 {
		return errNotAllowed
	}
	if len(apdu) < 6 {
		return errUnknown
	}
	ctrl := apdu[1]
	num := binary.BigEndian.Uint16(apdu[2:4])
	l, sz := cosem.DecodeLength(apdu[6:])
	if l < 0 || 6+sz+l != len(apdu) {
		return errUnknown
	}
	data := apdu[6+sz:]
	if len(data) == 0 && len(ss.gbtOut) > 0 {
		return ss.nextGBT()
	}
	if num != ss.gbtNext+1 {
		ss.gbtIn, ss.gbtNext = nil, 0
		if num != 1 {
			return errUnknown
		}
	}
	ss.gbtIn, ss.gbtNext, ss.gbtRecvN = append(ss.gbtIn, data...), num, num
	if ctrl&0x80 == 0 {
		// More request blocks: acknowledge this one.
		return gbtBlock(false, ss.gbtSent, num, nil)
	}
	inner := ss.gbtIn
	ss.gbtIn, ss.gbtNext = nil, 0
	ss.inGBT = true
	resp := ss.protected(inner)
	ss.inGBT = false
	if len(resp) == 0 || ss.noAnswer {
		return nil
	}
	return ss.startGBT(resp)
}

func (ss *session) startGBT(resp []byte) []byte {
	ss.gbtOut = nil
	n := ss.blockSize()
	for len(resp) > 0 {
		k := min(n, len(resp))
		ss.gbtOut = append(ss.gbtOut, resp[:k])
		resp = resp[k:]
	}
	return ss.nextGBT()
}

func (ss *session) nextGBT() []byte {
	chunk := ss.gbtOut[0]
	ss.gbtOut = ss.gbtOut[1:]
	ss.gbtSent++
	ss.s.count(func(st *Stats) { st.GBTBlocks++ })
	return gbtBlock(len(ss.gbtOut) == 0, ss.gbtSent, ss.gbtRecvN, chunk)
}

// gbtBlock is one general-block-transfer APDU (window 1, no streaming).
func gbtBlock(last bool, num, ack uint16, data []byte) []byte {
	ctrl := byte(0x01)
	if last {
		ctrl |= 0x80
	}
	out := []byte{0xE0, ctrl, byte(num >> 8), byte(num), byte(ack >> 8), byte(ack)}
	return append(out, octetString(data)...)
}

// ServeWrapper answers the wrapper on one connection (TCP, or a stream
// someone else opened) until it ends; each client wPort has its own
// session. WPDUs for another server wPort are dropped; the all-station
// wPort is served but never answered.
func (s *Server) ServeWrapper(c io.ReadWriter) error {
	if err := s.check(); err != nil {
		return err
	}
	sessions := map[uint16]*session{}
	for {
		h, apdu, err := wrapper.ReadWPDU(c)
		if errors.Is(err, wrapper.ErrVersion) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if h.Dst != s.address() && h.Dst != wrapper.AllStation {
			continue
		}
		ss := sessions[h.Src]
		if ss == nil {
			ss = newSession(s, h.Src)
			sessions[h.Src] = ss
		}
		resp := ss.answer(apdu)
		if resp == nil || h.Dst == wrapper.AllStation {
			continue
		}
		out, err := wrapper.Encode(s.address(), h.Src, resp)
		if err != nil {
			return err
		}
		if _, err := c.Write(out); err != nil {
			return err
		}
	}
}

// ListenWrapper serves the wrapper over TCP at addr ("127.0.0.1:0",
// ":4059") until Close, and returns the address listened on.
func (s *Server) ListenWrapper(addr string) (string, error) {
	return s.listen(addr, func(c net.Conn) { _ = s.ServeWrapper(c) })
}

// ListenHDLC serves HDLC over TCP at addr (a meter behind a serial to
// Ethernet converter) until Close.
func (s *Server) ListenHDLC(addr string) (string, error) {
	return s.listen(addr, func(c net.Conn) { _ = s.ServeHDLC(c) })
}

func (s *Server) listen(addr string, serve func(net.Conn)) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.track(c, true)
			go func() {
				defer func() {
					_ = c.Close()
					s.track(c, false)
				}()
				serve(c)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// ListenUDP serves the wrapper over UDP at addr until Close: one WPDU per
// datagram each way, a session per client address and port.
func (s *Server) ListenUDP(addr string) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pcs = append(s.pcs, pc)
	s.mu.Unlock()
	go func() {
		sessions := map[string]*session{}
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			h, apdu, err := wrapper.ParseDatagram(buf[:n])
			if err != nil || (h.Dst != s.address() && h.Dst != wrapper.AllStation) {
				continue
			}
			k := fmt.Sprintf("%s/%d", from, h.Src)
			ss := sessions[k]
			if ss == nil {
				ss = newSession(s, h.Src)
				sessions[k] = ss
			}
			resp := ss.answer(append([]byte(nil), apdu...))
			if resp == nil || h.Dst == wrapper.AllStation {
				continue
			}
			if out, err := wrapper.Encode(s.address(), h.Src, resp); err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return pc.LocalAddr().String(), nil
}

// ServeHDLC answers HDLC on rw (a serial port, a converter's connection)
// until it ends: the server is a secondary station at Address (upper) and
// HDLCAddress (lower); each client address is a data link of its own,
// with its session from SNRM to DISC. APDUs in UI frames are served and
// never answered.
func (s *Server) ServeHDLC(rw io.ReadWriter) error {
	if err := s.check(); err != nil {
		return err
	}
	size := s.HDLCAddressSize
	if size == 0 {
		size = 1
	}
	var mu sync.Mutex
	sessions := map[int]*session{}
	st := &hdlc.Station{Upper: int(s.address()), Lower: s.HDLCAddress, Size: size, Own: s.HDLCParams,
		Inactivity: s.HDLCInactivity,
		OnLink: func(client int, up bool) {
			mu.Lock()
			defer mu.Unlock()
			if up {
				sessions[client] = newSession(s, uint16(client))
			} else {
				delete(sessions, client)
			}
		},
		Log: func(event string) { s.logf("hdlc: %s", event) },
	}
	st.Handle = func(client int, apdu []byte, unconfirmed bool) []byte {
		mu.Lock()
		ss := sessions[client]
		if ss == nil {
			ss = newSession(s, uint16(client))
			sessions[client] = ss
		}
		mu.Unlock()
		resp := ss.answer(apdu)
		if unconfirmed {
			return nil
		}
		return resp
	}
	s.mu.Lock()
	s.sts = append(s.sts, st)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		for i, x := range s.sts {
			if x == st {
				s.sts = append(s.sts[:i], s.sts[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}()
	err := st.Serve(rw)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
