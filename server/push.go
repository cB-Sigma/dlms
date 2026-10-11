// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// Pushes (IEC 62056-6-2 push setup, IEC 62056-5-3 DataNotification): the
// server builds a data-notification (tag 0x0F: long invoke ID and
// priority, an optional date-time, the notification body) and sends it,
// over the wrapper on TCP or UDP from the server's wPort to the push
// client address, or in a UI frame on the open HDLC links. With
// PushSecurity it is protected in general-glo-ciphering.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/wrapper"
)

// PushOptions are how pushes are sent.
type PushOptions struct {
	// ClientAddress is the wPort pushes go to (default 64, the push
	// client of IS 15959 and of Gurux's examples).
	ClientAddress uint16
	// Security, when set, protects pushes in general-glo-ciphering with
	// its policy, suite and keys (its client address is not used).
	Security *Association
	// Time stamps each notification (the date-time field) when set.
	Time func() time.Time
	// Loc is the zone of the date-time (default UTC).
	Loc *time.Location
}

// DataNotification is the APDU of a data-notification with body.
func (s *Server) DataNotification(invokeID uint32, at time.Time, loc *time.Location, body *axdr.DlmsData) ([]byte, error) {
	b, err := encode(body)
	if err != nil {
		return nil, err
	}
	out := []byte{0x0F, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], invokeID)
	if at.IsZero() {
		out = append(out, 0x00)
	} else {
		if loc == nil {
			loc = time.UTC
		}
		out = append(out, octetString(classes.DateTime(at, loc))...)
	}
	return append(out, b...), nil
}

// protectPush applies the push security, if any.
func (s *Server) protectPush(apdu []byte, o PushOptions) ([]byte, error) {
	a := o.Security
	if a == nil || a.Policy == 0 {
		return apdu, nil
	}
	if len(s.SystemTitle) != 8 {
		return nil, errors.New("protected pushes need the server's system title")
	}
	p, err := cosem.Protect(cosem.Suite(a.Suite), a.Policy, a.Key, a.AuthKey, s.SystemTitle, s.nextIC(), apdu)
	if err != nil {
		return nil, err
	}
	return encodeGeneralGloDed(tagGeneralGlo, s.SystemTitle, p), nil
}

// PushTo sends a data-notification with body to network ("tcp" or "udp")
// address addr in a WPDU from the server's wPort.
func (s *Server) PushTo(network, addr string, body *axdr.DlmsData, o PushOptions) error {
	apdu, err := s.pushAPDU(body, o)
	if err != nil {
		return err
	}
	client := o.ClientAddress
	if client == 0 {
		client = 64
	}
	wpdu, err := wrapper.Encode(s.address(), client, apdu)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.Write(wpdu)
	return err
}

// PushHDLC queues a data-notification with body on every open HDLC link:
// it goes in a UI frame at the next right to talk.
func (s *Server) PushHDLC(body *axdr.DlmsData, o PushOptions) error {
	apdu, err := s.pushAPDU(body, o)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sts) == 0 {
		return errors.New("no HDLC link is open")
	}
	for _, st := range s.sts {
		st.Queue(apdu)
	}
	return nil
}

func (s *Server) pushAPDU(body *axdr.DlmsData, o PushOptions) ([]byte, error) {
	var at time.Time
	if o.Time != nil {
		at = o.Time()
	}
	s.mu.Lock()
	s.ic++
	id := s.ic & 0xFFFFFF
	s.mu.Unlock()
	apdu, err := s.DataNotification(id, at, o.Loc, body)
	if err != nil {
		return nil, err
	}
	return s.protectPush(apdu, o)
}

// Push runs the push of a push setup object (class 40): its object list
// read from the server's objects, as a structure, to its destination
// (send_destination_and_method: TCP or UDP, "host:port").
func (s *Server) Push(setupLN string, o PushOptions) error {
	obj, ok := s.Object(40, setupLN)
	if !ok {
		return fmt.Errorf("no push setup %s", setupLN)
	}
	list, err := obj.Get(2, nil)
	if err != nil {
		return fmt.Errorf("push setup %s: push object list: %w", setupLN, err)
	}
	entries, _ := list.Value.([]*axdr.DlmsData)
	var values []*axdr.DlmsData
	for _, e := range entries {
		f, ok := e.Value.([]*axdr.DlmsData)
		if !ok || len(f) < 3 {
			return fmt.Errorf("push setup %s: an object list entry is not a structure", setupLN)
		}
		class, _ := cosem.Number(*f[0])
		ln, err := lnOf(f[1])
		if err != nil {
			return fmt.Errorf("push setup %s: %w", setupLN, err)
		}
		attr, _ := cosem.Number(*f[2])
		v, err := s.Resolve(uint16(class), ln, int8(attr))
		if err != nil {
			return fmt.Errorf("push setup %s: %d/%s/%v: %w", setupLN, uint16(class), ln, attr, err)
		}
		values = append(values, v)
	}
	dest, err := obj.Get(3, nil)
	if err != nil {
		return fmt.Errorf("push setup %s: destination: %w", setupLN, err)
	}
	f, ok := dest.Value.([]*axdr.DlmsData)
	if !ok || len(f) < 2 {
		return fmt.Errorf("push setup %s: the destination is not a structure", setupLN)
	}
	service, _ := cosem.Number(*f[0])
	addrB, err := octetsValue(f[1])
	if err != nil {
		return fmt.Errorf("push setup %s: destination: %w", setupLN, err)
	}
	network := "tcp"
	switch int(service) {
	case 0:
	case 1:
		network = "udp"
	default:
		return fmt.Errorf("push setup %s: transport service %v is not TCP or UDP", setupLN, service)
	}
	return s.PushTo(network, strings.TrimSpace(string(addrB)), axdr.CreateAxdrStructure(values), o)
}

func octetsValue(d *axdr.DlmsData) ([]byte, error) {
	switch v := d.Value.(type) {
	case string:
		return hex.DecodeString(v)
	case []byte:
		return v, nil
	}
	return nil, errors.New("not an octet string")
}

func lnOf(d *axdr.DlmsData) (string, error) {
	b, err := octetsValue(d)
	if err != nil || len(b) != 6 {
		return "", errors.New("a logical name is not six octets")
	}
	return classes.LNString(b), nil
}
