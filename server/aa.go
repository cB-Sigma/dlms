// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// The application association on the server side (IEC 62056-5-3:2023
// 7.2.4, 6.3): the AARQ checked against the client's Association, the
// AARE with the negotiated xDLMS context, HLS passes 3 and 4 through
// reply_to_HLS_authentication, and the release.

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/cosem"
)

// ACSE service-user diagnostics.
const (
	diagNone             = 0
	diagNoReason         = 1
	diagContext          = 2
	diagMechanismUnknown = 11
	diagMechanismNeeded  = 12
	diagAuthFailure      = 13
	diagAuthRequired     = 14
)

// berItems reads the elements of an AARQ, AARE, RLRQ or RLRE.
func berItems(apdu []byte) (map[byte][]byte, bool) {
	out := map[byte][]byte{}
	if len(apdu) < 2 {
		return out, false
	}
	n, sz := cosem.DecodeLength(apdu[1:])
	if n < 0 || 1+sz+n > len(apdu) {
		return out, false
	}
	b := apdu[1+sz : 1+sz+n]
	for len(b) >= 2 {
		l, s := cosem.DecodeLength(b[1:])
		if l < 0 || 1+s+l > len(b) {
			return out, false
		}
		out[b[0]] = b[1+s : 1+s+l]
		b = b[1+s+l:]
	}
	return out, true
}

// initiateRequest is what an xDLMS InitiateRequest proposes.
type initiateRequest struct {
	dedKey      []byte
	unconfirmed bool
	version     byte
	conformance uint32
	maxPDU      int
}

func parseInitiate(ir []byte) (initiateRequest, bool) {
	var r initiateRequest
	if len(ir) < 2 || ir[0] != 0x01 {
		return r, false
	}
	b := ir[1:]
	if b[0] == 0x01 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return r, false
		}
		r.dedKey = append([]byte(nil), b[2:2+int(b[1])]...)
		b = b[2+int(b[1]):]
	} else {
		b = b[1:]
	}
	if len(b) < 1 {
		return r, false
	}
	if b[0] == 0x01 { // response-allowed given
		if len(b) < 2 {
			return r, false
		}
		r.unconfirmed = b[1] == 0x00
		b = b[2:]
	} else {
		b = b[1:]
	}
	if len(b) < 1 {
		return r, false
	}
	if b[0] == 0x01 { // proposed quality of service
		if len(b) < 2 {
			return r, false
		}
		b = b[2:]
	} else {
		b = b[1:]
	}
	if len(b) < 10 || b[1] != 0x5F || b[2] != 0x1F || b[3] != 0x04 {
		return r, false
	}
	r.version = b[0]
	r.conformance = uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	r.maxPDU = int(binary.BigEndian.Uint16(b[8:10]))
	return r, true
}

// aare builds an AARE.
func (ss *session) aare(ctx, result, diag byte, mech byte, withST bool, stoc, ui []byte) []byte {
	body := []byte{0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, ctx,
		0xA2, 0x03, 0x02, 0x01, result,
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, diag}
	if withST && len(ss.s.SystemTitle) == 8 {
		body = append(body, 0xA4, 0x0A, 0x04, 0x08)
		body = append(body, ss.s.SystemTitle...)
	}
	if mech >= 2 && result == 0 {
		body = append(body, 0x88, 0x02, 0x07, 0x80) // responder ACSE requirements: authentication
		body = append(body, 0x89, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, mech)
		body = append(body, 0xAA)
		body = append(body, berLen(2+len(stoc))...)
		body = append(body, 0x80)
		body = append(body, berLen(len(stoc))...)
		body = append(body, stoc...)
	}
	if ui != nil {
		body = append(body, 0xBE)
		body = append(body, berLen(2+len(ui))...)
		body = append(body, 0x04)
		body = append(body, berLen(len(ui))...)
		body = append(body, ui...)
	}
	return append(append([]byte{0x61}, berLen(len(body))...), body...)
}

func (ss *session) refuse(ctx, diag byte) []byte {
	ss.s.logf("client %d: association refused (diagnostic %d)", ss.client, diag)
	ss.reset()
	ss.s.count(func(st *Stats) { st.Refused++ })
	return ss.aare(ctx, 1, diag, 0, false, nil, nil)
}

// aarq handles passes 1 and 2.
func (ss *session) aarq(apdu []byte) []byte {
	ss.reset()
	s := ss.s
	items, ok := berItems(apdu)
	ctxName := items[0xA1]
	if !ok || len(ctxName) != 9 || ctxName[0] != 0x06 {
		return ss.refuse(1, diagNoReason)
	}
	ctx := ctxName[8]
	a := s.association(ss.client)
	if a == nil {
		return ss.refuse(ctx, diagNoReason)
	}
	sn := ctx == 2 || ctx == 4
	if ctx < 1 || ctx > 4 || sn != s.ShortNames || (a.Context != 0 && ctx != a.Context) {
		return ss.refuse(ctx, diagContext)
	}
	if a.Policy != 0 && ctx != 3 && ctx != 4 {
		// Protected APDUs need the ciphering context.
		return ss.refuse(ctx, diagContext)
	}
	var mech byte
	if m := items[0x8B]; len(m) == 7 {
		mech = m[6]
	} else if len(m) != 0 {
		return ss.refuse(ctx, diagMechanismUnknown)
	}
	if mech != a.Mechanism {
		if mech == 0 {
			return ss.refuse(ctx, diagMechanismNeeded)
		}
		return ss.refuse(ctx, diagMechanismUnknown)
	}
	if v := items[0xA6]; len(v) == 10 && v[0] == 0x04 && v[1] == 0x08 {
		ss.clientST = append([]byte(nil), v[2:]...)
	}
	var auth []byte
	if v := items[0xAC]; len(v) >= 2 && v[0] == 0x80 {
		if l, sz := cosem.DecodeLength(v[1:]); l >= 0 && 1+sz+l <= len(v) {
			auth = append([]byte(nil), v[1+sz:1+sz+l]...)
		}
	}
	switch {
	case mech == 1:
		if subtle.ConstantTimeCompare(auth, a.Secret) != 1 {
			return ss.refuse(ctx, diagAuthFailure)
		}
	case mech >= 2:
		if len(auth) < 8 && mech != 2 || len(auth) == 0 {
			return ss.refuse(ctx, diagAuthFailure)
		}
		ss.ctos = auth
		if mech >= 5 && len(ss.clientST) != 8 {
			return ss.refuse(ctx, diagAuthFailure)
		}
	}
	if a.Policy != 0 && len(ss.clientST) != 8 {
		return ss.refuse(ctx, diagAuthFailure)
	}
	// The xDLMS InitiateRequest, protected with the global key when APDUs
	// are.
	ui := items[0xBE]
	if len(ui) < 2 || ui[0] != 0x04 {
		return ss.refuse(ctx, diagNoReason)
	}
	l, sz := cosem.DecodeLength(ui[1:])
	if l < 0 || 1+sz+l > len(ui) {
		return ss.refuse(ctx, diagNoReason)
	}
	ir := ui[1+sz : 1+sz+l]
	var initIC uint32
	if len(ir) > 0 && ir[0] == 0x21 {
		if a.Policy == 0 || len(ss.clientST) != 8 {
			return ss.refuse(ctx, diagNoReason)
		}
		n, s2 := cosem.DecodeLength(ir[1:])
		if n < 0 || 1+s2+n > len(ir) {
			return ss.refuse(ctx, diagNoReason)
		}
		content := ir[1+s2 : 1+s2+n]
		plain, ic, err := cosem.UnprotectKeys(cosem.Suite(a.Suite), a.Key, nil, a.AuthKey, ss.clientST, content, nil)
		if err != nil {
			s.logf("client %d: the initiate request does not open: %v", ss.client, err)
			return ss.refuse(ctx, diagAuthFailure)
		}
		ss.initPolicy = content[0] & (cosem.SecAuthentication | cosem.SecEncryption)
		ir, initIC = plain, ic
		ss.seenIC, ss.lastIC = map[bool]bool{false: true}, map[bool]uint32{false: ic}
	} else if a.Policy != 0 {
		return ss.refuse(ctx, diagNoReason)
	}
	init, ok := parseInitiate(ir)
	if !ok || init.version < 6 {
		return ss.refuse(ctx, diagNoReason)
	}
	if init.dedKey != nil {
		// A dedicated key travels only authenticated and encrypted.
		if ss.initPolicy != cosem.SecAuthentication|cosem.SecEncryption {
			return ss.refuse(ctx, diagNoReason)
		}
		ss.dedKey = init.dedKey
	}
	if a.InvocationCounter != "" && a.Policy != 0 {
		if o, ok := s.Object(1, a.InvocationCounter); ok {
			if d, err := o.Get(2, nil); err == nil {
				if last, ok := cosem.Number(*d); ok && float64(initIC) <= last {
					s.logf("client %d: invocation counter %d is not above %v", ss.client, initIC, last)
					return ss.refuse(ctx, diagAuthFailure)
				}
			}
		}
		ss.noteIC0(initIC)
	}
	ss.a, ss.shortNames, ss.ciphering = a, sn, ctx == 3 || ctx == 4
	ss.conf = init.conformance & s.conformance(a)
	ss.clientMax = init.maxPDU
	if ss.clientMax == 0 || ss.clientMax > 0xFFFF {
		ss.clientMax = 0xFFFF
	}
	if init.unconfirmed {
		// An unconfirmed association: only the client authenticates
		// (none or low), and nothing is answered.
		if mech >= 2 {
			ss.reset()
			return nil
		}
		ss.associated, ss.noAnswer = true, true
		ss.s.count(func(st *Stats) { st.Associations++ })
		return nil
	}
	vaa := []byte{0x00, 0x07}
	if sn {
		vaa = []byte{0xFA, 0x00}
	}
	maxPDU := uint16(s.maxPDU())
	resp := []byte{0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00,
		byte(ss.conf >> 16), byte(ss.conf >> 8), byte(ss.conf), byte(maxPDU >> 8), byte(maxPDU), vaa[0], vaa[1]}
	if a.Policy != 0 {
		policy := a.Policy
		if ss.dedKey != nil {
			policy = cosem.SecAuthentication | cosem.SecEncryption
		}
		p, err := cosem.Protect(cosem.Suite(a.Suite), policy, a.Key, a.AuthKey, s.SystemTitle, s.nextIC(), resp)
		if err != nil {
			return ss.refuse(ctx, diagNoReason)
		}
		resp = append(append([]byte{0x28}, berLen(len(p))...), p...)
	}
	diag := byte(diagNone)
	if mech >= 2 {
		ss.stoc = challenge(32)
		if mech == 2 {
			ss.stoc = ss.stoc[:16]
		}
		ss.pending, diag = true, diagAuthRequired
	} else {
		ss.associated = true
		ss.s.count(func(st *Stats) { st.Associations++ })
	}
	return ss.aare(ctx, 0, diag, mech, a.Policy != 0 || mech >= 5, ss.stoc, resp)
}

// noteIC0 records the counter of the initiate request.
func (ss *session) noteIC0(ic uint32) {
	if o, ok := ss.s.Object(1, ss.s.association(ss.client).InvocationCounter); ok {
		_ = o.Set(2, axdr.CreateAxdrDoubleLongUnsigned(ic), nil)
	}
}

// hls is the cosem view of the association's HLS settings, from the
// server's side: MeterKey is the client's public key.
func (ss *session) hls() *cosem.HLS {
	a := ss.a
	h := &cosem.HLS{Mechanism: a.Mechanism, Secret: a.Secret, SignKey: a.SigningKey, MeterKey: a.ClientKey}
	h.Security = cosem.Security{Suite: cosem.Suite(a.Suite), Key: a.Key, AuthKey: a.AuthKey, SystemTitle: ss.s.SystemTitle}
	return h
}

// pass3 takes the client's f(StoC) (reply_to_HLS_authentication: an
// ACTION on the association LN object, or with short names a read with
// parameterized access or a write on the association SN object's method
// 8) and answers f(CtoS).
func (ss *session) pass3(apdu []byte) []byte {
	var (
		got  []byte
		ok   bool
		form byte
	)
	invoke := byte(0)
	switch {
	case !ss.shortNames && len(apdu) > 13 && apdu[0] == 0xC3 && apdu[1] == 0x01:
		invoke = apdu[2]
		if binary.BigEndian.Uint16(apdu[3:5]) == 15 && bytes.Equal(apdu[5:11], []byte{0, 0, 40, 0, 0, 255}) && apdu[11] == 1 && apdu[12] == 1 {
			got, ok = octetParam(apdu[13:])
		}
		form = 0xC7
	case ss.shortNames && len(apdu) > 7 && apdu[0] == 0x05 && apdu[1] == 0x01 && apdu[2] == 4:
		if binary.BigEndian.Uint16(apdu[3:5]) == 0xFA58 {
			got, ok = octetParam(apdu[6:])
		}
		form = 0x0C
	case ss.shortNames && len(apdu) > 7 && apdu[0] == 0x06 && apdu[1] == 0x01 && apdu[2] == 2:
		if binary.BigEndian.Uint16(apdu[3:5]) == 0xFA58 && apdu[5] == 0x01 {
			got, ok = octetParam(apdu[6:])
		}
		form = 0x0C
	default:
		return errNotAllowed
	}
	fail := func() []byte {
		ss.s.logf("client %d: HLS pass 3 failed", ss.client)
		ss.reset()
		ss.s.count(func(st *Stats) { st.Refused++ })
		if form == 0xC7 {
			return []byte{0xC7, 0x01, invoke, 250, 0x00}
		}
		return []byte{0x0C, 0x01, 0x01, 250}
	}
	if !ok {
		return fail()
	}
	h := ss.hls()
	if err := h.Check(ss.s.SystemTitle, ss.clientST, ss.stoc, ss.ctos, got); err != nil {
		return fail()
	}
	var ic uint32
	if ss.a.Mechanism == 5 {
		ic = ss.s.nextIC()
	}
	back, err := h.Answer(ss.s.SystemTitle, ss.clientST, ss.ctos, ss.stoc, ic)
	if err != nil {
		return fail()
	}
	ss.pending, ss.associated = false, true
	ss.s.count(func(st *Stats) { st.Associations++ })
	data := append([]byte{0x09}, octetString(back)...)
	if form == 0xC7 {
		return append([]byte{0xC7, 0x01, invoke, 0x00, 0x01, 0x00}, data...)
	}
	return append([]byte{0x0C, 0x01, 0x00}, data...)
}

// octetParam reads an A-XDR octet string (tag 09) at the start of b.
func octetParam(b []byte) ([]byte, bool) {
	d, _, err := decode(b)
	if err != nil || d.Tag != axdr.TagOctetString {
		return nil, false
	}
	switch v := d.Value.(type) {
	case string:
		o, err := hex.DecodeString(v)
		return o, err == nil
	case []byte:
		return v, true
	}
	return nil, false
}

// release answers an RLRQ: a ciphered InitiateRequest in it must open
// under a fresh counter, or the RLRQ is discarded; the RLRE then carries
// the InitiateResponse protected the same way.
func (ss *session) release(apdu []byte) []byte {
	items, _ := berItems(apdu)
	ui := items[0xBE]
	a := ss.a
	plain := []byte{0x63, 0x03, 0x80, 0x01, 0x00}
	if len(ui) == 0 || a == nil || a.Policy == 0 {
		ss.reset()
		return plain
	}
	if len(ui) < 2 || ui[0] != 0x04 {
		return nil
	}
	l, sz := cosem.DecodeLength(ui[1:])
	if l < 0 || 1+sz+l > len(ui) {
		return nil
	}
	ir := ui[1+sz : 1+sz+l]
	if len(ir) < 2 || ir[0] != 0x21 {
		return nil
	}
	n, s2 := cosem.DecodeLength(ir[1:])
	if n < 0 || 1+s2+n > len(ir) {
		return nil
	}
	content := ir[1+s2 : 1+s2+n]
	p, ic, err := cosem.UnprotectKeys(cosem.Suite(a.Suite), a.Key, nil, a.AuthKey, ss.clientST, content, nil)
	if err != nil || len(p) == 0 || p[0] != 0x01 || (ss.seenIC[false] && ic <= ss.lastIC[false]) {
		ss.s.logf("client %d: a ciphered release does not open; discarded", ss.client)
		return nil
	}
	policy := content[0] & (cosem.SecAuthentication | cosem.SecEncryption)
	conf := ss.conf
	maxPDU := uint16(ss.s.maxPDU())
	vaa := []byte{0x00, 0x07}
	if ss.shortNames {
		vaa = []byte{0xFA, 0x00}
	}
	resp := []byte{0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, byte(conf >> 16), byte(conf >> 8), byte(conf), byte(maxPDU >> 8), byte(maxPDU), vaa[0], vaa[1]}
	out, err := cosem.Protect(cosem.Suite(a.Suite), policy, a.Key, a.AuthKey, ss.s.SystemTitle, ss.s.nextIC(), resp)
	ss.reset()
	if err != nil {
		return plain
	}
	glo := append(append([]byte{0x28}, berLen(len(out))...), out...)
	body := append([]byte{0x80, 0x01, 0x00, 0xBE}, berLen(2+len(glo))...)
	body = append(body, 0x04)
	body = append(body, berLen(len(glo))...)
	body = append(body, glo...)
	return append(append([]byte{0x63}, berLen(len(body))...), body...)
}
