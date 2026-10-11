// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// One client's session: the association state, the protection of its
// APDUs and the dispatch of its services.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/cosem"
)

type session struct {
	s      *Server
	client uint16
	a      *Association

	associated bool
	pending    bool // HLS passes 1 and 2 done, waiting for pass 3
	ciphering  bool // a ciphered context was agreed
	shortNames bool
	conf       uint32 // negotiated conformance
	clientMax  int
	clientST   []byte
	ctos, stoc []byte
	dedKey     []byte
	dedIC      uint32
	lastIC     map[bool]uint32
	seenIC     map[bool]bool
	initPolicy byte // the protection of the initiate request (and of the release)
	noAnswer   bool // an unconfirmed association: nothing is answered

	// Block transfer state.
	getOut    []byte // GET data still to send
	getBlock  uint32
	setAttr   []byte // set-request-with-first-datablock: descriptor and access selection
	setList   [][]byte
	setBuf    []byte
	setBlock  uint32
	actMethod []byte // action-request-with-first-pblock: method descriptor
	actList   [][]byte
	actBuf    []byte
	actBlock  uint32
	actOut    []byte // ACTION return data still to send
	actOutN   uint32
	readOut   []byte // short names: read data still to send
	readBlock uint16
	writeBuf  []byte
	// General block transfer.
	gbtIn    []byte
	gbtNext  uint16
	gbtOut   [][]byte
	gbtSent  uint16
	inGBT    bool
	gbtRecvN uint16
}

func newSession(s *Server, client uint16) *session {
	return &session{s: s, client: client}
}

func (ss *session) reset() {
	*ss = session{s: ss.s, client: ss.client}
}

// exception is an exception-response: state error and service error.
func exception(state, service byte) []byte { return []byte{0xD8, state, service} }

var (
	errNotAllowed   = exception(1, 1) // service not allowed
	errUnknown      = exception(1, 2) // service unknown
	errDeciphering  = exception(2, 5) // other: deciphering error (service error "invocation counter" etc.)
	errNotSupported = exception(2, 2) // service not supported
)

// handle answers one APDU from the client (nil: no answer).
func (ss *session) handle(apdu []byte) []byte {
	if len(apdu) == 0 {
		return nil
	}
	switch apdu[0] {
	case 0x60:
		return ss.aarq(apdu)
	case 0x62:
		return ss.release(apdu)
	}
	if ss.a == nil || (!ss.associated && !ss.pending) {
		return errNotAllowed
	}
	if apdu[0] == 0xE0 {
		return ss.gbt(apdu)
	}
	resp := ss.protected(apdu)
	if ss.noAnswer {
		return nil
	}
	return resp
}

// Protected request tags: glo- and ded- forms and the plain tag they carry.
var protectedRequests = map[byte]struct {
	plain byte
	ded   bool
}{
	0xC8: {0xC0, false}, 0xC9: {0xC1, false}, 0xCB: {0xC3, false},
	0xD0: {0xC0, true}, 0xD1: {0xC1, true}, 0xD3: {0xC3, true},
	0x25: {0x05, false}, 0x26: {0x06, false}, 0x36: {0x16, false},
	0x45: {0x05, true}, 0x46: {0x06, true}, 0x56: {0x16, true},
}

const (
	tagGeneralGlo = 0xDB
	tagGeneralDed = 0xDC
)

// protected removes the protection of a request, runs it and protects the
// answer in the same form. Without protection it runs plain requests.
func (ss *session) protected(apdu []byte) []byte {
	a := ss.a
	if a.Policy == 0 {
		if _, p := protectedRequests[apdu[0]]; p || apdu[0] == tagGeneralGlo || apdu[0] == tagGeneralDed {
			return errNotAllowed
		}
		return ss.dispatch(apdu)
	}
	var (
		content []byte
		ded     bool
		general bool
		want    byte
	)
	switch {
	case apdu[0] == tagGeneralGlo || apdu[0] == tagGeneralDed:
		st, c, ok := decodeGeneralGloDed(apdu)
		if !ok || !bytes.Equal(st, ss.clientST) {
			return errDeciphering
		}
		content, ded, general = c, apdu[0] == tagGeneralDed, true
	default:
		p, ok := protectedRequests[apdu[0]]
		if !ok {
			// Plain requests are refused once APDUs are protected.
			return errNotAllowed
		}
		n, sz := cosem.DecodeLength(apdu[1:])
		if n < 0 || 1+sz+n != len(apdu) {
			return errDeciphering
		}
		content, ded, want = apdu[1+sz:], p.ded, p.plain
	}
	key := a.Key
	if ded {
		if ss.dedKey == nil {
			return errNotAllowed
		}
		key = a.Key
		key = ss.dedKey
	}
	var bkey []byte
	if !ded {
		bkey = a.BroadcastKey
	}
	plain, ic, err := cosem.UnprotectKeys(cosem.Suite(a.Suite), key, bkey, a.AuthKey, ss.clientST, content, nil)
	if err != nil || len(plain) == 0 || (want != 0 && plain[0] != want) {
		ss.s.logf("client %d: a protected request does not open: %v", ss.client, err)
		return errDeciphering
	}
	if len(content) > 0 && content[0]&cosem.SecBroadcastKey != 0 {
		// Under the broadcast key: unconfirmed services only, never answered.
		ss.s.mu.Lock()
		fresh := ic > ss.s.bcast
		if fresh {
			ss.s.bcast = ic
		}
		ss.s.mu.Unlock()
		if fresh {
			ss.dispatch(plain)
		}
		return nil
	}
	if ss.seenIC == nil {
		ss.seenIC, ss.lastIC = map[bool]bool{}, map[bool]uint32{}
	}
	if ss.seenIC[ded] && ic <= ss.lastIC[ded] {
		ss.s.logf("client %d: invocation counter %d replayed", ss.client, ic)
		return errDeciphering
	}
	ss.seenIC[ded], ss.lastIC[ded] = true, ic
	ss.noteIC(ic)
	ss.s.count(func(st *Stats) {
		switch {
		case general && ded:
			st.GeneralDed++
		case general:
			st.GeneralGlo++
		default:
			st.ServiceSpecific++
		}
	})
	resp := ss.dispatch(plain)
	if len(resp) == 0 || resp[0] == 0xD8 {
		return resp
	}
	policy := a.Policy
	out, err := ss.protect(resp, policy, ded, general)
	if err != nil {
		ss.s.logf("client %d: protecting an answer: %v", ss.client, err)
		return exception(2, 0)
	}
	return out
}

// noteIC records the client's last counter in its invocation counter
// object.
func (ss *session) noteIC(ic uint32) {
	if ss.a.InvocationCounter == "" {
		return
	}
	if o, ok := ss.s.Object(1, ss.a.InvocationCounter); ok {
		_ = o.Set(2, axdr.CreateAxdrDoubleLongUnsigned(ic), nil)
	}
}

// Plain response tags and their glo- and ded- forms.
var gloResponse = map[byte]byte{0xC4: 0xCC, 0xC5: 0xCD, 0xC7: 0xCF, 0x0C: 0x2C, 0x0D: 0x2D, 0x0E: 0x2E}
var dedResponse = map[byte]byte{0xC4: 0xD4, 0xC5: 0xD5, 0xC7: 0xD7, 0x0C: 0x4C, 0x0D: 0x4D}

// protect protects an answer in the form the request came in.
func (ss *session) protect(resp []byte, policy byte, ded, general bool) ([]byte, error) {
	a := ss.a
	key, ic := a.Key, uint32(0)
	if ded {
		ss.dedIC++
		key, ic = ss.dedKey, ss.dedIC
	} else {
		ic = ss.s.nextIC()
	}
	p, err := cosem.Protect(cosem.Suite(a.Suite), policy, key, a.AuthKey, ss.s.SystemTitle, ic, resp)
	if err != nil {
		return nil, err
	}
	if general || resp[0] == 0xDA {
		tag := byte(tagGeneralGlo)
		if ded {
			tag = tagGeneralDed
		}
		return encodeGeneralGloDed(tag, ss.s.SystemTitle, p), nil
	}
	tag, ok := gloResponse[resp[0]]
	if ded {
		tag, ok = dedResponse[resp[0]]
	}
	if !ok {
		return nil, fmt.Errorf("answer tag %#x has no protected form", resp[0])
	}
	return append(append([]byte{tag}, berLen(len(p))...), p...), nil
}

// dispatch runs a plain request.
func (ss *session) dispatch(apdu []byte) []byte {
	if len(apdu) < 2 {
		return errUnknown
	}
	if ss.pending {
		return ss.pass3(apdu)
	}
	if !ss.associated {
		return errNotAllowed
	}
	if ss.shortNames {
		switch apdu[0] {
		case 0x05:
			return ss.read(apdu)
		case 0x06:
			return ss.write(apdu, true)
		case 0x16:
			ss.write(apdu, false)
			return nil
		}
		return errNotSupported
	}
	switch apdu[0] {
	case 0xC0:
		return ss.get(apdu)
	case 0xC1:
		return ss.set(apdu)
	case 0xC3:
		return ss.action(apdu)
	case 0xD9:
		return ss.access(apdu)
	}
	return errUnknown
}

// berLen is a BER (and A-XDR) length.
func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

// octetString is an A-XDR octet string without its tag (length, octets).
func octetString(b []byte) []byte { return append(berLen(len(b)), b...) }

func encodeGeneralGloDed(tag byte, st, content []byte) []byte {
	out := append([]byte{tag}, octetString(st)...)
	return append(out, octetString(content)...)
}

func decodeGeneralGloDed(apdu []byte) (st, content []byte, ok bool) {
	b := apdu[1:]
	n, sz := cosem.DecodeLength(b)
	if n < 0 || sz+n > len(b) {
		return nil, nil, false
	}
	st, b = b[sz:sz+n], b[sz+n:]
	n, sz = cosem.DecodeLength(b)
	if n < 0 || sz+n != len(b) {
		return nil, nil, false
	}
	return st, b[sz:], true
}

// encode is the A-XDR encoding of d (null-data as one octet).
func encode(d *axdr.DlmsData) ([]byte, error) {
	if d == nil {
		return []byte{0x00}, nil
	}
	r, _, _ := cosem.EncodeAXDR(d)
	if len(r) == 0 {
		return nil, fmt.Errorf("the value (tag %d) does not encode", d.Tag)
	}
	return r, nil
}

// decode reads one A-XDR value from b and returns the rest.
func decode(b []byte) (*axdr.DlmsData, []byte, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("no data")
	}
	src := b
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return nil, nil, err
	}
	return &d, src, nil
}

func challenge(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func u32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
