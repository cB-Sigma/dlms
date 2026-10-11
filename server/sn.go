// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// The short name services (IEC 62056-5-3:2023 7.4): ReadRequest with
// variable names, parameterized access (selective access, or a method
// that returns data) and block-number access; WriteRequest (a method with
// no return data is invoked by writing its parameter); and
// UnconfirmedWriteRequest.

import (
	"encoding/binary"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
)

// snTarget is what a short name names: an attribute or a method of an
// object.
type snTarget struct {
	obj    classes.Object
	class  uint16
	ln     string
	id     int8
	method bool
}

// resolveSN finds the object and attribute or method of a short name.
func (ss *session) resolveSN(name uint16) (snTarget, bool) {
	s := ss.s
	var base uint16
	var key string
	if name >= 0xFA00 && name < 0xFB00 {
		base = 0xFA00
	} else {
		found := false
		s.mu.Lock()
		for b, k := range s.byBase {
			if b <= name && (!found || b > base) {
				base, key, found = b, k, true
			}
		}
		s.mu.Unlock()
		if !found {
			return snTarget{}, false
		}
	}
	var o classes.Object
	if base == 0xFA00 {
		o = ss.associationObject()
	} else {
		s.mu.Lock()
		o = s.objects[key]
		s.mu.Unlock()
	}
	off := name - base
	if off%8 != 0 {
		return snTarget{}, false
	}
	t := snTarget{obj: o, class: o.ClassID(), ln: o.LogicalName()}
	if c, ok := classes.Lookup(o.ClassID()); ok && c.FirstMethodSN != 0 && off >= c.FirstMethodSN {
		t.method, t.id = true, int8((off-c.FirstMethodSN)/8+1)
		return t, true
	}
	t.id = int8(off/8 + 1)
	return t, true
}

// read serves a ReadRequest.
func (ss *session) read(apdu []byte) []byte {
	b := apdu[1:]
	n, sz := cosem.DecodeLength(b)
	if n < 1 {
		return errUnknown
	}
	b = b[sz:]
	var items [][]byte // encoded Read-Response items
	for i := 0; i < n; i++ {
		if len(b) < 3 {
			return errUnknown
		}
		kind := b[0]
		switch kind {
		case 2, 4:
			name := binary.BigEndian.Uint16(b[1:3])
			b = b[3:]
			var sel *classes.Selector
			if kind == 4 {
				if len(b) < 2 {
					return errUnknown
				}
				p, rest, err := decode(b[1:])
				if err != nil {
					return errUnknown
				}
				sel, b = &classes.Selector{ID: b[0], Parameters: p}, rest
			}
			items = append(items, ss.readOne(name, sel))
		case 5: // block-number-access: the next block of the answer
			nb := binary.BigEndian.Uint16(b[1:3])
			b = b[3:]
			// The client names the block it received (or, as some do, the
			// one it wants next).
			if len(ss.readOut) == 0 || (nb != ss.readBlock && nb != ss.readBlock+1) {
				ss.readOut = nil
				return []byte{0x0C, 0x01, 0x01, byte(classes.BlockNumberInvalid)}
			}
			return ss.nextReadBlock()
		default:
			return errUnknown
		}
	}
	body := berLen(len(items))
	for _, it := range items {
		body = append(body, it...)
	}
	if !ss.fits(len(body)) && ss.conf&cosem.ConformanceBlockGetOrRead != 0 && !ss.inGBT && ss.conf&gbtBit == 0 {
		// The data goes in data blocks: one item's data, or the encoded
		// list of several.
		ss.readOut, ss.readBlock = body, 0
		if len(items) == 1 && items[0][0] == 0x00 {
			ss.readOut = items[0][1:]
		}
		return ss.nextReadBlock()
	}
	return append([]byte{0x0C}, body...)
}

func (ss *session) nextReadBlock() []byte {
	n := min(ss.blockSize(), len(ss.readOut))
	chunk := ss.readOut[:n]
	ss.readOut = ss.readOut[n:]
	ss.readBlock++
	ss.s.count(func(st *Stats) { st.Blocks++ })
	last := byte(0)
	if len(ss.readOut) == 0 {
		last = 1
	}
	out := []byte{0x0C, 0x01, 0x02, last, byte(ss.readBlock >> 8), byte(ss.readBlock)}
	return append(out, octetString(chunk)...)
}

// readOne reads one variable: [0] data or [1] data-access-error.
func (ss *session) readOne(name uint16, sel *classes.Selector) []byte {
	t, ok := ss.resolveSN(name)
	if !ok {
		return []byte{0x01, byte(classes.ObjectUndefined)}
	}
	d := descriptor{class: t.class, ln: t.ln, id: t.id}
	if t.method {
		var p *axdr.DlmsData
		if sel != nil {
			p = sel.Parameters
		}
		ret, res := ss.invoke(d, p)
		if res != 0 {
			return []byte{0x01, res}
		}
		if ret == nil {
			ret = []byte{0x00}
		}
		return append([]byte{0x00}, ret...)
	}
	data, res := ss.getValue(d, sel)
	if res != 0 {
		return []byte{0x01, res}
	}
	return append([]byte{0x00}, data...)
}

// write serves a WriteRequest (answer) or an UnconfirmedWriteRequest.
func (ss *session) write(apdu []byte, confirmed bool) []byte {
	b := apdu[1:]
	n, sz := cosem.DecodeLength(b)
	if n < 1 {
		return errUnknown
	}
	b = b[sz:]
	var names []uint16
	for i := 0; i < n; i++ {
		if len(b) < 3 || b[0] != 2 {
			return errUnknown
		}
		names = append(names, binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
	}
	m, sz := cosem.DecodeLength(b)
	if m != n {
		return errUnknown
	}
	b = b[sz:]
	out := append([]byte{0x0D}, berLen(n)...)
	for _, name := range names {
		v, rest, err := decode(b)
		if err != nil {
			return errUnknown
		}
		b = rest
		res := byte(classes.ObjectUndefined)
		if t, ok := ss.resolveSN(name); ok {
			d := descriptor{class: t.class, ln: t.ln, id: t.id}
			if t.method {
				if v.Tag == axdr.TagNull {
					v = nil
				}
				_, res = ss.invoke(d, v)
			} else {
				res = ss.setValue(d, nil, v)
			}
		}
		if res == 0 {
			out = append(out, 0x00)
		} else {
			out = append(out, 0x01, res)
		}
	}
	if !confirmed {
		return nil
	}
	return out
}
