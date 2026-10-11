// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// The logical name services (IEC 62056-5-3:2023 7.3): GET, SET and ACTION
// in their normal, with-list and block forms, and ACCESS.

import (
	"encoding/binary"
	"errors"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
)

// descriptor is a COSEM attribute or method descriptor.
type descriptor struct {
	class uint16
	ln    string
	id    int8
}

func parseDescriptor(b []byte) (descriptor, []byte, error) {
	if len(b) < 9 {
		return descriptor{}, nil, errors.New("short descriptor")
	}
	return descriptor{class: binary.BigEndian.Uint16(b), ln: lnText(b[2:8]), id: int8(b[8])}, b[9:], nil
}

func lnText(b []byte) string { return classes.LNString(b) }

// selection reads an optional access selection.
func selection(b []byte) (*classes.Selector, []byte, error) {
	if len(b) < 1 {
		return nil, nil, errors.New("no access selection flag")
	}
	if b[0] == 0 {
		return nil, b[1:], nil
	}
	if len(b) < 2 {
		return nil, nil, errors.New("short access selection")
	}
	d, rest, err := decode(b[2:])
	if err != nil {
		return nil, nil, err
	}
	return &classes.Selector{ID: b[1], Parameters: d}, rest, nil
}

// allowed asks the association's rights.
func (ss *session) allowed(d descriptor, op Op) bool {
	if ss.a.Allow == nil {
		return true
	}
	return ss.a.Allow(d.class, d.ln, d.id, op)
}

// object finds the object of a descriptor: the server's, or the current
// association object.
func (ss *session) object(class uint16, ln string) (classes.Object, bool) {
	if ln == "0.0.40.0.0.255" && (class == 15 || class == 12) {
		return ss.associationObject(), true
	}
	return ss.s.Object(class, ln)
}

// getValue reads an attribute: its encoded data, or a data access result.
func (ss *session) getValue(d descriptor, sel *classes.Selector) ([]byte, byte) {
	o, ok := ss.object(d.class, d.ln)
	if !ok {
		return nil, byte(classes.ObjectUndefined)
	}
	if !ss.allowed(d, OpRead) {
		return nil, byte(classes.ReadWriteDenied)
	}
	v, err := o.Get(d.id, sel)
	if err != nil {
		return nil, byte(classes.ResultOf(err))
	}
	b, err := encode(v)
	if err != nil {
		return nil, byte(classes.OtherReason)
	}
	return b, 0
}

func (ss *session) setValue(d descriptor, sel *classes.Selector, v *axdr.DlmsData) byte {
	o, ok := ss.object(d.class, d.ln)
	if !ok {
		return byte(classes.ObjectUndefined)
	}
	if !ss.allowed(d, OpWrite) {
		return byte(classes.ReadWriteDenied)
	}
	return byte(classes.ResultOf(o.Set(d.id, v, sel)))
}

func (ss *session) invoke(d descriptor, param *axdr.DlmsData) ([]byte, byte) {
	o, ok := ss.object(d.class, d.ln)
	if !ok {
		return nil, byte(classes.ObjectUndefined)
	}
	if !ss.allowed(d, OpExecute) {
		return nil, byte(classes.ReadWriteDenied)
	}
	ret, err := o.Action(d.id, param)
	if err != nil {
		return nil, byte(classes.ResultOf(err))
	}
	if ret == nil {
		return nil, 0
	}
	b, err := encode(ret)
	if err != nil {
		return nil, byte(classes.OtherReason)
	}
	return b, 0
}

// blockSize is the most data one block carries: what fits the smaller of
// the two PDU sizes after the headers and the protection.
func (ss *session) blockSize() int {
	if ss.s.BlockSize > 0 {
		return ss.s.BlockSize
	}
	n := min(ss.s.maxPDU(), ss.clientMax)
	n -= 40
	if n < 16 {
		n = 16
	}
	return n
}

// fits reports an answer of n octets that goes whole.
func (ss *session) fits(n int) bool { return n+30 <= min(ss.s.maxPDU(), ss.clientMax) }

// get serves get-request normal, next and with-list.
func (ss *session) get(apdu []byte) []byte {
	if len(apdu) < 3 {
		return errUnknown
	}
	invoke := apdu[2]
	switch apdu[1] {
	case 0x01:
		d, rest, err := parseDescriptor(apdu[3:])
		if err != nil {
			return getResult(invoke, byte(classes.OtherReason))
		}
		sel, _, err := selection(rest)
		if err != nil {
			return getResult(invoke, byte(classes.OtherReason))
		}
		data, res := ss.getValue(d, sel)
		if res != 0 {
			return getResult(invoke, res)
		}
		return ss.getAnswer(invoke, 0x01, data)
	case 0x02:
		if len(apdu) < 7 {
			return errUnknown
		}
		if len(ss.getOut) == 0 {
			return getBlockResult(invoke, byte(classes.NoLongInProgress))
		}
		if u32(apdu[3:7]) != ss.getBlock {
			ss.getOut = nil
			return getBlockResult(invoke, byte(classes.BlockNumberInvalid))
		}
		return ss.nextGetBlock(invoke)
	case 0x03:
		r := apdu[3:]
		n, sz := cosem.DecodeLength(r)
		if n < 0 {
			return errUnknown
		}
		r = r[sz:]
		var body []byte
		body = append(body, berLen(n)...)
		for i := 0; i < n; i++ {
			d, rest, err := parseDescriptor(r)
			if err != nil {
				return errUnknown
			}
			sel, rest, err := selection(rest)
			if err != nil {
				return errUnknown
			}
			r = rest
			data, res := ss.getValue(d, sel)
			if res != 0 {
				body = append(body, 0x01, res)
			} else {
				body = append(body, 0x00)
				body = append(body, data...)
			}
		}
		return ss.getAnswer(invoke, 0x03, body)
	}
	return errUnknown
}

// getAnswer sends data whole (get-response-normal or with-list) or starts
// sending it in blocks.
func (ss *session) getAnswer(invoke, kind byte, data []byte) []byte {
	if ss.fits(len(data)) {
		if kind == 0x01 {
			return append([]byte{0xC4, 0x01, invoke, 0x00}, data...)
		}
		return append([]byte{0xC4, 0x03, invoke}, data...)
	}
	if ss.inGBT || ss.conf&gbtBit != 0 {
		// The whole answer goes in general block transfer (answer, in
		// transport.go, splits it).
		if kind == 0x01 {
			return append([]byte{0xC4, 0x01, invoke, 0x00}, data...)
		}
		return append([]byte{0xC4, 0x03, invoke}, data...)
	}
	if ss.conf&cosem.ConformanceBlockGetOrRead == 0 {
		return getResult(invoke, byte(classes.OtherReason))
	}
	ss.getOut, ss.getBlock = data, 0
	return ss.nextGetBlock(invoke)
}

func (ss *session) nextGetBlock(invoke byte) []byte {
	n := min(ss.blockSize(), len(ss.getOut))
	chunk := ss.getOut[:n]
	ss.getOut = ss.getOut[n:]
	ss.getBlock++
	ss.s.count(func(st *Stats) { st.Blocks++ })
	last := byte(0)
	if len(ss.getOut) == 0 {
		last = 1
	}
	out := []byte{0xC4, 0x02, invoke, last, 0, 0, 0, 0, 0x00}
	binary.BigEndian.PutUint32(out[4:], ss.getBlock)
	out = append(out, octetString(chunk)...)
	return out
}

func getResult(invoke, code byte) []byte { return []byte{0xC4, 0x01, invoke, 0x01, code} }

func getBlockResult(invoke, code byte) []byte {
	return []byte{0xC4, 0x02, invoke, 0x01, 0, 0, 0, 0, 0x01, code}
}

// set serves set-request normal, with list, and in data blocks.
func (ss *session) set(apdu []byte) []byte {
	if len(apdu) < 3 {
		return errUnknown
	}
	invoke := apdu[2]
	b := apdu[3:]
	switch apdu[1] {
	case 0x01:
		d, rest, err := parseDescriptor(b)
		if err != nil {
			return setResult(invoke, byte(classes.OtherReason))
		}
		sel, rest, err := selection(rest)
		if err != nil {
			return setResult(invoke, byte(classes.OtherReason))
		}
		v, _, err := decode(rest)
		if err != nil {
			return setResult(invoke, byte(classes.TypeUnmatched))
		}
		return setResult(invoke, ss.setValue(d, sel, v))
	case 0x02, 0x04, 0x05:
		ss.setAttr, ss.setList, ss.setBuf, ss.setBlock = nil, nil, nil, 0
		if apdu[1] == 0x02 {
			if len(b) < 10 {
				return errUnknown
			}
			_, rest, err := parseDescriptor(b)
			if err != nil {
				return errUnknown
			}
			_, rest2, err := selection(rest)
			if err != nil {
				return errUnknown
			}
			ss.setAttr = append([]byte(nil), b[:len(b)-len(rest2)]...)
			b = rest2
		} else {
			n, sz := cosem.DecodeLength(b)
			if n < 0 {
				return errUnknown
			}
			b = b[sz:]
			for i := 0; i < n; i++ {
				_, rest, err := parseDescriptor(b)
				if err != nil {
					return errUnknown
				}
				_, rest2, err := selection(rest)
				if err != nil {
					return errUnknown
				}
				ss.setList = append(ss.setList, append([]byte(nil), b[:len(b)-len(rest2)]...))
				b = rest2
			}
			if apdu[1] == 0x04 {
				return ss.setWithList(invoke, b)
			}
		}
		ss.setBlock = 1
		return ss.setData(invoke, b)
	case 0x03:
		if ss.setAttr == nil && ss.setList == nil {
			return setLastResult(invoke, byte(classes.NoLongSetProgress), 0)
		}
		return ss.setData(invoke, b)
	}
	return errUnknown
}

// setData takes one DataBlock-SA (last, block number, raw data).
func (ss *session) setData(invoke byte, b []byte) []byte {
	fail := func(code byte) []byte {
		ss.setAttr, ss.setList, ss.setBuf = nil, nil, nil
		return setLastResult(invoke, code, ss.setBlock)
	}
	if len(b) < 6 {
		return fail(byte(classes.OtherReason))
	}
	last := b[0] != 0
	n := u32(b[1:5])
	l, sz := cosem.DecodeLength(b[5:])
	if n != ss.setBlock || l < 0 || 5+sz+l != len(b) {
		return fail(byte(classes.BlockNumberInvalid))
	}
	ss.setBuf = append(ss.setBuf, b[5+sz:]...)
	if !last {
		ss.setBlock++
		out := []byte{0xC5, 0x02, invoke, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[3:], n)
		return out
	}
	data := ss.setBuf
	if ss.setList != nil {
		resp := ss.setWithList(invoke, data)
		ss.setList, ss.setBuf = nil, nil
		if len(resp) > 3 && resp[1] == 0x05 {
			// set-response-last-datablock-with-list: results, then the block number.
			out := append([]byte{0xC5, 0x04, invoke}, resp[3:]...)
			return binary.BigEndian.AppendUint32(out, n)
		}
		return resp
	}
	d, rest, err := parseDescriptor(ss.setAttr)
	sel, _, err2 := selection(rest)
	ss.setAttr, ss.setBuf = nil, nil
	if err != nil || err2 != nil {
		return setLastResult(invoke, byte(classes.OtherReason), n)
	}
	v, more, err := decode(data)
	if err != nil || len(more) != 0 {
		return setLastResult(invoke, byte(classes.TypeUnmatched), n)
	}
	return setLastResult(invoke, ss.setValue(d, sel, v), n)
}

// setWithList writes each attribute of setList from the list of data b.
func (ss *session) setWithList(invoke byte, b []byte) []byte {
	descs := ss.setList
	ss.setList = nil
	n, sz := cosem.DecodeLength(b)
	if n != len(descs) {
		return errUnknown
	}
	b = b[sz:]
	out := append([]byte{0xC5, 0x05, invoke}, berLen(n)...)
	for _, raw := range descs {
		d, rest, _ := parseDescriptor(raw)
		sel, _, _ := selection(rest)
		v, more, err := decode(b)
		if err != nil {
			return errUnknown
		}
		b = more
		out = append(out, ss.setValue(d, sel, v))
	}
	return out
}

func setResult(invoke, code byte) []byte { return []byte{0xC5, 0x01, invoke, code} }

func setLastResult(invoke, code byte, n uint32) []byte {
	out := []byte{0xC5, 0x03, invoke, code, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[4:], n)
	return out
}

// action serves action-request normal, with list, and with parameter
// blocks both ways.
func (ss *session) action(apdu []byte) []byte {
	if len(apdu) < 3 {
		return errUnknown
	}
	invoke := apdu[2]
	b := apdu[3:]
	switch apdu[1] {
	case 0x01:
		d, rest, err := parseDescriptor(b)
		if err != nil || len(rest) < 1 {
			return actionResult(invoke, byte(classes.OtherReason))
		}
		var param *axdr.DlmsData
		if rest[0] != 0 {
			if param, _, err = decode(rest[1:]); err != nil {
				return actionResult(invoke, byte(classes.TypeUnmatched))
			}
		}
		ret, res := ss.invoke(d, param)
		return ss.actionAnswer(invoke, res, ret)
	case 0x02: // next-pblock: the client asks for the next block of our answer
		if len(b) < 4 || len(ss.actOut) == 0 {
			return actionResult(invoke, byte(classes.NoLongInProgress))
		}
		if u32(b) != ss.actOutN {
			ss.actOut = nil
			return actionResult(invoke, byte(classes.BlockNumberInvalid))
		}
		return ss.nextActionBlock(invoke)
	case 0x03: // with-list
		n, sz := cosem.DecodeLength(b)
		if n < 0 {
			return errUnknown
		}
		b = b[sz:]
		var descs []descriptor
		for i := 0; i < n; i++ {
			d, rest, err := parseDescriptor(b)
			if err != nil {
				return errUnknown
			}
			descs, b = append(descs, d), rest
		}
		m, sz := cosem.DecodeLength(b)
		if m != n {
			return errUnknown
		}
		b = b[sz:]
		body := berLen(n)
		for _, d := range descs {
			p, rest, err := decode(b)
			if err != nil {
				return errUnknown
			}
			b = rest
			if p.Tag == axdr.TagNull {
				p = nil
			}
			ret, res := ss.invoke(d, p)
			body = append(body, res)
			if ret != nil {
				body = append(body, 0x01, 0x00)
				body = append(body, ret...)
			} else {
				body = append(body, 0x00)
			}
		}
		return append([]byte{0xC7, 0x03, invoke}, body...)
	case 0x04, 0x06: // with-first-pblock, with-pblock
		if apdu[1] == 0x04 {
			if len(b) < 9 {
				return errUnknown
			}
			ss.actMethod, ss.actBuf, ss.actBlock = append([]byte(nil), b[:9]...), nil, 1
			b = b[9:]
		} else if ss.actMethod == nil {
			return actionResult(invoke, byte(classes.NoLongInProgress))
		}
		if len(b) < 6 {
			return errUnknown
		}
		last := b[0] != 0
		n := u32(b[1:5])
		l, sz := cosem.DecodeLength(b[5:])
		if n != ss.actBlock || l < 0 || 5+sz+l != len(b) {
			ss.actMethod, ss.actBuf = nil, nil
			return actionResult(invoke, byte(classes.BlockNumberInvalid))
		}
		ss.actBuf = append(ss.actBuf, b[5+sz:]...)
		if !last {
			ss.actBlock++
			out := []byte{0xC7, 0x04, invoke, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(out[3:], n)
			return out
		}
		d, _, _ := parseDescriptor(ss.actMethod)
		data := ss.actBuf
		ss.actMethod, ss.actBuf = nil, nil
		p, more, err := decode(data)
		if err != nil || len(more) != 0 {
			return actionResult(invoke, byte(classes.TypeUnmatched))
		}
		ret, res := ss.invoke(d, p)
		return ss.actionAnswer(invoke, res, ret)
	}
	return errUnknown
}

func actionResult(invoke, code byte) []byte { return []byte{0xC7, 0x01, invoke, code, 0x00} }

// actionAnswer sends an action's result and return data, in parameter
// blocks when it does not fit.
func (ss *session) actionAnswer(invoke, res byte, ret []byte) []byte {
	if ret == nil {
		return actionResult(invoke, res)
	}
	if ss.fits(len(ret)) || ss.inGBT || ss.conf&gbtBit != 0 || ss.conf&cosem.ConformanceBlockAction == 0 {
		return append([]byte{0xC7, 0x01, invoke, res, 0x01, 0x00}, ret...)
	}
	ss.actOut, ss.actOutN = ret, 0
	return ss.nextActionBlock(invoke)
}

func (ss *session) nextActionBlock(invoke byte) []byte {
	n := min(ss.blockSize(), len(ss.actOut))
	chunk := ss.actOut[:n]
	ss.actOut = ss.actOut[n:]
	ss.actOutN++
	ss.s.count(func(st *Stats) { st.Blocks++ })
	last := byte(0)
	if len(ss.actOut) == 0 {
		last = 1
	}
	out := []byte{0xC7, 0x02, invoke, last, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[4:], ss.actOutN)
	return append(out, octetString(chunk)...)
}

// access serves the ACCESS service: each operation in order, stopping
// after a failure when the request asks to break on error.
func (ss *session) access(apdu []byte) []byte {
	req, err := cosem.DecodeAccessRequest(apdu)
	if err != nil {
		ss.s.logf("client %d: access request: %v", ss.client, err)
		return errUnknown
	}
	if ss.conf&accessBit == 0 {
		return errNotAllowed
	}
	resp := &cosem.AccessResponse{InvokeID: req.InvokeID}
	failed := false
	for _, it := range req.Items {
		res := cosem.AccessResult{Kind: it.Kind, Data: axdr.DlmsData{Tag: axdr.TagNull}}
		d := descriptor{class: it.Class, ln: it.OBIS, id: it.ID}
		var sel *classes.Selector
		if it.Kind == cosem.AccessGetWithSelection || it.Kind == cosem.AccessSetWithSelection {
			sel = &classes.Selector{ID: it.Selector, Parameters: it.Parameters}
		}
		switch {
		case failed:
			res.Result = byte(classes.OtherReason)
		case it.Kind == cosem.AccessGet || it.Kind == cosem.AccessGetWithSelection:
			data, code := ss.getValue(d, sel)
			res.Result = code
			if code == 0 {
				v, _, err := decode(data)
				if err != nil {
					res.Result = byte(classes.OtherReason)
				} else {
					res.Data = *v
				}
			}
		case it.Kind == cosem.AccessSet || it.Kind == cosem.AccessSetWithSelection:
			v := it.Data
			if v == nil {
				v = &axdr.DlmsData{Tag: axdr.TagNull}
			}
			res.Result = ss.setValue(d, sel, v)
		case it.Kind == cosem.AccessAction:
			p := it.Data
			ret, code := ss.invoke(d, p)
			res.Result = code
			if ret != nil {
				if v, _, err := decode(ret); err == nil {
					res.Data = *v
				}
			}
		}
		if res.Result != 0 && req.InvokeID&cosem.AccessBreakOnError != 0 {
			failed = true
		}
		resp.Results = append(resp.Results, res)
	}
	out, err := resp.Encode()
	if err != nil {
		return errUnknown
	}
	if req.InvokeID&cosem.AccessConfirmed == 0 {
		return nil
	}
	return out
}
