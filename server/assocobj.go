// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

// The current association object, 0.0.40.0.0.255: association LN (class
// 15, version 3) or, with short names, association SN (class 12, version
// 4, base name 0xFA00). Its object list is the server's objects with the
// client's rights; reply_to_HLS_authentication is pass 3 (aa.go).

import (
	"encoding/hex"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
)

type assocObject struct{ ss *session }

func (ss *session) associationObject() classes.Object { return assocObject{ss} }

func (o assocObject) ClassID() uint16 {
	if o.ss.s.ShortNames {
		return 12
	}
	return 15
}

func (o assocObject) Version() uint8 {
	if o.ss.s.ShortNames {
		return 4
	}
	return 3
}

func (o assocObject) LogicalName() string { return "0.0.40.0.0.255" }

func octets(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }

func lnOctets(ln string) *axdr.DlmsData {
	b, err := classes.LNOctets(ln)
	if err != nil {
		b = make([]byte, 6)
	}
	return octets(b)
}

func (o assocObject) Get(attr int8, sel *classes.Selector) (*axdr.DlmsData, error) {
	ss := o.ss
	if attr == 1 {
		return lnOctets(o.LogicalName()), nil
	}
	if attr == 2 {
		return o.objectList(), nil
	}
	if ss.s.ShortNames {
		switch attr {
		case 4:
			return lnOctets("0.0.43.0.0.255"), nil
		}
		return nil, classes.ObjectUndefined
	}
	a := ss.a
	switch attr {
	case 3:
		return axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(int8(ss.client)), axdr.CreateAxdrLongUnsigned(ss.s.address())}), nil
	case 4:
		ctx := byte(1)
		if ss.ciphering {
			ctx = 3
		}
		return octets([]byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x01, ctx}), nil
	case 5:
		bits := fmt.Sprintf("%024b", ss.conf)
		return axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrBitString(bits), axdr.CreateAxdrLongUnsigned(uint16(ss.s.maxPDU())),
			axdr.CreateAxdrLongUnsigned(uint16(min(ss.clientMax, 0xFFFF))), axdr.CreateAxdrUnsigned(6),
			axdr.CreateAxdrInteger(0), octets(nil),
		}), nil
	case 6:
		var m byte
		if a != nil {
			m = a.Mechanism
		}
		return octets([]byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x02, m}), nil
	case 7:
		return nil, classes.ReadWriteDenied
	case 8:
		st := uint8(0)
		if ss.pending {
			st = 1
		} else if ss.associated {
			st = 2
		}
		return axdr.CreateAxdrEnum(st), nil
	case 9:
		return lnOctets("0.0.43.0.0.255"), nil
	}
	return nil, classes.ObjectUndefined
}

func (o assocObject) Set(attr int8, v *axdr.DlmsData, sel *classes.Selector) error {
	if attr >= 1 && attr <= 11 {
		return classes.ReadWriteDenied
	}
	return classes.ObjectUndefined
}

func (o assocObject) Action(m int8, param *axdr.DlmsData) (*axdr.DlmsData, error) {
	// reply_to_HLS_authentication is answered during the association;
	// key and secret changes are not offered.
	return nil, classes.ReadWriteDenied
}

// objectList lists the objects the client may see: every object for LN
// with its attribute and method rights, and every object with its base
// name for SN; the association object itself first.
func (o assocObject) objectList() *axdr.DlmsData {
	ss := o.ss
	s := ss.s
	var list []*axdr.DlmsData
	add := func(obj classes.Object, base uint16) {
		if s.ShortNames {
			list = append(list, axdr.CreateAxdrStructure([]*axdr.DlmsData{
				axdr.CreateAxdrLong(int16(base)), axdr.CreateAxdrLongUnsigned(obj.ClassID()),
				axdr.CreateAxdrUnsigned(obj.Version()), lnOctets(obj.LogicalName()),
			}))
			return
		}
		list = append(list, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(obj.ClassID()), axdr.CreateAxdrUnsigned(obj.Version()),
			lnOctets(obj.LogicalName()), ss.rights(obj),
		}))
	}
	add(o, 0xFA00)
	for _, k := range s.sortedKeys() {
		s.mu.Lock()
		obj, base := s.objects[k], s.bases[k]
		s.mu.Unlock()
		add(obj, base)
	}
	return axdr.CreateAxdrArray(list)
}

// rights is the access_rights of an object list entry (version 3: access
// modes as enums).
func (ss *session) rights(obj classes.Object) *axdr.DlmsData {
	nAttr, nMeth := 0, 0
	if c, ok := classes.Lookup(obj.ClassID()); ok {
		nAttr, nMeth = len(c.Attributes), len(c.Methods)
	}
	var attrs, meths []*axdr.DlmsData
	for i := 1; i <= nAttr; i++ {
		d := descriptor{class: obj.ClassID(), ln: obj.LogicalName(), id: int8(i)}
		mode := uint8(0)
		if ss.allowed(d, OpRead) {
			mode |= 1
		}
		if i > 1 && ss.allowed(d, OpWrite) {
			mode |= 2
		}
		attrs = append(attrs, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrInteger(int8(i)), axdr.CreateAxdrEnum(mode), {Tag: axdr.TagNull},
		}))
	}
	for i := 1; i <= nMeth; i++ {
		d := descriptor{class: obj.ClassID(), ln: obj.LogicalName(), id: int8(i)}
		mode := uint8(0)
		if ss.allowed(d, OpExecute) {
			mode = 1
		}
		meths = append(meths, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(int8(i)), axdr.CreateAxdrEnum(mode)}))
	}
	return axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrArray(attrs), axdr.CreateAxdrArray(meths)})
}
