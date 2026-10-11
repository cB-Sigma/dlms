// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"fmt"
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// AttributeAccess is the access an association has to one attribute:
// Mode is the attribute access mode enumeration (0 none, 1 read, 2 write,
// 3 read and write, higher values add authentication and ciphering
// requirements); Selectors lists the selective access selectors the
// attribute takes (nil: none, encoded as null-data).
type AttributeAccess struct {
	Index     int8
	Mode      uint8
	Selectors []int8
}

// MethodAccess is the access an association has to one method: Mode 0 is
// no access, 1 access, higher values add security requirements.
type MethodAccess struct {
	Index int8
	Mode  uint8
}

// ObjectListItem is one decoded entry of an object list. BaseName is set
// for short name lists; the access lists for logical name lists.
type ObjectListItem struct {
	Class      uint16
	Version    uint8
	LN         string
	BaseName   int16
	Attributes []AttributeAccess
	Methods    []MethodAccess
}

// ObjectListEntryLN is one entry of an Association LN object list:
// {class, version, logical name, {attribute accesses, method accesses}}.
func ObjectListEntryLN(class uint16, version uint8, ln string, attrAccess []AttributeAccess, methodAccess []MethodAccess) *axdr.DlmsData {
	attrs := make([]*axdr.DlmsData, len(attrAccess))
	for i, a := range attrAccess {
		sel := nullData()
		if a.Selectors != nil {
			s := make([]*axdr.DlmsData, len(a.Selectors))
			for j, x := range a.Selectors {
				s[j] = axdr.CreateAxdrInteger(x)
			}
			sel = arrayOf(s)
		}
		attrs[i] = structOf(axdr.CreateAxdrInteger(a.Index), axdr.CreateAxdrEnum(a.Mode), sel)
	}
	methods := make([]*axdr.DlmsData, len(methodAccess))
	for i, m := range methodAccess {
		methods[i] = structOf(axdr.CreateAxdrInteger(m.Index), axdr.CreateAxdrEnum(m.Mode))
	}
	return structOf(axdr.CreateAxdrLongUnsigned(class), axdr.CreateAxdrUnsigned(version), lnData(ln),
		structOf(arrayOf(attrs), arrayOf(methods)))
}

// ObjectListEntrySN is one entry of an Association SN object list:
// {base name, class, version, logical name}.
func ObjectListEntrySN(baseName int16, class uint16, version uint8, ln string) *axdr.DlmsData {
	return structOf(axdr.CreateAxdrLong(baseName), axdr.CreateAxdrLongUnsigned(class),
		axdr.CreateAxdrUnsigned(version), lnData(ln))
}

// accessMode reads an access mode: an enumeration, or the boolean of
// version 0 method lists.
func accessMode(d *axdr.DlmsData) (uint8, error) {
	if d != nil && d.Tag == axdr.TagBoolean {
		b, err := boolOf(d)
		if b {
			return 1, err
		}
		return 0, err
	}
	return enumOf(d)
}

// ParseObjectListLN decodes an Association LN object list (attribute 2).
func ParseObjectListLN(d axdr.DlmsData) ([]ObjectListItem, error) {
	entries, err := arrayItems(&d)
	if err != nil {
		return nil, fmt.Errorf("object list is not an array")
	}
	out := make([]ObjectListItem, len(entries))
	for i, e := range entries {
		bad := func(what string) error { return fmt.Errorf("object list entry %d: %s", i+1, what) }
		f, err := structItems(e, 4)
		if err != nil {
			return nil, bad("not a structure of four")
		}
		it := &out[i]
		if it.Class, err = u16Of(f[0]); err != nil {
			return nil, bad("class is not long-unsigned")
		}
		if it.Version, err = u8Of(f[1]); err != nil {
			return nil, bad("version is not unsigned")
		}
		if it.LN, err = lnOf(f[2]); err != nil {
			return nil, bad("logical name is not six octets")
		}
		acc, err := structItems(f[3], 2)
		if err != nil {
			return nil, bad("access rights are not a structure of two")
		}
		attrs, err := arrayItems(acc[0])
		if err != nil {
			return nil, bad("attribute access is not an array")
		}
		for _, a := range attrs {
			af, err := structItems(a, 3)
			if err != nil {
				return nil, bad("attribute access item is not a structure of three")
			}
			var x AttributeAccess
			if x.Index, err = i8Of(af[0]); err != nil {
				return nil, bad("attribute index is not integer")
			}
			if x.Mode, err = accessMode(af[1]); err != nil {
				return nil, bad("attribute access mode is not enum")
			}
			if af[2].Tag != axdr.TagNull {
				sels, err := arrayItems(af[2])
				if err != nil {
					return nil, bad("access selectors are not an array")
				}
				x.Selectors = make([]int8, len(sels))
				for k, s := range sels {
					if x.Selectors[k], err = i8Of(s); err != nil {
						return nil, bad("access selector is not integer")
					}
				}
			}
			it.Attributes = append(it.Attributes, x)
		}
		methods, err := arrayItems(acc[1])
		if err != nil {
			return nil, bad("method access is not an array")
		}
		for _, m := range methods {
			mf, err := structItems(m, 2)
			if err != nil {
				return nil, bad("method access item is not a structure of two")
			}
			var x MethodAccess
			if x.Index, err = i8Of(mf[0]); err != nil {
				return nil, bad("method index is not integer")
			}
			if x.Mode, err = accessMode(mf[1]); err != nil {
				return nil, bad("method access mode is not enum or boolean")
			}
			it.Methods = append(it.Methods, x)
		}
	}
	return out, nil
}

// ParseObjectListSN decodes an Association SN object list (attribute 2).
func ParseObjectListSN(d axdr.DlmsData) ([]ObjectListItem, error) {
	entries, err := arrayItems(&d)
	if err != nil {
		return nil, fmt.Errorf("object list is not an array")
	}
	out := make([]ObjectListItem, len(entries))
	for i, e := range entries {
		bad := func(what string) error { return fmt.Errorf("object list entry %d: %s", i+1, what) }
		f, err := structItems(e, 4)
		if err != nil {
			return nil, bad("not a structure of four")
		}
		it := &out[i]
		if it.BaseName, err = i16Of(f[0]); err != nil {
			return nil, bad("base name is not long")
		}
		if it.Class, err = u16Of(f[1]); err != nil {
			return nil, bad("class is not long-unsigned")
		}
		if it.Version, err = u8Of(f[2]); err != nil {
			return nil, bad("version is not unsigned")
		}
		if it.LN, err = lnOf(f[3]); err != nil {
			return nil, bad("logical name is not six octets")
		}
	}
	return out, nil
}

// AssociationLN is class 15 (version 3) as data the server fills: the
// server answers its methods itself, so Action is refused here. GET of
// the object list uses ObjectListFunc when set (the server lists what
// the current association may see), else ObjectList. The secret is never
// read back; a SET of it is allowed (a low-level-security password
// change). Everything else is read-only to clients.
type AssociationLN struct {
	sync.Mutex
	LN                          string
	ObjectList                  *axdr.DlmsData
	ObjectListFunc              func() *axdr.DlmsData
	ClientSAP                   int8
	ServerSAP                   uint16
	ApplicationContextName      *axdr.DlmsData
	XDLMSContextInfo            *axdr.DlmsData
	AuthenticationMechanismName *axdr.DlmsData
	Secret                      []byte
	Status                      uint8 // 0 non-associated, 1 pending, 2 associated
	SecuritySetupReference      string
	UserList                    *axdr.DlmsData
	CurrentUser                 *axdr.DlmsData
}

func (o *AssociationLN) ClassID() uint16     { return 15 }
func (o *AssociationLN) Version() uint8      { return 3 }
func (o *AssociationLN) LogicalName() string { return o.LN }

func objectListAttr(list **axdr.DlmsData, f func() *axdr.DlmsData) attr {
	return attr{get: func() (*axdr.DlmsData, error) {
		if f != nil {
			if d := f(); d != nil {
				return d, nil
			}
		}
		if *list == nil {
			return arrayOf(nil), nil
		}
		return *list, nil
	}}
}

func (o *AssociationLN) attrs() map[int8]attr {
	return map[int8]attr{
		2: objectListAttr(&o.ObjectList, o.ObjectListFunc),
		3: {get: func() (*axdr.DlmsData, error) {
			return structOf(axdr.CreateAxdrInteger(o.ClientSAP), axdr.CreateAxdrLongUnsigned(o.ServerSAP)), nil
		}},
		4:  readOnly(fData(&o.ApplicationContextName)),
		5:  readOnly(fData(&o.XDLMSContextInfo)),
		6:  readOnly(fData(&o.AuthenticationMechanismName)),
		7:  {get: func() (*axdr.DlmsData, error) { return nil, ReadWriteDenied }, set: fOctets(&o.Secret).set},
		8:  readOnly(fEnum(&o.Status)),
		9:  readOnly(fLN(&o.SecuritySetupReference)),
		10: readOnly(fArray(&o.UserList)),
		11: readOnly(fData(&o.CurrentUser)),
	}
}

func (o *AssociationLN) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *AssociationLN) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action is refused: the server runs the association's methods.
func (o *AssociationLN) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m < 1 || m > 6 {
		return nil, ObjectUndefined
	}
	return nil, ReadWriteDenied
}

// AssociationSN is class 12 (version 4) as data the server fills, like
// AssociationLN.
type AssociationSN struct {
	sync.Mutex
	LN                     string
	ObjectList             *axdr.DlmsData
	ObjectListFunc         func() *axdr.DlmsData
	AccessRightsList       *axdr.DlmsData
	SecuritySetupReference string
	UserList               *axdr.DlmsData
	CurrentUser            *axdr.DlmsData
}

func (o *AssociationSN) ClassID() uint16     { return 12 }
func (o *AssociationSN) Version() uint8      { return 4 }
func (o *AssociationSN) LogicalName() string { return o.LN }

func (o *AssociationSN) attrs() map[int8]attr {
	return map[int8]attr{
		2: objectListAttr(&o.ObjectList, o.ObjectListFunc),
		3: readOnly(fArray(&o.AccessRightsList)),
		4: readOnly(fLN(&o.SecuritySetupReference)),
		5: readOnly(fArray(&o.UserList)),
		6: readOnly(fData(&o.CurrentUser)),
	}
}

func (o *AssociationSN) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *AssociationSN) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action is refused: the server runs the association's methods.
func (o *AssociationSN) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	c, _ := Lookup(12)
	if _, ok := c.Method(m); !ok {
		return nil, ObjectUndefined
	}
	return nil, ReadWriteDenied
}
