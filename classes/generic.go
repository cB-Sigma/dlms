// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Generic is an object of any class held as A-XDR data: Attrs by index
// (attribute 1 always comes from LN), Writable naming the attributes a
// SET may change (keeping their type), and Methods running the methods.
// An attribute the class has (by the catalogue) but Attrs lacks reads as
// null-data; one it does not have is undefined. Selective access is
// refused.
type Generic struct {
	sync.Mutex
	Class    uint16
	Ver      uint8
	LN       string
	Attrs    map[int8]*axdr.DlmsData
	Writable map[int8]bool
	Methods  map[int8]func(param *axdr.DlmsData) (*axdr.DlmsData, error)
}

// The typed objects of this package.
var (
	_ Object = (*Data)(nil)
	_ Object = (*Register)(nil)
	_ Object = (*ExtendedRegister)(nil)
	_ Object = (*DemandRegister)(nil)
	_ Object = (*RegisterActivation)(nil)
	_ Object = (*ProfileGeneric)(nil)
	_ Object = (*Clock)(nil)
	_ Object = (*ScriptTable)(nil)
	_ Object = (*Schedule)(nil)
	_ Object = (*SpecialDaysTable)(nil)
	_ Object = (*AssociationSN)(nil)
	_ Object = (*AssociationLN)(nil)
	_ Object = (*SAPAssignment)(nil)
	_ Object = (*ImageTransfer)(nil)
	_ Object = (*IECLocalPortSetup)(nil)
	_ Object = (*ActivityCalendar)(nil)
	_ Object = (*RegisterMonitor)(nil)
	_ Object = (*SingleActionSchedule)(nil)
	_ Object = (*IECHDLCSetup)(nil)
	_ Object = (*PushSetup)(nil)
	_ Object = (*TCPUDPSetup)(nil)
	_ Object = (*IPv4Setup)(nil)
	_ Object = (*SecuritySetup)(nil)
	_ Object = (*DisconnectControl)(nil)
	_ Object = (*Limiter)(nil)
	_ Object = (*Generic)(nil)

	_ Binder = (*ProfileGeneric)(nil)
	_ Binder = (*PushSetup)(nil)
	_ Binder = (*RegisterMonitor)(nil)
)

func (o *Generic) ClassID() uint16     { return o.Class }
func (o *Generic) Version() uint8      { return o.Ver }
func (o *Generic) LogicalName() string { return o.LN }

func (o *Generic) known(a int8) bool {
	if _, ok := o.Attrs[a]; ok {
		return true
	}
	if c, ok := Lookup(o.Class); ok {
		_, has := c.Attribute(a)
		return has
	}
	return false
}

func (o *Generic) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	if sel != nil {
		return nil, ScopeViolated
	}
	if a == 1 {
		return lnData(o.LN), nil
	}
	if !o.known(a) {
		return nil, ObjectUndefined
	}
	return orNull(o.Attrs[a]), nil
}

func (o *Generic) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	if sel != nil {
		return ScopeViolated
	}
	if a != 1 && !o.known(a) {
		return ObjectUndefined
	}
	if a == 1 || !o.Writable[a] {
		return ReadWriteDenied
	}
	if err := sameType(o.Attrs[a], v); err != nil {
		return err
	}
	if o.Attrs == nil {
		o.Attrs = map[int8]*axdr.DlmsData{}
	}
	o.Attrs[a] = v
	return nil
}

// Action runs Methods[m]; a method the class has but Methods lacks is
// refused (read-write denied), one it does not have is undefined.
func (o *Generic) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	f := o.Methods[m]
	o.Unlock()
	if f != nil {
		return f(p)
	}
	if c, ok := Lookup(o.Class); ok {
		if _, has := c.Method(m); has {
			return nil, ReadWriteDenied
		}
	}
	return nil, ObjectUndefined
}
