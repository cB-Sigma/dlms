// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"bytes"
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Every typed object embeds a sync.Mutex. The server holds it during a
// GET, SET or ACTION; hold it too while changing the fields from outside.

// ValueRef points at one attribute of another object (a monitored or
// captured value).
type ValueRef struct {
	Class uint16
	LN    string
	Attr  int8
}

func (r ValueRef) data() *axdr.DlmsData {
	return structOf(axdr.CreateAxdrLongUnsigned(r.Class), lnData(r.LN), axdr.CreateAxdrInteger(r.Attr))
}

func valueRefOf(d *axdr.DlmsData) (ValueRef, error) {
	it, err := structItems(d, 3)
	if err != nil {
		return ValueRef{}, err
	}
	var r ValueRef
	if r.Class, err = u16Of(it[0]); err != nil {
		return r, err
	}
	if r.LN, err = lnOf(it[1]); err != nil {
		return r, err
	}
	r.Attr, err = i8Of(it[2])
	return r, err
}

func fValueRef(p *ValueRef) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return p.data(), nil },
		set: func(d *axdr.DlmsData) error {
			r, err := valueRefOf(d)
			if err == nil {
				*p = r
			}
			return err
		}}
}

// ScriptRef names a script: the script table's logical name and the
// script's number in it.
type ScriptRef struct {
	LN       string
	Selector uint16
}

func (s ScriptRef) data() *axdr.DlmsData {
	return structOf(lnData(s.LN), axdr.CreateAxdrLongUnsigned(s.Selector))
}

func scriptRefOf(d *axdr.DlmsData) (ScriptRef, error) {
	it, err := structItems(d, 2)
	if err != nil {
		return ScriptRef{}, err
	}
	var s ScriptRef
	if s.LN, err = lnOf(it[0]); err != nil {
		return s, err
	}
	s.Selector, err = u16Of(it[1])
	return s, err
}

func fScaler(s *int8, u *uint8) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return scalerUnitData(*s, *u), nil },
		set: func(d *axdr.DlmsData) error {
			a, b, err := scalerUnitOf(d)
			if err == nil {
				*s, *u = a, b
			}
			return err
		}}
}

func noMethod(int8, *axdr.DlmsData) (*axdr.DlmsData, error) { return nil, ObjectUndefined }

// Data is class 1: one value of any type. ReadOnly refuses SETs of it.
type Data struct {
	sync.Mutex
	LN       string
	Value    *axdr.DlmsData
	ReadOnly bool
}

func (o *Data) ClassID() uint16     { return 1 }
func (o *Data) Version() uint8      { return 0 }
func (o *Data) LogicalName() string { return o.LN }

func (o *Data) attrs() map[int8]attr {
	a := fData(&o.Value)
	if o.ReadOnly {
		a = readOnly(a)
	}
	return map[int8]attr{2: a}
}

func (o *Data) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *Data) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *Data) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) { return noMethod(m, p) }

// Register is class 3: a value with its scaler and unit.
type Register struct {
	sync.Mutex
	LN     string
	Value  *axdr.DlmsData
	Scaler int8
	Unit   uint8
}

func (o *Register) ClassID() uint16     { return 3 }
func (o *Register) Version() uint8      { return 0 }
func (o *Register) LogicalName() string { return o.LN }

func (o *Register) attrs() map[int8]attr {
	return map[int8]attr{2: fData(&o.Value), 3: fScaler(&o.Scaler, &o.Unit)}
}

func (o *Register) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *Register) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs reset (1): the value becomes zero of its type.
func (o *Register) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	o.Lock()
	defer o.Unlock()
	o.Value = zeroOf(o.Value)
	return nil, nil
}

// ExtendedRegister is class 4: a register with a status and the time the
// value was captured.
type ExtendedRegister struct {
	sync.Mutex
	LN          string
	Value       *axdr.DlmsData
	Scaler      int8
	Unit        uint8
	Status      *axdr.DlmsData
	CaptureTime time.Time
	// Location is the meter's local time zone (time.Local when nil); Now
	// is the time source (time.Now when nil).
	Location *time.Location
	Now      func() time.Time
}

func (o *ExtendedRegister) ClassID() uint16     { return 4 }
func (o *ExtendedRegister) Version() uint8      { return 0 }
func (o *ExtendedRegister) LogicalName() string { return o.LN }

func (o *ExtendedRegister) loc() *time.Location { return locOr(o.Location) }

func (o *ExtendedRegister) attrs() map[int8]attr {
	return map[int8]attr{2: fData(&o.Value), 3: fScaler(&o.Scaler, &o.Unit), 4: fData(&o.Status),
		5: readOnly(fTime(&o.CaptureTime, o.loc))}
}

func (o *ExtendedRegister) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *ExtendedRegister) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs reset (1): the value becomes zero and the capture time now.
func (o *ExtendedRegister) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	o.Lock()
	defer o.Unlock()
	o.Value = zeroOf(o.Value)
	o.CaptureTime = nowOr(o.Now)
	return nil, nil
}

// DemandRegister is class 5: an average over a sliding period.
type DemandRegister struct {
	sync.Mutex
	LN               string
	CurrentAverage   *axdr.DlmsData
	LastAverage      *axdr.DlmsData
	Scaler           int8
	Unit             uint8
	Status           *axdr.DlmsData
	CaptureTime      time.Time
	StartTimeCurrent time.Time
	Period           uint32 // seconds
	NumberOfPeriods  uint16
	Location         *time.Location
	Now              func() time.Time
}

func (o *DemandRegister) ClassID() uint16     { return 5 }
func (o *DemandRegister) Version() uint8      { return 0 }
func (o *DemandRegister) LogicalName() string { return o.LN }

func (o *DemandRegister) loc() *time.Location { return locOr(o.Location) }

func (o *DemandRegister) attrs() map[int8]attr {
	return map[int8]attr{
		2: readOnly(fData(&o.CurrentAverage)), 3: readOnly(fData(&o.LastAverage)),
		4: fScaler(&o.Scaler, &o.Unit), 5: fData(&o.Status),
		6: readOnly(fTime(&o.CaptureTime, o.loc)), 7: readOnly(fTime(&o.StartTimeCurrent, o.loc)),
		8: fU32(&o.Period), 9: fU16(&o.NumberOfPeriods),
	}
}

func (o *DemandRegister) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *DemandRegister) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs reset (1: both averages zero, times now) and next_period
// (2: the current average becomes the last one and a new period starts).
func (o *DemandRegister) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	now := nowOr(o.Now)
	switch m {
	case 1:
		o.CurrentAverage = zeroOf(o.CurrentAverage)
		o.LastAverage = zeroOf(o.LastAverage)
	case 2:
		o.LastAverage = o.CurrentAverage
		o.CurrentAverage = zeroOf(o.CurrentAverage)
	default:
		return nil, ObjectUndefined
	}
	o.CaptureTime, o.StartTimeCurrent = now, now
	return nil, nil
}

// RegisterActivation is class 6: register assignments and masks of them.
// RegisterAssignment is an array of {class, logical name}; MaskList an
// array of {mask name, array of indexes}.
type RegisterActivation struct {
	sync.Mutex
	LN                 string
	RegisterAssignment *axdr.DlmsData
	MaskList           *axdr.DlmsData
	ActiveMask         []byte
}

func (o *RegisterActivation) ClassID() uint16     { return 6 }
func (o *RegisterActivation) Version() uint8      { return 0 }
func (o *RegisterActivation) LogicalName() string { return o.LN }

func (o *RegisterActivation) attrs() map[int8]attr {
	return map[int8]attr{2: fArray(&o.RegisterAssignment), 3: fArray(&o.MaskList), 4: fOctets(&o.ActiveMask)}
}

func (o *RegisterActivation) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *RegisterActivation) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs add_register (1), add_mask (2, replacing a mask of the same
// name) and delete_mask (3).
func (o *RegisterActivation) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	list := func(d *axdr.DlmsData) []*axdr.DlmsData {
		it, _ := arrayItems(d)
		return it
	}
	maskName := func(d *axdr.DlmsData) []byte {
		it, err := structItems(d, 2)
		if err != nil {
			return nil
		}
		b, _ := octetsOf(it[0])
		return b
	}
	switch m {
	case 1:
		if _, err := structItems(p, 2); err != nil {
			return nil, err
		}
		o.RegisterAssignment = arrayOf(append(list(o.RegisterAssignment), p))
	case 2:
		it, err := structItems(p, 2)
		if err != nil {
			return nil, err
		}
		name, err := octetsOf(it[0])
		if err != nil {
			return nil, err
		}
		masks := list(o.MaskList)
		for i, x := range masks {
			if bytes.Equal(maskName(x), name) {
				masks[i] = p
				o.MaskList = arrayOf(masks)
				return nil, nil
			}
		}
		o.MaskList = arrayOf(append(masks, p))
	case 3:
		name, err := octetsOf(p)
		if err != nil {
			return nil, err
		}
		var keep []*axdr.DlmsData
		for _, x := range list(o.MaskList) {
			if !bytes.Equal(maskName(x), name) {
				keep = append(keep, x)
			}
		}
		o.MaskList = arrayOf(keep)
	default:
		return nil, ObjectUndefined
	}
	return nil, nil
}

// RegisterMonitor is class 21: thresholds on another object's value, with
// a script to run when the value crosses each one upwards or downwards.
// Check reads the value through the server and calls OnScript on each
// crossing.
type RegisterMonitor struct {
	sync.Mutex
	LN             string
	Thresholds     *axdr.DlmsData // array of values
	MonitoredValue ValueRef
	Actions        []MonitorAction
	OnScript       func(s ScriptRef) error

	resolver Resolver
	above    []bool
}

// MonitorAction is the pair of scripts of one threshold.
type MonitorAction struct {
	Up, Down ScriptRef
}

func (o *RegisterMonitor) ClassID() uint16     { return 21 }
func (o *RegisterMonitor) Version() uint8      { return 0 }
func (o *RegisterMonitor) LogicalName() string { return o.LN }

// Bind keeps the server's resolver for Check.
func (o *RegisterMonitor) Bind(r Resolver) {
	o.Lock()
	o.resolver = r
	o.Unlock()
}

func (o *RegisterMonitor) attrs() map[int8]attr {
	return map[int8]attr{2: fArray(&o.Thresholds), 3: fValueRef(&o.MonitoredValue), 4: {
		get: func() (*axdr.DlmsData, error) {
			items := make([]*axdr.DlmsData, len(o.Actions))
			for i, a := range o.Actions {
				items[i] = structOf(a.Up.data(), a.Down.data())
			}
			return arrayOf(items), nil
		},
		set: func(d *axdr.DlmsData) error {
			it, err := arrayItems(d)
			if err != nil {
				return err
			}
			acts := make([]MonitorAction, len(it))
			for i, x := range it {
				pair, err := structItems(x, 2)
				if err != nil {
					return err
				}
				if acts[i].Up, err = scriptRefOf(pair[0]); err != nil {
					return err
				}
				if acts[i].Down, err = scriptRefOf(pair[1]); err != nil {
					return err
				}
			}
			o.Actions = acts
			return nil
		}}}
}

func (o *RegisterMonitor) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *RegisterMonitor) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	if a == 2 {
		o.above = nil
	}
	return setAttr(o.attrs(), a, v, sel)
}

func (o *RegisterMonitor) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	return noMethod(m, p)
}

// Check reads the monitored value and runs the up script of every
// threshold it has risen above and the down script of every threshold it
// has fallen to or below since the last Check (the first Check compares
// with "below every threshold").
func (o *RegisterMonitor) Check() error {
	o.Lock()
	r, ref := o.resolver, o.MonitoredValue
	o.Unlock()
	if r == nil {
		return TemporaryFailure
	}
	v, err := r.Resolve(ref.Class, ref.LN, ref.Attr)
	if err != nil {
		return err
	}
	x, isNum := numberOf(v)
	if !isNum {
		return TypeUnmatched
	}
	o.Lock()
	th, _ := arrayItems(o.Thresholds)
	if len(o.above) != len(th) {
		o.above = make([]bool, len(th))
	}
	var run []ScriptRef
	for i, t := range th {
		tv, isNum := numberOf(t)
		if !isNum {
			continue
		}
		now := x > tv
		if now != o.above[i] && i < len(o.Actions) {
			if now {
				run = append(run, o.Actions[i].Up)
			} else {
				run = append(run, o.Actions[i].Down)
			}
		}
		o.above[i] = now
	}
	f := o.OnScript
	o.Unlock()
	if f == nil {
		return nil
	}
	for _, s := range run {
		if err := f(s); err != nil {
			return err
		}
	}
	return nil
}

// SingleActionSchedule is class 22: a script run at given times.
// ExecutionTime is an array of {time, date} octet strings.
type SingleActionSchedule struct {
	sync.Mutex
	LN             string
	ExecutedScript ScriptRef
	Type           uint8
	ExecutionTime  *axdr.DlmsData
}

func (o *SingleActionSchedule) ClassID() uint16     { return 22 }
func (o *SingleActionSchedule) Version() uint8      { return 0 }
func (o *SingleActionSchedule) LogicalName() string { return o.LN }

func (o *SingleActionSchedule) attrs() map[int8]attr {
	return map[int8]attr{
		2: {get: func() (*axdr.DlmsData, error) { return o.ExecutedScript.data(), nil },
			set: func(d *axdr.DlmsData) error {
				s, err := scriptRefOf(d)
				if err == nil {
					o.ExecutedScript = s
				}
				return err
			}},
		3: fEnum(&o.Type), 4: fArray(&o.ExecutionTime),
	}
}

func (o *SingleActionSchedule) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *SingleActionSchedule) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *SingleActionSchedule) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	return noMethod(m, p)
}

// Limiter is class 71: thresholds on a monitored value with scripts for
// going over and under. The structured attributes are kept as A-XDR data;
// EmergencyProfileActive is the meter's to set.
type Limiter struct {
	sync.Mutex
	LN                     string
	MonitoredValue         ValueRef
	ThresholdActive        *axdr.DlmsData
	ThresholdNormal        *axdr.DlmsData
	ThresholdEmergency     *axdr.DlmsData
	MinOverDuration        uint32 // seconds
	MinUnderDuration       uint32 // seconds
	EmergencyProfile       *axdr.DlmsData
	EmergencyGroupIDs      *axdr.DlmsData
	EmergencyProfileActive bool
	Actions                *axdr.DlmsData
}

func (o *Limiter) ClassID() uint16     { return 71 }
func (o *Limiter) Version() uint8      { return 0 }
func (o *Limiter) LogicalName() string { return o.LN }

func (o *Limiter) attrs() map[int8]attr {
	return map[int8]attr{
		2: fValueRef(&o.MonitoredValue), 3: fData(&o.ThresholdActive), 4: fData(&o.ThresholdNormal),
		5: fData(&o.ThresholdEmergency), 6: fU32(&o.MinOverDuration), 7: fU32(&o.MinUnderDuration),
		8: fData(&o.EmergencyProfile), 9: fArray(&o.EmergencyGroupIDs),
		10: readOnly(fBool(&o.EmergencyProfileActive)), 11: fData(&o.Actions),
	}
}

func (o *Limiter) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *Limiter) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *Limiter) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) { return noMethod(m, p) }
