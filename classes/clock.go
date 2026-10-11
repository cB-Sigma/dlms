// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Clock is class 8. Its time runs from Now (time.Now when nil) plus an
// offset that SETs of the time and the adjusting methods move, so a meter
// simulator or gateway can keep its own clock without touching the host's.
// The time is shown in Location (time.Local when nil).
type Clock struct {
	sync.Mutex
	LN       string
	Now      func() time.Time
	Location *time.Location
	// TimeZone is the zone's distance from UTC in minutes, as the class
	// carries it; it is reported as set and does not move the time.
	TimeZone int16
	// Status is OR-ed into the clock status octet of the time (the
	// daylight saving bit comes from Location).
	Status uint8
	// DSTBegin and DSTEnd are 12-octet date-times, wildcards allowed.
	DSTBegin     []byte
	DSTEnd       []byte
	DSTDeviation int8 // minutes
	DSTEnabled   bool
	ClockBase    uint8
	// MeasuringPeriod is the period adjust_to_measuring_period rounds to;
	// that method is refused while it is 0.
	MeasuringPeriod time.Duration

	offset                     time.Duration
	preset, validFrom, validTo time.Time
	presetSet                  bool
}

func (o *Clock) ClassID() uint16     { return 8 }
func (o *Clock) Version() uint8      { return 0 }
func (o *Clock) LogicalName() string { return o.LN }

func (o *Clock) loc() *time.Location { return locOr(o.Location) }

func (o *Clock) current() time.Time { return nowOr(o.Now).Add(o.offset).In(o.loc()) }

func (o *Clock) setTime(t time.Time) { o.offset = t.Sub(nowOr(o.Now)) }

// Time is the clock's current time.
func (o *Clock) Time() time.Time {
	o.Lock()
	defer o.Unlock()
	return o.current()
}

// SetTime moves the clock to t.
func (o *Clock) SetTime(t time.Time) {
	o.Lock()
	o.setTime(t)
	o.Unlock()
}

func pattern12(p *[]byte) attr {
	return attr{get: func() (*axdr.DlmsData, error) {
		if len(*p) != 12 {
			return octetData(DateTime(time.Time{}, nil)), nil
		}
		return octetData(*p), nil
	}, set: func(d *axdr.DlmsData) error {
		b, err := octetsOf(d)
		if err != nil || len(b) != 12 {
			return TypeUnmatched
		}
		*p = b
		return nil
	}}
}

func (o *Clock) attrs() map[int8]attr {
	return map[int8]attr{
		2: {get: func() (*axdr.DlmsData, error) {
			b := DateTime(o.current(), o.loc())
			b[11] |= o.Status
			return octetData(b), nil
		}, set: func(d *axdr.DlmsData) error {
			t, err := dateTimeOf(d, o.loc())
			if err != nil {
				return err
			}
			if t.IsZero() {
				return TypeUnmatched
			}
			o.setTime(t)
			return nil
		}},
		3: fI16(&o.TimeZone),
		4: readOnly(fU8(&o.Status)),
		5: pattern12(&o.DSTBegin),
		6: pattern12(&o.DSTEnd),
		7: fI8(&o.DSTDeviation),
		8: fBool(&o.DSTEnabled),
		9: readOnly(fEnum(&o.ClockBase)),
	}
}

func (o *Clock) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *Clock) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// roundLocal rounds t to the nearest multiple of d counted from local
// midnight.
func roundLocal(t time.Time, d time.Duration) time.Time {
	y, m, day := t.Date()
	midnight := time.Date(y, m, day, 0, 0, 0, 0, t.Location())
	since := t.Sub(midnight)
	return midnight.Add(since.Round(d))
}

// Action runs adjust_to_quarter (1), adjust_to_measuring_period (2),
// adjust_to_minute (3), adjust_to_preset_time (4), preset_adjusting_time
// (5: {preset time, valid from, valid to}) and shift_time (6: seconds,
// -900 to 900).
func (o *Clock) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	switch m {
	case 1:
		o.setTime(roundLocal(o.current(), 15*time.Minute))
	case 2:
		if o.MeasuringPeriod <= 0 {
			return nil, ReadWriteDenied
		}
		o.setTime(roundLocal(o.current(), o.MeasuringPeriod))
	case 3:
		o.setTime(roundLocal(o.current(), time.Minute))
	case 4:
		now := o.current()
		if !o.presetSet || now.Before(o.validFrom) || now.After(o.validTo) {
			return nil, TemporaryFailure
		}
		o.setTime(o.preset)
		o.presetSet = false
	case 5:
		it, err := structItems(p, 3)
		if err != nil {
			return nil, err
		}
		var ts [3]time.Time
		for i := range ts {
			if ts[i], err = dateTimeOf(it[i], o.loc()); err != nil {
				return nil, err
			}
		}
		o.preset, o.validFrom, o.validTo, o.presetSet = ts[0], ts[1], ts[2], true
	case 6:
		s, err := i16Of(p)
		if err != nil {
			return nil, err
		}
		if s < -900 || s > 900 {
			return nil, OtherReason
		}
		o.offset += time.Duration(s) * time.Second
	default:
		return nil, ObjectUndefined
	}
	return nil, nil
}
