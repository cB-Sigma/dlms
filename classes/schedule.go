// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// ScriptTable is class 9. Scripts is kept as A-XDR data (an array of
// {script id, actions}); execute (1) calls OnExecute with the script id.
type ScriptTable struct {
	sync.Mutex
	LN        string
	Scripts   *axdr.DlmsData
	OnExecute func(id uint16) error
}

func (o *ScriptTable) ClassID() uint16     { return 9 }
func (o *ScriptTable) Version() uint8      { return 0 }
func (o *ScriptTable) LogicalName() string { return o.LN }

func (o *ScriptTable) attrs() map[int8]attr { return map[int8]attr{2: fArray(&o.Scripts)} }

func (o *ScriptTable) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *ScriptTable) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs execute (1, the script id as long-unsigned).
func (o *ScriptTable) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	id, err := u16Of(p)
	if err != nil {
		return nil, err
	}
	o.Lock()
	f := o.OnExecute
	o.Unlock()
	if f != nil {
		return nil, f(id)
	}
	return nil, nil
}

// Schedule is class 10. Entries is an array of entry structures whose
// first element is the entry's index (long-unsigned). insert (2) adds or
// replaces an entry; delete (3, {first, last}) removes a range of
// indexes. enable_disable (1) is refused: it is not implemented here.
type Schedule struct {
	sync.Mutex
	LN      string
	Entries *axdr.DlmsData
}

func (o *Schedule) ClassID() uint16     { return 10 }
func (o *Schedule) Version() uint8      { return 0 }
func (o *Schedule) LogicalName() string { return o.LN }

func (o *Schedule) attrs() map[int8]attr { return map[int8]attr{2: fArray(&o.Entries)} }

func (o *Schedule) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *Schedule) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func entryIndex(d *axdr.DlmsData) (uint16, bool) {
	it, err := structItems(d, -1)
	if err != nil || len(it) == 0 {
		return 0, false
	}
	v, err := u16Of(it[0])
	return v, err == nil
}

func (o *Schedule) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	entries, _ := arrayItems(o.Entries)
	switch m {
	case 1:
		return nil, ReadWriteDenied
	case 2:
		idx, isEntry := entryIndex(p)
		if !isEntry {
			return nil, TypeUnmatched
		}
		for i, e := range entries {
			if x, _ := entryIndex(e); x == idx {
				entries[i] = p
				o.Entries = arrayOf(entries)
				return nil, nil
			}
		}
		o.Entries = arrayOf(append(entries, p))
	case 3:
		it, err := structItems(p, 2)
		if err != nil {
			return nil, err
		}
		first, err := u16Of(it[0])
		if err != nil {
			return nil, err
		}
		last, err := u16Of(it[1])
		if err != nil {
			return nil, err
		}
		var keep []*axdr.DlmsData
		for _, e := range entries {
			if x, _ := entryIndex(e); x < first || x > last {
				keep = append(keep, e)
			}
		}
		o.Entries = arrayOf(keep)
	default:
		return nil, ObjectUndefined
	}
	return nil, nil
}

// SpecialDay is one entry of a special days table: Date is the 5-octet
// COSEM date (wildcards allowed), DayID the day profile to use.
type SpecialDay struct {
	Index uint16
	Date  []byte
	DayID uint8
}

func (s SpecialDay) data() *axdr.DlmsData {
	return structOf(axdr.CreateAxdrLongUnsigned(s.Index), octetData(s.Date), axdr.CreateAxdrUnsigned(s.DayID))
}

func specialDayOf(d *axdr.DlmsData) (SpecialDay, error) {
	it, err := structItems(d, 3)
	if err != nil {
		return SpecialDay{}, err
	}
	var s SpecialDay
	if s.Index, err = u16Of(it[0]); err != nil {
		return s, err
	}
	if s.Date, err = octetsOf(it[1]); err != nil {
		return s, err
	}
	s.DayID, err = u8Of(it[2])
	return s, err
}

// SpecialDaysTable is class 11: insert (1) adds or replaces an entry by
// index, delete (2) removes one by index.
type SpecialDaysTable struct {
	sync.Mutex
	LN      string
	Entries []SpecialDay
}

func (o *SpecialDaysTable) ClassID() uint16     { return 11 }
func (o *SpecialDaysTable) Version() uint8      { return 0 }
func (o *SpecialDaysTable) LogicalName() string { return o.LN }

func (o *SpecialDaysTable) attrs() map[int8]attr {
	return map[int8]attr{2: {get: func() (*axdr.DlmsData, error) {
		items := make([]*axdr.DlmsData, len(o.Entries))
		for i, e := range o.Entries {
			items[i] = e.data()
		}
		return arrayOf(items), nil
	}, set: func(d *axdr.DlmsData) error {
		it, err := arrayItems(d)
		if err != nil {
			return err
		}
		out := make([]SpecialDay, len(it))
		for i, x := range it {
			if out[i], err = specialDayOf(x); err != nil {
				return err
			}
		}
		o.Entries = out
		return nil
	}}}
}

func (o *SpecialDaysTable) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *SpecialDaysTable) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *SpecialDaysTable) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	switch m {
	case 1:
		s, err := specialDayOf(p)
		if err != nil {
			return nil, err
		}
		for i := range o.Entries {
			if o.Entries[i].Index == s.Index {
				o.Entries[i] = s
				return nil, nil
			}
		}
		o.Entries = append(o.Entries, s)
	case 2:
		idx, err := u16Of(p)
		if err != nil {
			return nil, err
		}
		var keep []SpecialDay
		for _, e := range o.Entries {
			if e.Index != idx {
				keep = append(keep, e)
			}
		}
		o.Entries = keep
	default:
		return nil, ObjectUndefined
	}
	return nil, nil
}

// ActivityCalendar is class 20. The profiles are kept as A-XDR arrays;
// the active calendar is read-only and changes only by
// activate_passive_calendar (1), which copies the passive one over it.
// ActivatePassiveTime is a 12-octet date-time (wildcards allowed).
type ActivityCalendar struct {
	sync.Mutex
	LN                  string
	NameActive          []byte
	SeasonActive        *axdr.DlmsData
	WeekActive          *axdr.DlmsData
	DayActive           *axdr.DlmsData
	NamePassive         []byte
	SeasonPassive       *axdr.DlmsData
	WeekPassive         *axdr.DlmsData
	DayPassive          *axdr.DlmsData
	ActivatePassiveTime []byte
}

func (o *ActivityCalendar) ClassID() uint16     { return 20 }
func (o *ActivityCalendar) Version() uint8      { return 0 }
func (o *ActivityCalendar) LogicalName() string { return o.LN }

func (o *ActivityCalendar) attrs() map[int8]attr {
	return map[int8]attr{
		2: readOnly(fOctets(&o.NameActive)), 3: readOnly(fArray(&o.SeasonActive)),
		4: readOnly(fArray(&o.WeekActive)), 5: readOnly(fArray(&o.DayActive)),
		6: fOctets(&o.NamePassive), 7: fArray(&o.SeasonPassive), 8: fArray(&o.WeekPassive),
		9: fArray(&o.DayPassive), 10: pattern12(&o.ActivatePassiveTime),
	}
}

func (o *ActivityCalendar) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *ActivityCalendar) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *ActivityCalendar) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	o.Lock()
	defer o.Unlock()
	o.ActivatePassive()
	return nil, nil
}

// ActivatePassive copies the passive calendar over the active one (the
// caller holds the lock; the meter calls it when ActivatePassiveTime
// comes).
func (o *ActivityCalendar) ActivatePassive() {
	o.NameActive = append([]byte(nil), o.NamePassive...)
	o.SeasonActive, o.WeekActive, o.DayActive = o.SeasonPassive, o.WeekPassive, o.DayPassive
}
