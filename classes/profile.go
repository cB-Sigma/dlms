// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// CaptureObject is one column of a profile (or one value of a push): an
// attribute of another object, and with DataIndex above 0 only that
// element (1-based) of it.
type CaptureObject struct {
	Class     uint16
	LN        string
	Attr      int8
	DataIndex uint16
}

func (c CaptureObject) data() *axdr.DlmsData {
	return structOf(axdr.CreateAxdrLongUnsigned(c.Class), lnData(c.LN), axdr.CreateAxdrInteger(c.Attr),
		axdr.CreateAxdrLongUnsigned(c.DataIndex))
}

func captureObjectOf(d *axdr.DlmsData) (CaptureObject, error) {
	it, err := structItems(d, 4)
	if err != nil {
		return CaptureObject{}, err
	}
	var c CaptureObject
	if c.Class, err = u16Of(it[0]); err != nil {
		return c, err
	}
	if c.LN, err = lnOf(it[1]); err != nil {
		return c, err
	}
	if c.Attr, err = i8Of(it[2]); err != nil {
		return c, err
	}
	c.DataIndex, err = u16Of(it[3])
	return c, err
}

func captureListData(list []CaptureObject) *axdr.DlmsData {
	items := make([]*axdr.DlmsData, len(list))
	for i, c := range list {
		items[i] = c.data()
	}
	return arrayOf(items)
}

func captureListOf(d *axdr.DlmsData) ([]CaptureObject, error) {
	it, err := arrayItems(d)
	if err != nil {
		return nil, err
	}
	out := make([]CaptureObject, len(it))
	for i, x := range it {
		if out[i], err = captureObjectOf(x); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// resolveCapture reads one capture object through r.
func resolveCapture(r Resolver, c CaptureObject) (*axdr.DlmsData, error) {
	v, err := r.Resolve(c.Class, c.LN, c.Attr)
	if err != nil {
		return nil, err
	}
	if c.DataIndex == 0 || v == nil {
		return orNull(v), nil
	}
	items, isList := v.Value.([]*axdr.DlmsData)
	if !isList || int(c.DataIndex) > len(items) || items[c.DataIndex-1] == nil {
		return nullData(), nil
	}
	return items[c.DataIndex-1], nil
}

// ProfileGeneric is class 7: a buffer of rows, each row one capture of
// the capture objects. Rows are kept oldest first; once ProfileEntries
// (when above 0) is reached a capture drops the oldest row. Only that
// first-in first-out order is implemented; SortMethod and SortObject are
// kept and reported but do not reorder the buffer.
//
// Reading the buffer takes selective access by range (selector 1: rows
// whose restricting column lies between two values, date-times or
// numbers) and by entry (selector 2: a window of rows and columns,
// 1-based, 0 meaning "to the last").
type ProfileGeneric struct {
	sync.Mutex
	LN             string
	Buffer         [][]*axdr.DlmsData
	CaptureObjects []CaptureObject
	CapturePeriod  uint32 // seconds; 0: captured only on request
	SortMethod     uint8
	SortObject     CaptureObject
	ProfileEntries uint32
	// Location is the meter's time zone for date-times without a
	// deviation (time.Local when nil).
	Location *time.Location

	resolver Resolver
}

func (o *ProfileGeneric) ClassID() uint16     { return 7 }
func (o *ProfileGeneric) Version() uint8      { return 1 }
func (o *ProfileGeneric) LogicalName() string { return o.LN }

// Bind keeps the server's resolver for captures.
func (o *ProfileGeneric) Bind(r Resolver) {
	o.Lock()
	o.resolver = r
	o.Unlock()
}

func (o *ProfileGeneric) attrs() map[int8]attr {
	return map[int8]attr{
		2: {get: func() (*axdr.DlmsData, error) { return o.rows(o.Buffer, nil), nil }},
		3: {get: func() (*axdr.DlmsData, error) { return captureListData(o.CaptureObjects), nil },
			set: func(d *axdr.DlmsData) error {
				list, err := captureListOf(d)
				if err == nil {
					o.CaptureObjects, o.Buffer = list, nil
				}
				return err
			}},
		4: fU32(&o.CapturePeriod),
		5: fEnum(&o.SortMethod),
		6: {get: func() (*axdr.DlmsData, error) { return o.SortObject.data(), nil },
			set: func(d *axdr.DlmsData) error {
				c, err := captureObjectOf(d)
				if err == nil {
					o.SortObject = c
				}
				return err
			}},
		7: {get: func() (*axdr.DlmsData, error) {
			return axdr.CreateAxdrDoubleLongUnsigned(uint32(len(o.Buffer))), nil
		}},
		8: {get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrDoubleLongUnsigned(o.ProfileEntries), nil },
			set: func(d *axdr.DlmsData) error {
				v, err := u32Of(d)
				if err == nil {
					o.ProfileEntries = v
					o.trim()
				}
				return err
			}},
	}
}

func (o *ProfileGeneric) trim() {
	if o.ProfileEntries > 0 && len(o.Buffer) > int(o.ProfileEntries) {
		o.Buffer = append([][]*axdr.DlmsData(nil), o.Buffer[len(o.Buffer)-int(o.ProfileEntries):]...)
	}
}

// rows encodes rows as an array of structures, keeping only the columns
// cols (all when nil).
func (o *ProfileGeneric) rows(rows [][]*axdr.DlmsData, cols []int) *axdr.DlmsData {
	out := make([]*axdr.DlmsData, len(rows))
	for i, r := range rows {
		var vals []*axdr.DlmsData
		if cols == nil {
			vals = make([]*axdr.DlmsData, len(r))
			for j, v := range r {
				vals[j] = orNull(v)
			}
		} else {
			vals = make([]*axdr.DlmsData, len(cols))
			for j, c := range cols {
				if c < len(r) {
					vals[j] = orNull(r[c])
				} else {
					vals[j] = nullData()
				}
			}
		}
		out[i] = structOf(vals...)
	}
	return arrayOf(out)
}

func (o *ProfileGeneric) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	if a == 2 && sel != nil {
		switch sel.ID {
		case 1:
			return o.byRange(sel.Parameters)
		case 2:
			return o.byEntry(sel.Parameters)
		}
		return nil, ScopeViolated
	}
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *ProfileGeneric) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *ProfileGeneric) column(c CaptureObject, matchIndex bool) int {
	for i, x := range o.CaptureObjects {
		if x.Class == c.Class && x.LN == c.LN && x.Attr == c.Attr && (!matchIndex || x.DataIndex == c.DataIndex) {
			return i
		}
	}
	return -1
}

// columns maps a selected-values list to column positions (nil: all).
func (o *ProfileGeneric) columns(d *axdr.DlmsData) ([]int, error) {
	list, err := captureListOf(d)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	cols := make([]int, len(list))
	for i, c := range list {
		if cols[i] = o.column(c, true); cols[i] < 0 {
			return nil, ObjectUnavailable
		}
	}
	return cols, nil
}

func (o *ProfileGeneric) byRange(p *axdr.DlmsData) (*axdr.DlmsData, error) {
	it, err := structItems(p, 4)
	if err != nil {
		return nil, err
	}
	restrict, err := captureObjectOf(it[0])
	if err != nil {
		return nil, err
	}
	col := o.column(restrict, false)
	if col < 0 {
		return nil, ObjectUnavailable
	}
	cols, err := o.columns(it[3])
	if err != nil {
		return nil, err
	}
	loc := locOr(o.Location)
	var keep [][]*axdr.DlmsData
	for _, r := range o.Buffer {
		if col >= len(r) {
			continue
		}
		lo, ok1 := compareValues(r[col], it[1], loc)
		hi, ok2 := compareValues(r[col], it[2], loc)
		if ok1 && ok2 && lo >= 0 && hi <= 0 {
			keep = append(keep, r)
		}
	}
	return o.rows(keep, cols), nil
}

func (o *ProfileGeneric) byEntry(p *axdr.DlmsData) (*axdr.DlmsData, error) {
	it, err := structItems(p, 4)
	if err != nil {
		return nil, err
	}
	from, err := u32Of(it[0])
	if err != nil {
		return nil, err
	}
	to, err := u32Of(it[1])
	if err != nil {
		return nil, err
	}
	fromCol, err := u16Of(it[2])
	if err != nil {
		return nil, err
	}
	toCol, err := u16Of(it[3])
	if err != nil {
		return nil, err
	}
	n := uint32(len(o.Buffer))
	if from == 0 {
		from = 1
	}
	if to == 0 || to > n {
		to = n
	}
	var rows [][]*axdr.DlmsData
	if from <= to {
		rows = o.Buffer[from-1 : to]
	}
	nc := uint16(len(o.CaptureObjects))
	if fromCol == 0 {
		fromCol = 1
	}
	if toCol == 0 || toCol > nc {
		toCol = nc
	}
	cols := []int{}
	for c := fromCol; c <= toCol && c > 0; c++ {
		cols = append(cols, int(c-1))
	}
	return o.rows(rows, cols), nil
}

// compareValues orders a against b: both date-times, or both numbers.
func compareValues(a, b *axdr.DlmsData, loc *time.Location) (int, bool) {
	if ta, ok := asTime(a, loc); ok {
		tb, ok := asTime(b, loc)
		if !ok {
			return 0, false
		}
		return ta.Compare(tb), true
	}
	x, ok1 := numberOf(a)
	y, ok2 := numberOf(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	switch {
	case x < y:
		return -1, true
	case x > y:
		return 1, true
	}
	return 0, true
}

func asTime(d *axdr.DlmsData, loc *time.Location) (time.Time, bool) {
	if d == nil {
		return time.Time{}, false
	}
	if t, ok := d.Value.(time.Time); ok {
		return t, true
	}
	b, err := octetsOf(d)
	if err != nil {
		return time.Time{}, false
	}
	return ParseDateTime(b, loc)
}

// Action runs reset (1: the buffer is emptied) and capture (2).
func (o *ProfileGeneric) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	switch m {
	case 1:
		o.Lock()
		o.Buffer = nil
		o.Unlock()
		return nil, nil
	case 2:
		return nil, o.Capture()
	}
	return nil, ObjectUndefined
}

// Capture reads every capture object through the server and appends the
// row. It reports TemporaryFailure before Bind, and the first error of a
// read (no row is added then).
func (o *ProfileGeneric) Capture() error {
	o.Lock()
	r := o.resolver
	objs := append([]CaptureObject(nil), o.CaptureObjects...)
	o.Unlock()
	if r == nil {
		return TemporaryFailure
	}
	row := make([]*axdr.DlmsData, len(objs))
	for i, c := range objs {
		v, err := resolveCapture(r, c)
		if err != nil {
			return err
		}
		row[i] = v
	}
	o.Lock()
	defer o.Unlock()
	if len(o.CaptureObjects) != len(objs) {
		return TemporaryFailure // the columns changed while reading
	}
	o.Buffer = append(o.Buffer, row)
	o.trim()
	return nil
}
