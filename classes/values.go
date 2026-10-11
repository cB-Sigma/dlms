// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// LNOctets turns a logical name written "a.b.c.d.e.f" (each 0 to 255)
// into its six octets.
func LNOctets(ln string) ([]byte, error) {
	parts := strings.Split(ln, ".")
	if len(parts) != 6 {
		return nil, fmt.Errorf("logical name %q does not have six groups", ln)
	}
	b := make([]byte, 6)
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("logical name %q: group %d is not 0 to 255", ln, i+1)
		}
		b[i] = byte(n)
	}
	return b, nil
}

// LNString writes six octets as "a.b.c.d.e.f". Any other length gives "".
func LNString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", b[0], b[1], b[2], b[3], b[4], b[5])
}

// unspecifiedDeviation is the deviation value that says "not given".
const unspecifiedDeviation = 0x8000

// DateTime is the 12-octet COSEM date-time of t: t is shown in loc (t's
// own location when loc is nil), the deviation is the minutes to add to
// that local time to reach UTC, and the clock status has its daylight
// saving bit (0x80) set when loc is on summer time at t. The zero time
// gives the "not specified" form (every field 0xFF, deviation 0x8000).
func DateTime(t time.Time, loc *time.Location) []byte {
	b := make([]byte, 12)
	if t.IsZero() {
		for i := range b {
			b[i] = 0xFF
		}
		binary.BigEndian.PutUint16(b[9:], unspecifiedDeviation)
		return b
	}
	if loc != nil {
		t = t.In(loc)
	}
	binary.BigEndian.PutUint16(b, uint16(t.Year()))
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	b[2], b[3], b[4] = byte(t.Month()), byte(t.Day()), byte(wd)
	b[5], b[6], b[7], b[8] = byte(t.Hour()), byte(t.Minute()), byte(t.Second()), byte(t.Nanosecond()/1e7)
	_, off := t.Zone()
	binary.BigEndian.PutUint16(b[9:], uint16(int16(-off/60)))
	if t.IsDST() {
		b[11] = 0x80
	}
	return b
}

// ParseDateTime reads a 12-octet COSEM date-time. A deviation of 0x8000
// (not specified) means local time in loc (UTC when loc is nil); any other
// deviation fixes the instant. Unspecified hundredths count as 0. It
// reports false for another length or for a year, month, day, hour,
// minute or second that is not specified or out of range.
func ParseDateTime(b []byte, loc *time.Location) (time.Time, bool) {
	if len(b) != 12 {
		return time.Time{}, false
	}
	year := int(binary.BigEndian.Uint16(b[0:2]))
	month, day, hour, minute, sec, hund := int(b[2]), int(b[3]), int(b[5]), int(b[6]), int(b[7]), int(b[8])
	if year == 0xFFFF || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 59 {
		return time.Time{}, false
	}
	if hund == 0xFF || hund > 99 {
		hund = 0
	}
	l := loc
	if l == nil {
		l = time.UTC
	}
	if dev := binary.BigEndian.Uint16(b[9:11]); dev != unspecifiedDeviation {
		l = time.FixedZone("", -int(int16(dev))*60)
	}
	return time.Date(year, time.Month(month), day, hour, minute, sec, hund*1e7, l), true
}

// unspecifiedDateTime reports whether b is the all-"not specified" form.
func unspecifiedDateTime(b []byte) bool {
	if len(b) != 12 {
		return false
	}
	for i := 0; i < 9; i++ {
		if b[i] != 0xFF {
			return false
		}
	}
	return true
}

// --- encoding helpers: Go values to A-XDR ---

func octetData(b []byte) *axdr.DlmsData {
	return axdr.CreateAxdrOctetString(hex.EncodeToString(b))
}

// lnData is the logical name as six octets (zeros when ln is malformed;
// the server checks names when objects are added).
func lnData(ln string) *axdr.DlmsData {
	b, err := LNOctets(ln)
	if err != nil {
		b = make([]byte, 6)
	}
	return octetData(b)
}

func dtData(t time.Time, loc *time.Location) *axdr.DlmsData {
	return octetData(DateTime(t, loc))
}

func nullData() *axdr.DlmsData { return axdr.CreateAxdrNull() }

func orNull(d *axdr.DlmsData) *axdr.DlmsData {
	if d == nil {
		return nullData()
	}
	return d
}

func structOf(items ...*axdr.DlmsData) *axdr.DlmsData {
	return axdr.CreateAxdrStructure(items)
}

func arrayOf(items []*axdr.DlmsData) *axdr.DlmsData {
	if items == nil {
		items = []*axdr.DlmsData{}
	}
	return axdr.CreateAxdrArray(items)
}

func scalerUnitData(scaler int8, unit uint8) *axdr.DlmsData {
	return structOf(axdr.CreateAxdrInteger(scaler), axdr.CreateAxdrEnum(unit))
}

// --- decoding helpers: A-XDR to Go values, TypeUnmatched on a mismatch ---

func tagIs(d *axdr.DlmsData, tag axdr.DlmsData) bool {
	return d != nil && d.Tag == tag.Tag
}

var (
	tUnsigned     = axdr.DlmsData{Tag: axdr.TagUnsigned}
	tEnum         = axdr.DlmsData{Tag: axdr.TagEnum}
	tLongUnsigned = axdr.DlmsData{Tag: axdr.TagLongUnsigned}
	tDLU          = axdr.DlmsData{Tag: axdr.TagDoubleLongUnsigned}
	tInteger      = axdr.DlmsData{Tag: axdr.TagInteger}
	tLong         = axdr.DlmsData{Tag: axdr.TagLong}
	tBoolean      = axdr.DlmsData{Tag: axdr.TagBoolean}
	tOctet        = axdr.DlmsData{Tag: axdr.TagOctetString}
	tStructure    = axdr.DlmsData{Tag: axdr.TagStructure}
	tArray        = axdr.DlmsData{Tag: axdr.TagArray}
	tBitString    = axdr.DlmsData{Tag: axdr.TagBitString}
)

func u8Of(d *axdr.DlmsData) (uint8, error) {
	if !tagIs(d, tUnsigned) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(uint8)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func enumOf(d *axdr.DlmsData) (uint8, error) {
	if !tagIs(d, tEnum) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(uint8)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func u16Of(d *axdr.DlmsData) (uint16, error) {
	if !tagIs(d, tLongUnsigned) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(uint16)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func u32Of(d *axdr.DlmsData) (uint32, error) {
	if !tagIs(d, tDLU) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(uint32)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func i8Of(d *axdr.DlmsData) (int8, error) {
	if !tagIs(d, tInteger) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(int8)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func i16Of(d *axdr.DlmsData) (int16, error) {
	if !tagIs(d, tLong) {
		return 0, TypeUnmatched
	}
	v, ok := d.Value.(int16)
	if !ok {
		return 0, TypeUnmatched
	}
	return v, nil
}

func boolOf(d *axdr.DlmsData) (bool, error) {
	if !tagIs(d, tBoolean) {
		return false, TypeUnmatched
	}
	v, ok := d.Value.(bool)
	if !ok {
		return false, TypeUnmatched
	}
	return v, nil
}

// octetsOf reads an octet string, carried as hexadecimal text (as gosem
// decodes it) or as bytes.
func octetsOf(d *axdr.DlmsData) ([]byte, error) {
	if !tagIs(d, tOctet) {
		return nil, TypeUnmatched
	}
	switch v := d.Value.(type) {
	case string:
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, TypeUnmatched
		}
		return b, nil
	case []byte:
		return append([]byte(nil), v...), nil
	}
	return nil, TypeUnmatched
}

func lnOf(d *axdr.DlmsData) (string, error) {
	b, err := octetsOf(d)
	if err != nil || len(b) != 6 {
		return "", TypeUnmatched
	}
	return LNString(b), nil
}

// dateTimeOf reads a date-time attribute: a 12-octet string (the
// all-unspecified form gives the zero time) or gosem's date-time value.
func dateTimeOf(d *axdr.DlmsData, loc *time.Location) (time.Time, error) {
	if d != nil && d.Tag == axdr.TagDateTime {
		if t, ok := d.Value.(time.Time); ok {
			return t, nil
		}
		return time.Time{}, TypeUnmatched
	}
	b, err := octetsOf(d)
	if err != nil || len(b) != 12 {
		return time.Time{}, TypeUnmatched
	}
	if unspecifiedDateTime(b) {
		return time.Time{}, nil
	}
	t, ok := ParseDateTime(b, loc)
	if !ok {
		return time.Time{}, TypeUnmatched
	}
	return t, nil
}

func itemsOf(d *axdr.DlmsData, tag axdr.DlmsData, n int) ([]*axdr.DlmsData, error) {
	if !tagIs(d, tag) {
		return nil, TypeUnmatched
	}
	items, ok := d.Value.([]*axdr.DlmsData)
	if !ok {
		return nil, TypeUnmatched
	}
	if n >= 0 && len(items) != n {
		return nil, TypeUnmatched
	}
	for _, it := range items {
		if it == nil {
			return nil, TypeUnmatched
		}
	}
	return items, nil
}

func structItems(d *axdr.DlmsData, n int) ([]*axdr.DlmsData, error) {
	return itemsOf(d, tStructure, n)
}

func arrayItems(d *axdr.DlmsData) ([]*axdr.DlmsData, error) {
	return itemsOf(d, tArray, -1)
}

func scalerUnitOf(d *axdr.DlmsData) (int8, uint8, error) {
	it, err := structItems(d, 2)
	if err != nil {
		return 0, 0, err
	}
	s, err := i8Of(it[0])
	if err != nil {
		return 0, 0, err
	}
	u, err := enumOf(it[1])
	if err != nil {
		return 0, 0, err
	}
	return s, u, nil
}

// sameType checks that v may replace old: any type when old is nil or
// null-data, otherwise the same tag.
func sameType(old, v *axdr.DlmsData) error {
	if v == nil {
		return TypeUnmatched
	}
	if old == nil || old.Tag == axdr.TagNull {
		return nil
	}
	if old.Tag != v.Tag {
		return TypeUnmatched
	}
	return nil
}

// zeroOf is a value of d's type set to zero (empty for strings and lists).
func zeroOf(d *axdr.DlmsData) *axdr.DlmsData {
	if d == nil {
		return nil
	}
	z := &axdr.DlmsData{Tag: d.Tag}
	switch d.Value.(type) {
	case int8:
		z.Value = int8(0)
	case int16:
		z.Value = int16(0)
	case int32:
		z.Value = int32(0)
	case int64:
		z.Value = int64(0)
	case uint8:
		z.Value = uint8(0)
	case uint16:
		z.Value = uint16(0)
	case uint32:
		z.Value = uint32(0)
	case uint64:
		z.Value = uint64(0)
	case float32:
		z.Value = float32(0)
	case float64:
		z.Value = float64(0)
	case bool:
		z.Value = false
	case string:
		z.Value = ""
	case []byte:
		z.Value = []byte{}
	case []*axdr.DlmsData:
		z.Value = []*axdr.DlmsData{}
	default:
		z.Value = d.Value
	}
	return z
}

// numberOf reads any numeric A-XDR value.
func numberOf(d *axdr.DlmsData) (float64, bool) {
	if d == nil {
		return 0, false
	}
	switch v := d.Value.(type) {
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// --- attribute dispatch shared by the typed objects ---

// attr is one attribute of a typed object: get encodes it, set (nil when
// the attribute is read-only) decodes and stores it.
type attr struct {
	get func() (*axdr.DlmsData, error)
	set func(*axdr.DlmsData) error
}

// getAttr answers a GET for an object without selective access.
func getAttr(ln string, attrs map[int8]attr, a int8, sel *Selector) (*axdr.DlmsData, error) {
	if sel != nil {
		return nil, ScopeViolated
	}
	if a == 1 {
		return lnData(ln), nil
	}
	at, ok := attrs[a]
	if !ok {
		return nil, ObjectUndefined
	}
	return at.get()
}

// setAttr answers a SET.
func setAttr(attrs map[int8]attr, a int8, v *axdr.DlmsData, sel *Selector) error {
	if sel != nil {
		return ScopeViolated
	}
	if a == 1 {
		return ReadWriteDenied
	}
	at, ok := attrs[a]
	if !ok {
		return ObjectUndefined
	}
	if at.set == nil {
		return ReadWriteDenied
	}
	if v == nil {
		return TypeUnmatched
	}
	return at.set(v)
}

// Field adapters: each returns an attr bound to a Go field.

func fU8(p *uint8) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrUnsigned(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := u8Of(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fEnum(p *uint8) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrEnum(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := enumOf(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fU16(p *uint16) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrLongUnsigned(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := u16Of(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fU32(p *uint32) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrDoubleLongUnsigned(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := u32Of(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fI8(p *int8) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrInteger(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := i8Of(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fI16(p *int16) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrLong(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := i16Of(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fBool(p *bool) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrBoolean(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := boolOf(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fOctets(p *[]byte) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return octetData(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := octetsOf(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fLN(p *string) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return lnData(*p), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := lnOf(d)
			if err == nil {
				*p = v
			}
			return err
		}}
}

func fTime(p *time.Time, loc func() *time.Location) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return dtData(*p, loc()), nil },
		set: func(d *axdr.DlmsData) error {
			v, err := dateTimeOf(d, loc())
			if err == nil {
				*p = v
			}
			return err
		}}
}

// fData is an attribute held as A-XDR data; a SET keeps the type when one
// is set (null-data or nil accepts any).
func fData(p **axdr.DlmsData) attr {
	return attr{get: func() (*axdr.DlmsData, error) { return orNull(*p), nil },
		set: func(d *axdr.DlmsData) error {
			if err := sameType(*p, d); err != nil {
				return err
			}
			*p = d
			return nil
		}}
}

// fArray is an attribute that is an array held as A-XDR data.
func fArray(p **axdr.DlmsData) attr {
	return attr{get: func() (*axdr.DlmsData, error) {
		if *p == nil {
			return arrayOf(nil), nil
		}
		return *p, nil
	}, set: func(d *axdr.DlmsData) error {
		if _, err := arrayItems(d); err != nil {
			return err
		}
		*p = d
		return nil
	}}
}

func readOnly(a attr) attr { a.set = nil; return a }

func locOr(l *time.Location) *time.Location {
	if l == nil {
		return time.Local
	}
	return l
}

func nowOr(f func() time.Time) time.Time {
	if f == nil {
		return time.Now()
	}
	return f()
}
