package cosem

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/is15959"
)

// IsTimeColumn reports a capture object holding a date-time that times a
// profile's entries: the clock's time (IEC 62056-6-2:2023 4.5.1), or the
// time stamp of the billing period (6.2.3: a Data object, or a register
// or extended register with scaler 0 and no unit).
func IsTimeColumn(c Capture) bool {
	if c.Attr != 2 {
		return false
	}
	switch c.Class {
	case ClassClock:
		return true
	case ClassData, ClassRegister, ClassExtendedRegister:
		return c.OBIS == "0.0.0.1.2.255"
	}
	return false
}

// TimeColumn returns the first time column of a profile.
func TimeColumn(cols []Capture) (int, bool) {
	for i, c := range cols {
		if IsTimeColumn(c) {
			return i, true
		}
	}
	return 0, false
}

// RangeDescriptor is the selective access by range of a profile's buffer
// (IEC 62056-6-2:2023 4.3.6.2.9, access selector 1): restricted by the
// profile's own time column (a capture_object_definition with data index
// 0), from and to as date-time octet strings in the meter's local time,
// and every column (an empty selected_values).
func RangeDescriptor(c Capture, from, to time.Time, loc *time.Location) *axdr.DlmsData {
	ln, _ := ParseOBIS(c.OBIS)
	return axdr.CreateAxdrStructure([]*axdr.DlmsData{
		axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(c.Class), axdr.CreateAxdrOctetString(hex.EncodeToString(ln[:])),
			axdr.CreateAxdrInteger(c.Attr), axdr.CreateAxdrLongUnsigned(0),
		}),
		axdr.CreateAxdrOctetString(hex.EncodeToString(EncodeDateTime(from, loc))),
		axdr.CreateAxdrOctetString(hex.EncodeToString(EncodeDateTime(to, loc))),
		axdr.CreateAxdrArray([]*axdr.DlmsData{}),
	})
}

// RowScalers gives ProfileRow what it needs beyond the entry: the time
// zone of the meter's clock (deviation unspecified), a register's scaler
// (Scaler), the scaler of the value a limiter monitors (Limiter, for its
// thresholds; nil: unscaled) and an event code's name (EventName; nil:
// is15959.CodeName).
type RowScalers struct {
	Location  *time.Location
	Scaler    func(class uint16, obis string) Scaler
	Limiter   func(obis string) Scaler
	EventName func(code int) string
}

// ProfileRow is a profile entry as written: each capture object's value
// by its name, register values scaled by the meter's scaler_unit with the
// units under "units", an event code named, and the entry's time from its
// first time column (zero when it has none).
func ProfileRow(r *axdr.DlmsData, cols []Capture, x RowScalers) (map[string]any, time.Time) {
	loc := x.Location
	if loc == nil {
		loc = time.UTC
	}
	fields, _ := r.Value.([]*axdr.DlmsData)
	row := map[string]any{}
	// Each value's unit as the meter reports it (scaler_unit), for those that have one.
	units := map[string]any{}
	var at time.Time
	for i, f := range fields {
		if i >= len(cols) || f == nil {
			break
		}
		c := cols[i]
		isClock := IsTimeColumn(c)
		v := Value(*f, loc, isClock)
		if isClock && at.IsZero() {
			if s, ok := f.Value.(string); ok {
				if t, ok := DateTime(s, loc); ok {
					at = t
				}
				if st, ok := ClockStatus(s); ok {
					row["clockStatus"] = float64(st)
				}
			}
		}
		if ScaledValue(c.Class, c.Attr) {
			if n, ok := Number(*f); ok {
				var sc Scaler
				if x.Scaler != nil {
					sc = x.Scaler(c.Class, c.OBIS)
				}
				v = Scaled(n, sc.Exponent)
				if sc.OK && sc.Unit != "" {
					units[c.Name] = sc.Unit
				}
			}
		} else if LimiterThreshold(c.Class, c.Attr) {
			if n, ok := Number(*f); ok && x.Limiter != nil {
				if sc := x.Limiter(c.OBIS); sc.OK {
					v = Scaled(n, sc.Exponent)
					if sc.Unit != "" {
						units[c.Name] = sc.Unit
					}
				}
			}
		}
		row[c.Name] = v
		if c.Class == ClassData && strings.HasPrefix(c.OBIS, "0.0.96.11.") {
			if n, ok := Number(*f); ok {
				if x.EventName != nil {
					row["eventName"] = x.EventName(int(n))
				} else {
					row["eventName"] = is15959.CodeName(int(n))
				}
				DescribeEvent(row, int(n))
			}
		}
	}
	if len(units) > 0 {
		row["units"] = units
	}
	return row, at
}

// ClockStatus is the clock_status octet of a 12-octet COSEM date-time in
// hex (its last octet), unless it is 0xFF, not specified.
func ClockStatus(s string) (byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 12 || b[11] == 0xFF {
		return 0, false
	}
	return b[11], true
}

// DescribeEvent adds what IS 16444 readers need of an event code to its
// log row: the key applications label it by, its compartment,
// occurrence or restoration, the condition it belongs to and whether we
// class it as a tamper (is15959.EventInfo). Codes no part defines get
// none of these.
func DescribeEvent(row map[string]any, code int) {
	e, ok := is15959.Info(code)
	if !ok {
		return
	}
	row["eventKey"], row["eventCategory"], row["eventKind"], row["eventCondition"] = e.Key, e.Category, e.Kind, e.Condition
	if e.Tamper {
		row["tamper"] = true
	}
}

// ParseCaptureObjects reads a profile's capture_objects (class 7
// attribute 3): {class_id, logical_name, attribute_index, data_index} per
// column; columns are named by the catalogue.
func ParseCaptureObjects(d axdr.DlmsData, profile string) ([]Capture, error) {
	items, _ := d.Value.([]*axdr.DlmsData)
	var cols []Capture
	for _, it := range items {
		f, _ := it.Value.([]*axdr.DlmsData)
		if len(f) < 3 {
			return nil, fmt.Errorf("capture_objects of %s are not in the expected form", profile)
		}
		class, _ := Number(*f[0])
		ln, _ := f[1].Value.(string)
		attr, _ := Number(*f[2])
		obis, err := OBISFromHex(ln)
		if err != nil {
			return nil, err
		}
		cols = append(cols, Capture{Class: uint16(class), OBIS: obis, Attr: int8(attr), Name: NameOf(obis, uint16(class), int8(attr))})
	}
	return cols, nil
}

// ReadCaptureObjects reads a profile's columns.
func ReadCaptureObjects(c gdlms.Client, profile string) ([]Capture, error) {
	var d axdr.DlmsData
	if err := c.GetRequest(gdlms.CreateAttributeDescriptor(ClassProfileGeneric, profile, 3), &d); err != nil {
		return nil, err
	}
	return ParseCaptureObjects(d, profile)
}

// ReadProfileRange reads the entries of a profile's buffer from from to
// to, by its time column tc (selective access by range).
func ReadProfileRange(c gdlms.Client, profile string, tc Capture, from, to time.Time, loc *time.Location) ([]*axdr.DlmsData, error) {
	var d axdr.DlmsData
	if err := c.GetRequestWithSelectiveAccess(gdlms.CreateAttributeDescriptor(ClassProfileGeneric, profile, 2),
		*RangeDescriptor(tc, from, to, loc), &d); err != nil {
		return nil, err
	}
	rows, _ := d.Value.([]*axdr.DlmsData)
	return rows, nil
}

// ReadCapturePeriod reads a profile's capture_period (IEC 62056-6-2:2023
// profile generic, class 7 attribute 4, seconds): 0 when it is
// asynchronous or cannot be read.
func ReadCapturePeriod(c gdlms.Client, profile string) uint32 {
	var d axdr.DlmsData
	if err := c.GetRequest(gdlms.CreateAttributeDescriptor(ClassProfileGeneric, profile, 4), &d); err == nil {
		if n, ok := Number(d); ok && n > 0 {
			return uint32(n)
		}
	}
	return 0
}

// ReadScaler reads the scaler_unit of a register, extended register or
// demand register; a class without one, or a value not in the expected
// form, gives a scaler that is not OK and no error.
func ReadScaler(c gdlms.Client, class uint16, obis string) (Scaler, error) {
	a := ScalerAttr(class)
	if a == 0 {
		return Scaler{}, nil
	}
	var d axdr.DlmsData
	if err := c.GetRequest(gdlms.CreateAttributeDescriptor(class, obis, a), &d); err != nil {
		return Scaler{}, err
	}
	sc, u, err := ScalerUnit(d)
	if err != nil {
		return Scaler{}, nil
	}
	return Scaler{Exponent: sc, Unit: UnitSymbol(u), OK: true}, nil
}

// ScalerProfile reads the scalers a scaler profile's entry holds (IS
// 15959 Part 1 annexes C to G, Part 2 and 3 "scaler profile" clauses):
// the scaler_unit of each register of the profile it belongs to, by the
// register's logical name, from the last entry of rows.
func ScalerProfile(rows []*axdr.DlmsData, cols []Capture) map[string]Scaler {
	out := map[string]Scaler{}
	if len(rows) == 0 {
		return out
	}
	fields, _ := rows[len(rows)-1].Value.([]*axdr.DlmsData)
	for i, f := range fields {
		if i >= len(cols) || f == nil || cols[i].Attr == 0 || cols[i].Attr != ScalerAttr(cols[i].Class) {
			continue
		}
		if sc, u, err := ScalerUnit(*f); err == nil {
			out[cols[i].OBIS] = Scaler{Exponent: sc, Unit: UnitSymbol(u), OK: true}
		}
	}
	return out
}

// ParsePushObjectList reads a push setup's push_object_list (class 40
// attribute 2) as columns named by the catalogue; nil when an entry is not
// in the expected form.
func ParsePushObjectList(d axdr.DlmsData) []is15959.Column {
	items, _ := d.Value.([]*axdr.DlmsData)
	var cols []is15959.Column
	for _, it := range items {
		f, _ := it.Value.([]*axdr.DlmsData)
		if len(f) < 3 {
			return nil
		}
		class, _ := Number(*f[0])
		ln, _ := f[1].Value.(string)
		attr, _ := Number(*f[2])
		obis, err := OBISFromHex(ln)
		if err != nil {
			return nil
		}
		cols = append(cols, is15959.Column{Name: NameOf(obis, uint16(class), int8(attr)), OBIS: obis, Class: uint16(class), Attr: int8(attr)})
	}
	return cols
}
