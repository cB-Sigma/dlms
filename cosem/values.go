package cosem

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Value converts A-XDR data to a JSON-friendly Go value. Octet strings are
// hexadecimal text, except 12-byte ones when asDateTime is set.
func Value(d axdr.DlmsData, loc *time.Location, asDateTime bool) any {
	switch d.Tag {
	case axdr.TagNull:
		return nil
	case axdr.TagArray, axdr.TagStructure, axdr.TagCompactArray:
		items, _ := d.Value.([]*axdr.DlmsData)
		out := make([]any, len(items))
		for i, x := range items {
			if x != nil {
				out[i] = Value(*x, loc, false)
			}
		}
		return out
	case axdr.TagOctetString:
		s, _ := d.Value.(string)
		if asDateTime {
			if t, ok := DateTime(s, loc); ok {
				return t.UTC().Format(time.RFC3339)
			}
		}
		return s
	case axdr.TagDateTime:
		if t, ok := d.Value.(time.Time); ok {
			return t.UTC().Format(time.RFC3339)
		}
	case axdr.TagFloat32, axdr.TagFloatingPoint:
		if f, ok := d.Value.(float32); ok {
			return float64(f)
		}
	}
	if f, ok := Number(d); ok {
		return f
	}
	return d.Value
}

// Readable is Value for an object's own reading: an octet string whose
// bytes are all printable ASCII is text (IS 15959 keeps the serial number,
// manufacturer name, device ID and firmware version in octet strings), a
// 12-byte one that is a valid COSEM date-time (the capture time of a
// maximum demand register) is a time, and any other stays hexadecimal
// (keys, system titles, bit fields). SigmaM2M finding F-2600 (PROVENANCE.md).
func Readable(d axdr.DlmsData, loc *time.Location, asDateTime bool) any {
	v := Value(d, loc, asDateTime)
	if d.Tag != axdr.TagOctetString {
		return v
	}
	s, ok := v.(string)
	if !ok {
		return v
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return v
	}
	if printable(b) {
		return string(b)
	}
	// Twelve bytes are also a key's or a counter's size: a date-time needs
	// a plausible year, a weekday 1 to 7 (or not specified) and hundredths
	// up to 99 (or not specified).
	if len(b) == 12 && (b[4] == 0xFF || (b[4] >= 1 && b[4] <= 7)) && (b[8] == 0xFF || b[8] <= 99) {
		if t, ok := DateTime(s, loc); ok && t.Year() >= 1990 && t.Year() <= 2100 {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return v
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// Number returns a numeric A-XDR value as float64.
func Number(d axdr.DlmsData) (float64, bool) {
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

// DateTime decodes a COSEM date-time (12-byte octet string, as hex). An
// unspecified deviation (0x8000) means the meter's local time in loc; a
// given deviation is minutes of UTC minus local time.
func DateTime(hexs string, loc *time.Location) (time.Time, bool) {
	b, err := hex.DecodeString(hexs)
	if err != nil || len(b) != 12 {
		return time.Time{}, false
	}
	year := int(binary.BigEndian.Uint16(b[0:2]))
	month, day, hour, minute, sec, hund := int(b[2]), int(b[3]), int(b[5]), int(b[6]), int(b[7]), int(b[8])
	if year == 0xFFFF || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 59 {
		return time.Time{}, false
	}
	if hund == 0xFF {
		hund = 0
	}
	dev := binary.BigEndian.Uint16(b[9:11])
	l := loc
	if dev != 0x8000 {
		l = time.FixedZone("", -int(int16(dev))*60)
	}
	return time.Date(year, time.Month(month), day, hour, minute, sec, hund*1e7, l), true
}

// EncodeDateTime is the inverse of DateTime for loc: a COSEM date-time
// (IEC 62056-6-2:2023 4.1.6.1) in local time with the deviation not
// specified, hundredths 0, and clock_status bit 7 (daylight saving
// active) set when loc is on daylight saving time at t.
func EncodeDateTime(t time.Time, loc *time.Location) []byte {
	t = t.In(loc)
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, uint16(t.Year()))
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	b[2], b[3], b[4], b[5], b[6], b[7], b[8] = byte(t.Month()), byte(t.Day()), byte(wd), byte(t.Hour()), byte(t.Minute()), byte(t.Second()), 0
	binary.BigEndian.PutUint16(b[9:], 0x8000)
	if t.IsDST() {
		b[11] = 0x80
	}
	return b
}

// ScalerUnit decodes a register's scaler_unit attribute.
func ScalerUnit(d axdr.DlmsData) (int8, uint8, error) {
	items, ok := d.Value.([]*axdr.DlmsData)
	if d.Tag != axdr.TagStructure || !ok || len(items) != 2 || items[0] == nil || items[1] == nil {
		return 0, 0, fmt.Errorf("scaler_unit is not a structure of two values")
	}
	s, ok1 := Number(*items[0])
	u, ok2 := Number(*items[1])
	if !ok1 || !ok2 {
		return 0, 0, fmt.Errorf("scaler_unit values are not numbers")
	}
	return int8(s), uint8(u), nil
}

// Scaled applies 10^scaler to a numeric value, keeping it tidy.
func Scaled(v float64, scaler int8) float64 {
	if scaler == 0 {
		return v
	}
	r := v * math.Pow10(int(scaler))
	// Round away binary noise such as 230.50000000000003.
	if scaler < 0 {
		p := math.Pow10(int(-scaler))
		r = math.Round(r*p) / p
	}
	return r
}

// TypedData builds A-XDR data for a SET from a type name and a JSON value.
func TypedData(typ string, v any) (*axdr.DlmsData, error) {
	num := func() (float64, error) {
		switch x := v.(type) {
		case float64:
			return x, nil
		case string:
			return strconv.ParseFloat(x, 64)
		}
		return 0, fmt.Errorf("%v is not a number", v)
	}
	switch typ {
	case "boolean":
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%v is not true or false", v)
		}
		return axdr.CreateAxdrBoolean(b), nil
	case "octet-string":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("an octet-string value is hexadecimal text")
		}
		s = strings.ReplaceAll(s, " ", "")
		if _, err := hex.DecodeString(s); err != nil {
			return nil, fmt.Errorf("%q is not hexadecimal", s)
		}
		return axdr.CreateAxdrOctetString(s), nil
	case "visible-string":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not text", v)
		}
		return axdr.CreateAxdrVisibleString(s), nil
	}
	f, err := num()
	if err != nil {
		return nil, err
	}
	in := func(lo, hi float64) error {
		if f < lo || f > hi || f != math.Trunc(f) {
			return fmt.Errorf("%v is not a whole number in %s's range", v, typ)
		}
		return nil
	}
	switch typ {
	case "integer":
		if err := in(math.MinInt8, math.MaxInt8); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrInteger(int8(f)), nil
	case "long":
		if err := in(math.MinInt16, math.MaxInt16); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrLong(int16(f)), nil
	case "double-long":
		if err := in(math.MinInt32, math.MaxInt32); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrDoubleLong(int32(f)), nil
	case "unsigned":
		if err := in(0, math.MaxUint8); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrUnsigned(uint8(f)), nil
	case "enum":
		if err := in(0, math.MaxUint8); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrEnum(uint8(f)), nil
	case "long-unsigned":
		if err := in(0, math.MaxUint16); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrLongUnsigned(uint16(f)), nil
	case "double-long-unsigned":
		if err := in(0, math.MaxUint32); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrDoubleLongUnsigned(uint32(f)), nil
	case "float32":
		return axdr.CreateAxdrFloat32(float32(f)), nil
	case "float64":
		return axdr.CreateAxdrFloat64(f), nil
	}
	return nil, fmt.Errorf("type %q is not one of boolean, integer, long, double-long, unsigned, enum, long-unsigned, double-long-unsigned, float32, float64, octet-string, visible-string", typ)
}
