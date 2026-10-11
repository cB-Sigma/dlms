// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meter

// The meter's values: registers, nameplate, profiles that agree with the
// registers, event logs and push lists, written into a Store.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/is15959"
)

// Store holds a meter's attribute values and profile buffers. Its methods
// are called by one goroutine at a time (a caller holding the store's
// lock).
type Store interface {
	Value(class uint16, obis string, attr int8) (axdr.DlmsData, bool)
	SetValue(class uint16, obis string, attr int8, v *axdr.DlmsData)
	// Rows is a profile's capture objects and buffer; ok is false for a
	// profile the store does not hold.
	Rows(obis string) (cols []is15959.Column, rows [][]*axdr.DlmsData, ok bool)
	SetRows(obis string, cols []is15959.Column, rows [][]*axdr.DlmsData)
}

// Memory is a Store in maps, safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	values   map[string]axdr.DlmsData
	order    []string
	profiles map[string]*memProfile
	porder   []string
}

type memProfile struct {
	cols []is15959.Column
	rows [][]*axdr.DlmsData
}

func vkey(class uint16, obis string, attr int8) string {
	return fmt.Sprintf("%d/%s/%d", class, obis, attr)
}

// Value returns an attribute's value.
func (m *Memory) Value(class uint16, obis string, attr int8) (axdr.DlmsData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[vkey(class, obis, attr)]
	return v, ok
}

// SetValue stores an attribute's value.
func (m *Memory) SetValue(class uint16, obis string, attr int8, v *axdr.DlmsData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[string]axdr.DlmsData{}
	}
	k := vkey(class, obis, attr)
	if _, ok := m.values[k]; !ok {
		m.order = append(m.order, k)
	}
	m.values[k] = *v
}

// Rows returns a profile's capture objects and buffer.
func (m *Memory) Rows(obis string) ([]is15959.Column, [][]*axdr.DlmsData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[obis]
	if !ok {
		return nil, nil, false
	}
	return p.cols, p.rows, true
}

// SetRows stores a profile.
func (m *Memory) SetRows(obis string, cols []is15959.Column, rows [][]*axdr.DlmsData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profiles == nil {
		m.profiles = map[string]*memProfile{}
	}
	if _, ok := m.profiles[obis]; !ok {
		m.porder = append(m.porder, obis)
	}
	m.profiles[obis] = &memProfile{cols: cols, rows: rows}
}

// Attr is one stored attribute.
type Attr struct {
	Class uint16
	OBIS  string
	Attr  int8
	Value axdr.DlmsData
}

// Attrs lists the stored attributes in the order they were first set.
func (m *Memory) Attrs() []Attr {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Attr, 0, len(m.order))
	for _, k := range m.order {
		parts := strings.Split(k, "/")
		c, _ := strconv.Atoi(parts[0])
		a, _ := strconv.Atoi(parts[2])
		out = append(out, Attr{Class: uint16(c), OBIS: parts[1], Attr: int8(a), Value: m.values[k]})
	}
	return out
}

// Profiles lists the stored profiles' logical names in the order they
// were first set.
func (m *Memory) Profiles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.porder...)
}

// DateTime is t in loc as a COSEM date-time octet string (deviation not
// specified, the daylight saving bit of clock_status when it applies).
func DateTime(t time.Time, loc *time.Location) *axdr.DlmsData {
	return axdr.CreateAxdrOctetString(hex.EncodeToString(dateTime(t, loc)))
}

func dateTime(t time.Time, loc *time.Location) []byte {
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

// unitCodes maps unit symbols the catalogue uses to the COSEM unit
// enumeration and the scaler the meter reports with.
var unitCodes = map[string]struct {
	code   uint8
	scaler int8
}{
	"V": {35, -2}, "A": {33, -3}, "Hz": {44, -2}, "W": {27, 0}, "kW": {27, 0}, "VA": {28, 0}, "kVA": {28, 0},
	"var": {29, 0}, "kvar": {29, 0}, "Wh": {30, 0}, "kWh": {30, 0}, "VAh": {31, 0}, "kVAh": {31, 0},
	"varh": {32, 0}, "kvarh": {32, 0}, "min": {6, 0}, "s": {7, 0}, "h": {5, 0}, "d": {4, 0}, "%": {56, 0}, "": {255, -3},
}

// OBISHex is a logical name as the hex of its six octets.
func OBISHex(obis string) string {
	var b []byte
	for _, p := range strings.FieldsFunc(obis, func(r rune) bool { return r == '.' }) {
		var n int
		_, _ = fmt.Sscanf(p, "%d", &n)
		b = append(b, byte(n))
	}
	return hex.EncodeToString(b)
}

// Populate writes every object, profile and event log of the profile into
// st, with o's nameplate (o is completed with Defaults).
func Populate(st Store, spec *is15959.Spec, o Options) {
	o = o.Defaults()
	loc := o.Location
	n := uint32(1)
	value := func(ob is15959.Object) *axdr.DlmsData {
		n++
		switch ob.OBIS {
		case "0.0.96.1.0.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Serial)))
		case "0.0.96.1.2.255", "0.0.42.0.0.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.DeviceID())))
		case "0.0.96.1.1.255":
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Model)))
		// Nameplate values a real meter carries, instead of the placeholder
		// a type gives ("V7" for the category, 63 for the year).
		case "0.0.96.1.4.255": // year of manufacture
			return axdr.CreateAxdrLongUnsigned(uint16(o.nameplateYear()))
		case "1.0.0.2.0.255": // firmware version
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Firmware)))
		case "0.0.94.91.11.255": // meter category
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Category)))
		case "0.0.94.91.12.255": // current rating
			return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(o.Rating)))
		case is15959.EventStatusWord:
			return axdr.CreateAxdrBitString(strings.Repeat("0", 128))
		}
		if v := plausible(ob); v != nil {
			return v
		}
		return sample(ob.Type, n, o.Now, loc)
	}
	for _, ob := range spec.Objects {
		switch ob.Class {
		case is15959.ClassProfileGeneric:
			continue
		case is15959.ClassRegister, is15959.ClassExtendedRegister, is15959.ClassDemandRegister:
			if ob.Attr == 2 {
				u := unitCodes[ob.Unit]
				v := value(ob)
				st.SetValue(ob.Class, ob.OBIS, 2, v)
				st.SetValue(ob.Class, ob.OBIS, is15959.ScalerAttr(ob.Class), axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(u.scaler), axdr.CreateAxdrEnum(u.code)}))
				switch ob.Class {
				case is15959.ClassExtendedRegister:
					st.SetValue(ob.Class, ob.OBIS, 5, DateTime(o.Now.Add(-time.Hour), loc))
				case is15959.ClassDemandRegister: // last_average_value, capture_time
					st.SetValue(ob.Class, ob.OBIS, 3, v)
					st.SetValue(ob.Class, ob.OBIS, 6, DateTime(o.Now.Add(-time.Hour), loc))
				}
				continue
			}
		case is15959.ClassClock:
			if ob.Attr == 2 {
				continue // the clock runs
			}
		}
		if ob.Class == is15959.ClassPushSetup && ob.Attr == 2 {
			if ps := spec.PushSetup(ob.OBIS); ps != nil {
				st.SetValue(ob.Class, ob.OBIS, 2, PushList(ps.Capture))
			} else {
				st.SetValue(ob.Class, ob.OBIS, 2, axdr.CreateAxdrArray(nil))
			}
			continue
		}
		st.SetValue(ob.Class, ob.OBIS, ob.Attr, value(ob))
	}
	for _, p := range spec.Profiles {
		st.SetRows(p.OBIS, p.Capture, buildRows(st, p, o.Now, o.Rows, loc))
		if !scalerBuffer(p) {
			st.SetValue(7, p.OBIS, 4, axdr.CreateAxdrDoubleLongUnsigned(uint32(p.Period/time.Second)))
		}
	}
	for _, l := range spec.Events {
		eventLog(st, l, o)
	}
	// Disconnect control: connected (1), control_mode 4 (remote
	// disconnection and direct remote reconnection, local disconnection).
	st.SetValue(is15959.ClassDisconnect, is15959.DisconnectControl, 2, axdr.CreateAxdrBoolean(true))
	st.SetValue(is15959.ClassDisconnect, is15959.DisconnectControl, 3, axdr.CreateAxdrEnum(1))
	st.SetValue(is15959.ClassDisconnect, is15959.DisconnectControl, 4, axdr.CreateAxdrEnum(4))
	// The load limiter watches the active power register: its thresholds
	// are in that register's units (monitored_value, attribute 2).
	if spec.Object("0.0.17.0.0.255", 3) != nil && spec.Object("1.0.1.7.0.255", 2) != nil {
		st.SetValue(is15959.ClassLimiter, "0.0.17.0.0.255", 2, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(is15959.ClassRegister), axdr.CreateAxdrOctetString(OBISHex("1.0.1.7.0.255")), axdr.CreateAxdrInteger(2)}))
	}
	it := ImageTransferOBIS(spec)
	st.SetValue(is15959.ClassImageTransfer, it, 2, axdr.CreateAxdrDoubleLongUnsigned(64))
	st.SetValue(is15959.ClassImageTransfer, it, 5, axdr.CreateAxdrBoolean(true))
	st.SetValue(is15959.ClassImageTransfer, it, 6, axdr.CreateAxdrEnum(0))
}

// PushList is a push_object_list (class 40 attribute 2) of capture
// columns.
func PushList(cols []is15959.Column) *axdr.DlmsData {
	var items []*axdr.DlmsData
	for _, c := range cols {
		attr := c.Attr
		if attr == 0 {
			attr = 2
		}
		items = append(items, axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrLongUnsigned(c.Class), axdr.CreateAxdrOctetString(OBISHex(c.OBIS)),
			axdr.CreateAxdrInteger(attr), axdr.CreateAxdrLongUnsigned(0),
		}))
	}
	return axdr.CreateAxdrArray(items)
}

// ImageTransferOBIS is the profile's image transfer object.
func ImageTransferOBIS(sp *is15959.Spec) string {
	for _, mt := range sp.Methods {
		if mt.Class == is15959.ClassImageTransfer {
			return mt.OBIS
		}
	}
	return "0.0.44.0.0.255"
}

// sample is a value of an A-XDR type.
func sample(typ string, n uint32, now time.Time, loc *time.Location) *axdr.DlmsData {
	switch typ {
	case "boolean":
		return axdr.CreateAxdrBoolean(true)
	case "integer":
		return axdr.CreateAxdrInteger(int8(n % 100))
	case "long":
		return axdr.CreateAxdrLong(int16(n))
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(n) * 10)
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(n))
	case "enum":
		return axdr.CreateAxdrEnum(1)
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(n * 7))
	case "double-long-unsigned", "":
		return axdr.CreateAxdrDoubleLongUnsigned(n * 1000)
	case "long64-unsigned":
		return axdr.CreateAxdrLong64Unsigned(uint64(n) * 1000)
	case "date-time":
		return DateTime(now, loc)
	case "octet-string":
		return axdr.CreateAxdrOctetString(hex.EncodeToString([]byte(fmt.Sprintf("V%d", n))))
	case "visible-string":
		return axdr.CreateAxdrVisibleString(fmt.Sprintf("V%d", n))
	case "bit-string":
		return axdr.CreateAxdrBitString(strings.Repeat("0", 16))
	case "float32":
		return axdr.CreateAxdrFloat32(float32(n))
	case "array":
		return axdr.CreateAxdrArray(nil)
	case "structure":
		return axdr.CreateAxdrStructure(nil)
	}
	return axdr.CreateAxdrDoubleLongUnsigned(n)
}

// Cell is the value a capture column holds in an entry captured at at
// (entry i): the clock for time columns, the attribute's present value
// (counters advanced by i), else a placeholder.
func Cell(st Store, c is15959.Column, at time.Time, i int, loc *time.Location) *axdr.DlmsData {
	if c.Class == is15959.ClassClock || c.OBIS == "0.0.0.1.2.255" {
		return DateTime(at, loc)
	}
	if v, ok := st.Value(c.Class, c.OBIS, c.Attr); ok {
		if f, ok := v.Value.(uint32); ok {
			return axdr.CreateAxdrDoubleLongUnsigned(f + uint32(i))
		}
		if f, ok := v.Value.(uint16); ok {
			return axdr.CreateAxdrLongUnsigned(f + uint16(i))
		}
		cp := v
		return &cp
	}
	if is15959.IsTimeAttr(c.Class, c.Attr) {
		return DateTime(at, loc)
	}
	return axdr.CreateAxdrDoubleLongUnsigned(uint32(100 + i))
}

// Row is an entry of capture columns captured at at (entry i).
func Row(st Store, cols []is15959.Column, at time.Time, i int, loc *time.Location) []*axdr.DlmsData {
	row := make([]*axdr.DlmsData, len(cols))
	for j, c := range cols {
		row[j] = Cell(st, c, at, i, loc)
	}
	return row
}

// buildRows is a profile's buffer at now with rows entries.
func buildRows(st Store, p is15959.Profile, now time.Time, rows int, loc *time.Location) [][]*axdr.DlmsData {
	if scalerBuffer(p) {
		// A scaler profile: one entry holding each column's scaler_unit.
		var row []*axdr.DlmsData
		for _, c := range p.Capture {
			if v, ok := st.Value(c.Class, c.OBIS, c.Attr); ok {
				cp := v
				row = append(row, &cp)
			} else {
				row = append(row, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrInteger(0), axdr.CreateAxdrEnum(255)}))
			}
		}
		return [][]*axdr.DlmsData{row}
	}
	step := p.Period
	if step == 0 {
		step = 24 * time.Hour
	}
	end := now.Truncate(step)
	var out [][]*axdr.DlmsData
	for i := rows - 1; i >= 0; i-- {
		at := end.Add(-time.Duration(i) * step)
		row := make([]*axdr.DlmsData, len(p.Capture))
		for j, c := range p.Capture {
			if p.Period > 0 {
				if v := periodCell(st, c, at, now, p.Period, rows-i); v != nil {
					row[j] = v
					continue
				}
			}
			row[j] = Cell(st, c, at, rows-i, loc)
		}
		out = append(out, row)
	}
	if p.Period > 0 {
		keepLastAverages(st, p, out)
	}
	return out
}

// scalerBuffer reports whether a profile is a scaler profile.
func scalerBuffer(p is15959.Profile) bool {
	if !strings.HasPrefix(p.OBIS, "1.0.94.91.") || p.Period != 0 {
		return false
	}
	for _, c := range p.Capture {
		if c.Attr == 0 || c.Attr != is15959.ScalerAttr(c.Class) {
			return false
		}
	}
	return len(p.Capture) > 0
}

// IsScalerProfile reports whether a profile holds scaler_units only.
func IsScalerProfile(p is15959.Profile) bool { return scalerBuffer(p) }

// eventLog fills an event log with one entry per event code (up to
// o.Rows), the code in the event code column.
func eventLog(st Store, l is15959.EventLog, o Options) {
	var rows [][]*axdr.DlmsData
	for i, e := range l.Codes {
		if i >= o.Rows {
			break
		}
		at := o.Now.Add(-time.Duration(len(l.Codes)-i) * time.Hour).Truncate(time.Second)
		rows = append(rows, eventRow(st, l, e.Code, at, i, o.Location))
		st.SetValue(1, l.CodeOBIS, 2, axdr.CreateAxdrLongUnsigned(uint16(e.Code)))
	}
	st.SetRows(l.OBIS, l.Capture, rows)
}

func eventRow(st Store, l is15959.EventLog, code int, at time.Time, i int, loc *time.Location) []*axdr.DlmsData {
	row := make([]*axdr.DlmsData, len(l.Capture))
	for j, c := range l.Capture {
		if c.OBIS == l.CodeOBIS || strings.HasPrefix(c.OBIS, "0.0.96.11.") {
			row[j] = axdr.CreateAxdrLongUnsigned(uint16(code))
			continue
		}
		row[j] = Cell(st, c, at, i, loc)
	}
	return row
}

// RaiseEvent logs an event as a meter does when the condition occurs or
// clears: an entry in the event log whose codes include it, captured at
// at, and the log's event code object set to it. False when no log of the
// profile has the code.
func RaiseEvent(st Store, spec *is15959.Spec, code int, at time.Time, loc *time.Location) bool {
	for _, l := range spec.Events {
		has := false
		for _, e := range l.Codes {
			has = has || e.Code == code
		}
		cols, rows, ok := st.Rows(l.OBIS)
		if !has || !ok {
			continue
		}
		at = at.Truncate(time.Second)
		rows = append(rows, eventRow(st, l, code, at, len(rows), loc))
		st.SetRows(l.OBIS, cols, rows)
		st.SetValue(1, l.CodeOBIS, 2, axdr.CreateAxdrLongUnsigned(uint16(code)))
		return true
	}
	return false
}

// Recapture rebuilds the periodic load profiles and the scaler profiles
// from the present register values, as if the load had been steady, the
// newest entry the last whole period before now.
func Recapture(st Store, spec *is15959.Spec, rows int, now time.Time, loc *time.Location) {
	if rows == 0 {
		rows = 4
	}
	// Scaler profiles first: they hold the registers' scaler_units the
	// profiles below are converted with.
	for _, p := range spec.Profiles {
		if scalerBuffer(p) {
			st.SetRows(p.OBIS, p.Capture, buildRows(st, p, now, rows, loc))
		}
	}
	for _, p := range spec.Profiles {
		if p.Period > 0 {
			st.SetRows(p.OBIS, p.Capture, buildRows(st, p, now, rows, loc))
		}
	}
}

// obisCD is an OBIS code's value groups C (quantity) and D (processing).
func obisCD(obis string) (c, d int, ok bool) {
	f := strings.Split(obis, ".")
	if len(f) != 6 || f[0] != "1" {
		return 0, 0, false
	}
	c, err1 := strconv.Atoi(f[2])
	d, err2 := strconv.Atoi(f[3])
	return c, d, err1 == nil && err2 == nil
}

func withD(obis string, d int) string {
	f := strings.Split(obis, ".")
	f[3] = strconv.Itoa(d)
	return strings.Join(f, ".")
}

func scalerOf(st Store, obis string) int {
	v, ok := st.Value(is15959.ClassRegister, obis, is15959.ScalerAttr(is15959.ClassRegister))
	if !ok {
		return 0
	}
	f, _ := v.Value.([]*axdr.DlmsData)
	if len(f) == 0 {
		return 0
	}
	s, _ := f[0].Value.(int8)
	return int(s)
}

func quantity(st Store, obis string) (float64, bool) {
	v, ok := st.Value(is15959.ClassRegister, obis, 2)
	if !ok {
		return 0, false
	}
	n, ok := numeric(v)
	if !ok {
		return 0, false
	}
	return n * math.Pow10(scalerOf(st, obis)), true
}

// power is the measured power that feeds an energy quantity C (active
// import 1 from 1.7, apparent import 9 from 9.7, net 16 from 1.7); 0 for
// export and reactive energy.
func power(st Store, c int) float64 {
	src := map[int]string{1: "1.0.1.7.0.255", 9: "1.0.9.7.0.255", 16: "1.0.1.7.0.255"}[c]
	if src == "" {
		return 0
	}
	p, _ := quantity(st, src)
	return math.Max(p, 0)
}

// periodCell is the value of a register column of a periodic profile at
// entry time at (entry k), derived from the instantaneous registers; nil
// for columns it does not derive.
func periodCell(st Store, col is15959.Column, at, now time.Time, period time.Duration, k int) *axdr.DlmsData {
	if col.Class != is15959.ClassRegister || col.Attr != 2 {
		return nil
	}
	c, d, ok := obisCD(col.OBIS)
	if !ok {
		return nil
	}
	wave := math.Sin(float64(k) * 0.7)
	var q float64
	switch d {
	case 27: // the average over the period of what C.7 measures
		inst, ok := quantity(st, withD(col.OBIS, 7))
		if !ok {
			return nil
		}
		amp := 0.08 // currents and powers move with the load
		switch c {
		case 12, 32, 52, 72, 14: // voltages and frequency hardly do
			amp = 0.003
		}
		q = inst * (1 + amp*wave)
	case 29: // the energy of one period
		q = power(st, c) * period.Hours() * (1 + 0.08*wave)
	case 8: // cumulative energy at the entry's time
		reg, ok := quantity(st, col.OBIS)
		if !ok {
			return nil
		}
		q = math.Max(reg-power(st, c)*now.Sub(at).Hours(), 0)
	default:
		return nil
	}
	return registerValue(st, col.OBIS, q)
}

func registerValue(st Store, obis string, q float64) *axdr.DlmsData {
	raw := math.Round(q / math.Pow10(scalerOf(st, obis)))
	clamp := func(lo, hi float64) float64 { return math.Min(math.Max(raw, lo), hi) }
	tmpl, ok := st.Value(is15959.ClassRegister, obis, 2)
	if !ok {
		return axdr.CreateAxdrDoubleLongUnsigned(uint32(clamp(0, math.MaxUint32)))
	}
	switch tmpl.Value.(type) {
	case uint8:
		return axdr.CreateAxdrUnsigned(uint8(clamp(0, math.MaxUint8)))
	case int8:
		return axdr.CreateAxdrInteger(int8(clamp(math.MinInt8, math.MaxInt8)))
	case uint16:
		return axdr.CreateAxdrLongUnsigned(uint16(clamp(0, math.MaxUint16)))
	case int16:
		return axdr.CreateAxdrLong(int16(clamp(math.MinInt16, math.MaxInt16)))
	case int32:
		return axdr.CreateAxdrDoubleLong(int32(clamp(math.MinInt32, math.MaxInt32)))
	case uint64:
		return axdr.CreateAxdrLong64Unsigned(uint64(clamp(0, math.MaxUint32)))
	case int64:
		return axdr.CreateAxdrLong64(int64(clamp(math.MinInt32, math.MaxInt32)))
	}
	return axdr.CreateAxdrDoubleLongUnsigned(uint32(clamp(0, math.MaxUint32)))
}

// keepLastAverages sets each average register (D = 27) a profile captures
// to its newest entry, as a meter's register holds the last period's
// average.
func keepLastAverages(st Store, p is15959.Profile, rows [][]*axdr.DlmsData) {
	if len(rows) == 0 {
		return
	}
	last := rows[len(rows)-1]
	for j, c := range p.Capture {
		if _, d, ok := obisCD(c.OBIS); ok && d == 27 && c.Class == is15959.ClassRegister && c.Attr == 2 && last[j] != nil {
			st.SetValue(c.Class, c.OBIS, 2, last[j])
		}
	}
}

func numeric(d axdr.DlmsData) (float64, bool) {
	switch v := d.Value.(type) {
	case uint8:
		return float64(v), true
	case int8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case int16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case int32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// typed is v as a value of an A-XDR numeric type, clamped to its range;
// nil for a type that is not a number.
func typed(typ string, v float64) *axdr.DlmsData {
	c := func(lo, hi float64) float64 { return math.Min(math.Max(math.Round(v), lo), hi) }
	switch typ {
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(c(0, math.MaxUint8)))
	case "integer":
		return axdr.CreateAxdrInteger(int8(c(math.MinInt8, math.MaxInt8)))
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(c(0, math.MaxUint16)))
	case "long":
		return axdr.CreateAxdrLong(int16(c(math.MinInt16, math.MaxInt16)))
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(c(math.MinInt32, math.MaxInt32)))
	case "double-long-unsigned", "":
		return axdr.CreateAxdrDoubleLongUnsigned(uint32(c(0, math.MaxUint32)))
	case "long64":
		return axdr.CreateAxdrLong64(int64(c(math.MinInt32, math.MaxInt32)))
	case "long64-unsigned":
		return axdr.CreateAxdrLong64Unsigned(uint64(c(0, math.MaxUint32)))
	case "float32":
		return axdr.CreateAxdrFloat32(float32(v))
	}
	return nil
}

// plausibleValues are register values a household meter of a 10-60 A
// rating could show: demand in W and energy in Wh (scaler 0), durations in
// minutes, counts. Tariff registers share the total between them.
var plausibleValues = map[string]uint32{
	"maxDemandActive":            4200, // W, the month's highest demand
	"maxDemandApparent":          4500, // VA
	"billingCount":               12,
	"powerOnDuration":            41760,  // min, this billing period (29 days)
	"powerOnDurationTotal":       786240, // min, about a year and a half
	"powerFailureDuration":       380,    // min
	"activeEnergyImportPeriod":   182000, // Wh this billing period
	"apparentEnergyImportPeriod": 196000,
	"tamperCount":                2,
	"programmingCount":           3,
	"loadLimit":                  6000, // W, the limiter's threshold for the sanctioned load
	"powerFailures":              17,
}

// instantaneous are readings of a household load on a 230 V, 50 Hz
// supply, by value group C of an instantaneous register (D = 7), in the
// units and scalers of unitCodes: voltage 0.01 V, current 0.001 A,
// frequency 0.01 Hz, power factor 0.001, powers in W, VA and var.
var instantaneous = map[int]float64{
	12: 23010, 32: 23050, 52: 22980, 72: 23120, // V
	11: 5200, 31: 5200, 51: 4800, 71: 5600, 91: 300, // mA
	13: 980, 33: 985, 53: 975, 73: 990, // power factor
	14: 5000,                            // Hz
	1:  1150, 21: 390, 41: 360, 61: 400, // W
	9: 1180, 29: 400, 49: 370, 69: 410, // VA
	3: 200, 23: 70, 43: 60, 63: 70, // var
}

func plausible(ob is15959.Object) *axdr.DlmsData {
	if ob.Class == is15959.ClassRegister && (ob.Attr == 2 || ob.Attr == 0) {
		if c, d, ok := obisCD(ob.OBIS); ok && d == 7 {
			if v, ok := instantaneous[c]; ok {
				return typed(ob.Type, v)
			}
		}
	}
	name := ob.Name
	tariff := 0
	if i := strings.LastIndex(name, "T"); i > 0 && i == len(name)-2 && name[i+1] >= '1' && name[i+1] <= '8' {
		tariff = int(name[i+1] - '0')
		name = name[:i]
	}
	v, ok := plausibleValues[name]
	if !ok {
		return nil
	}
	if tariff > 0 {
		// A tariff zone's share: its demand a little lower, its energy a part of the total.
		if strings.HasPrefix(name, "maxDemand") {
			v -= uint32(tariff) * 250
		} else {
			v /= 4
		}
	}
	switch ob.Type {
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(min(v, 65535)))
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(min(v, 255)))
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(v))
	case "long64-unsigned":
		return axdr.CreateAxdrLong64Unsigned(uint64(v))
	case "double-long-unsigned", "":
		return axdr.CreateAxdrDoubleLongUnsigned(v)
	}
	return nil
}
