// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// fakeResolver answers from a map, counting reads.
type fakeResolver struct {
	vals map[CaptureObject]*axdr.DlmsData
	objs map[string]Object
}

func (f *fakeResolver) Resolve(class uint16, ln string, attr int8) (*axdr.DlmsData, error) {
	if o, ok := f.objs[ln]; ok && o.ClassID() == class {
		return o.Get(attr, nil)
	}
	v, ok := f.vals[CaptureObject{Class: class, LN: ln, Attr: attr}]
	if !ok {
		return nil, ObjectUndefined
	}
	return v, nil
}

func hexOf(t *testing.T, d *axdr.DlmsData) []byte {
	t.Helper()
	b, err := octetsOf(d)
	if err != nil {
		t.Fatalf("not an octet string: %+v", d)
	}
	return b
}

func wantResult(t *testing.T, err error, want Result) {
	t.Helper()
	if ResultOf(err) != want {
		t.Fatalf("result %v, want %v", err, want)
	}
}

func items(t *testing.T, d *axdr.DlmsData) []*axdr.DlmsData {
	t.Helper()
	it, ok := d.Value.([]*axdr.DlmsData)
	if !ok {
		t.Fatalf("not a list: %+v", d)
	}
	return it
}

// allObjects is one instance of every typed object.
func allObjects() []Object {
	ln := "0.0.1.0.0.255"
	return []Object{
		&Data{LN: ln}, &Register{LN: ln}, &ExtendedRegister{LN: ln}, &DemandRegister{LN: ln},
		&RegisterActivation{LN: ln}, &ProfileGeneric{LN: ln}, &Clock{LN: ln}, &ScriptTable{LN: ln},
		&Schedule{LN: ln}, &SpecialDaysTable{LN: ln}, &AssociationSN{LN: ln}, &AssociationLN{LN: ln},
		&SAPAssignment{LN: ln}, &ImageTransfer{LN: ln}, &IECLocalPortSetup{LN: ln}, &ActivityCalendar{LN: ln},
		&RegisterMonitor{LN: ln}, &SingleActionSchedule{LN: ln}, &IECHDLCSetup{LN: ln}, &PushSetup{LN: ln},
		&TCPUDPSetup{LN: ln}, &IPv4Setup{LN: ln}, &SecuritySetup{LN: ln}, &DisconnectControl{LN: ln},
		&Limiter{LN: ln}, &Generic{Class: 43, LN: ln},
	}
}

// Covers: SIG-IPE-6466
func TestEveryObjectMatchesCatalogue(t *testing.T) {
	for _, o := range allObjects() {
		c, ok := Lookup(o.ClassID())
		if !ok {
			t.Errorf("class %d not in the catalogue", o.ClassID())
			continue
		}
		if c.Version != o.Version() {
			t.Errorf("%s: version %d, catalogue %d", c.Name, o.Version(), c.Version)
		}
		for _, a := range c.Attributes {
			d, err := o.Get(a.Index, nil)
			if c.ID == 15 && a.Index == 7 {
				wantResult(t, err, ReadWriteDenied)
				continue
			}
			if err != nil {
				t.Errorf("%s: get %s: %v", c.Name, a.Name, err)
				continue
			}
			if d == nil {
				t.Errorf("%s: get %s gave nil", c.Name, a.Name)
				continue
			}
			if d.Tag != axdr.TagNull {
				if _, err := d.Encode(); err != nil {
					t.Errorf("%s: %s does not encode: %v", c.Name, a.Name, err)
				}
			}
		}
		if d, _ := o.Get(1, nil); !bytes.Equal(hexOf(t, d), []byte{0, 0, 1, 0, 0, 255}) {
			t.Errorf("%s: logical name % x", c.Name, hexOf(t, d))
		}
		if _, err := o.Get(int8(len(c.Attributes)+1), nil); ResultOf(err) != ObjectUndefined {
			t.Errorf("%s: unknown attribute gave %v", c.Name, err)
		}
		if err := o.Set(1, octetData([]byte{1, 1, 1, 1, 1, 1}), nil); ResultOf(err) != ReadWriteDenied {
			t.Errorf("%s: set of logical name gave %v", c.Name, err)
		}
		if _, err := o.Action(99, nil); ResultOf(err) != ObjectUndefined {
			t.Errorf("%s: unknown method gave %v", c.Name, err)
		}
		if o.LogicalName() != "0.0.1.0.0.255" {
			t.Errorf("%s: LogicalName %q", c.Name, o.LogicalName())
		}
	}
}

// Covers: SIG-IPE-6466
func TestRegisterAndData(t *testing.T) {
	r := &Register{LN: "1.0.1.8.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(1234), Scaler: -1, Unit: 30}
	v, _ := r.Get(2, nil)
	if v.Value.(uint32) != 1234 {
		t.Errorf("value %v", v.Value)
	}
	su, _ := r.Get(3, nil)
	s, u, err := scalerUnitOf(su)
	if err != nil || s != -1 || u != 30 {
		t.Errorf("scaler_unit %d %d %v", s, u, err)
	}
	wantResult(t, r.Set(2, axdr.CreateAxdrLong(5), nil), TypeUnmatched)
	if err := r.Set(2, axdr.CreateAxdrDoubleLongUnsigned(99), nil); err != nil {
		t.Fatal(err)
	}
	wantResult(t, r.Set(3, axdr.CreateAxdrInteger(1), nil), TypeUnmatched)
	if err := r.Set(3, scalerUnitData(-2, 33), nil); err != nil || r.Scaler != -2 || r.Unit != 33 {
		t.Errorf("set scaler_unit: %v", err)
	}
	if _, err := r.Action(1, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	if r.Value.Tag != axdr.TagDoubleLongUnsigned || r.Value.Value.(uint32) != 0 {
		t.Errorf("reset left %+v", r.Value)
	}
	wantResult(t, r.Set(2, nil, nil), TypeUnmatched)
	_, err = r.Get(2, &Selector{ID: 1})
	wantResult(t, err, ScopeViolated)

	d := &Data{LN: "0.0.96.1.0.255", Value: octetData([]byte("SN123"))}
	if err := d.Set(2, axdr.CreateAxdrVisibleString("x"), nil); ResultOf(err) != TypeUnmatched {
		t.Errorf("data type change gave %v", err)
	}
	d.ReadOnly = true
	wantResult(t, d.Set(2, octetData([]byte("SN124")), nil), ReadWriteDenied)
	free := &Data{LN: "0.0.96.1.1.255"}
	if err := free.Set(2, axdr.CreateAxdrUnsigned(7), nil); err != nil {
		t.Errorf("data with no value refused a set: %v", err)
	}
}

// Covers: SIG-IPE-6466
func TestExtendedAndDemandRegister(t *testing.T) {
	now := time.Date(2026, 10, 11, 10, 15, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	e := &ExtendedRegister{LN: "1.0.1.6.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(500),
		Status: axdr.CreateAxdrUnsigned(0), Now: clock, Location: time.UTC}
	if _, err := e.Action(1, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	ct, _ := e.Get(5, nil)
	if got, ok := ParseDateTime(hexOf(t, ct), time.UTC); !ok || !got.Equal(now) {
		t.Errorf("capture time %v", got)
	}
	wantResult(t, e.Set(5, ct, nil), ReadWriteDenied)
	if err := e.Set(4, axdr.CreateAxdrUnsigned(3), nil); err != nil {
		t.Error(err)
	}

	d := &DemandRegister{LN: "1.0.1.4.0.255", CurrentAverage: axdr.CreateAxdrDoubleLongUnsigned(42),
		LastAverage: axdr.CreateAxdrDoubleLongUnsigned(0), Period: 900, NumberOfPeriods: 1, Now: clock, Location: time.UTC}
	if _, err := d.Action(2, nil); err != nil {
		t.Fatal(err)
	}
	if d.LastAverage.Value.(uint32) != 42 || d.CurrentAverage.Value.(uint32) != 0 || !d.StartTimeCurrent.Equal(now) {
		t.Errorf("next period: last %v current %v", d.LastAverage.Value, d.CurrentAverage.Value)
	}
	wantResult(t, d.Set(2, axdr.CreateAxdrDoubleLongUnsigned(1), nil), ReadWriteDenied)
	if err := d.Set(8, axdr.CreateAxdrDoubleLongUnsigned(1800), nil); err != nil || d.Period != 1800 {
		t.Errorf("period: %v", err)
	}
	wantResult(t, d.Set(9, axdr.CreateAxdrUnsigned(1), nil), TypeUnmatched)
	if _, err := d.Action(1, nil); err != nil || d.LastAverage.Value.(uint32) != 0 {
		t.Errorf("reset: %v", err)
	}
}

func dt(t time.Time) *axdr.DlmsData { return octetData(DateTime(t, time.UTC)) }

// Covers: SIG-IPE-6466
func TestProfileGeneric(t *testing.T) {
	clockRef := CaptureObject{Class: 8, LN: "0.0.1.0.0.255", Attr: 2}
	energy := CaptureObject{Class: 3, LN: "1.0.1.8.0.255", Attr: 2}
	status := CaptureObject{Class: 1, LN: "0.0.96.10.1.255", Attr: 2}
	start := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	now := start
	clk := &Clock{LN: clockRef.LN, Now: func() time.Time { return now }, Location: time.UTC}
	reg := &Register{LN: energy.LN, Value: axdr.CreateAxdrDoubleLongUnsigned(0)}
	res := &fakeResolver{objs: map[string]Object{clk.LN: clk, reg.LN: reg},
		vals: map[CaptureObject]*axdr.DlmsData{status: axdr.CreateAxdrUnsigned(0)}}

	p := &ProfileGeneric{LN: "1.0.99.1.0.255", CaptureObjects: []CaptureObject{clockRef, energy, status},
		CapturePeriod: 900, SortMethod: 1, ProfileEntries: 4, Location: time.UTC}
	_, err := p.Action(2, axdr.CreateAxdrInteger(0))
	wantResult(t, err, TemporaryFailure)
	p.Bind(res)
	for i := 0; i < 6; i++ {
		now = start.Add(time.Duration(i) * 15 * time.Minute)
		reg.Lock()
		reg.Value = axdr.CreateAxdrDoubleLongUnsigned(uint32(100 * i))
		reg.Unlock()
		if _, err := p.Action(2, axdr.CreateAxdrInteger(0)); err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
	}
	n, _ := p.Get(7, nil)
	if n.Value.(uint32) != 4 {
		t.Fatalf("entries in use %v, want 4 (FIFO)", n.Value)
	}
	all, _ := p.Get(2, nil)
	rows := items(t, all)
	if first := items(t, rows[0]); first[1].Value.(uint32) != 200 {
		t.Errorf("oldest kept row has %v, want 200", first[1].Value)
	}

	// By range: 00:30 to 00:45 on the clock column, energy only.
	rangeSel := &Selector{ID: 1, Parameters: structOf(clockRef.data(), dt(start.Add(30*time.Minute)),
		dt(start.Add(45*time.Minute)), arrayOf([]*axdr.DlmsData{energy.data()}))}
	got, err := p.Get(2, rangeSel)
	if err != nil {
		t.Fatal(err)
	}
	rows = items(t, got)
	if len(rows) != 2 {
		t.Fatalf("range gave %d rows, want 2", len(rows))
	}
	for i, want := range []uint32{200, 300} {
		r := items(t, rows[i])
		if len(r) != 1 || r[0].Value.(uint32) != want {
			t.Errorf("range row %d = %+v", i, r)
		}
	}
	// By range with all columns.
	rangeSel.Parameters = structOf(clockRef.data(), dt(start), dt(start.Add(time.Hour)), arrayOf(nil))
	got, _ = p.Get(2, rangeSel)
	if rows = items(t, got); len(rows) != 3 || len(items(t, rows[0])) != 3 {
		t.Errorf("range all columns: %d rows", len(rows))
	}
	// Unknown restricting object.
	rangeSel.Parameters = structOf(CaptureObject{Class: 3, LN: "1.0.2.8.0.255", Attr: 2}.data(), dt(start), dt(start), arrayOf(nil))
	_, err = p.Get(2, rangeSel)
	wantResult(t, err, ObjectUnavailable)

	// By entry: rows 2 to the last, columns 2 to 3.
	entrySel := &Selector{ID: 2, Parameters: structOf(axdr.CreateAxdrDoubleLongUnsigned(2), axdr.CreateAxdrDoubleLongUnsigned(0),
		axdr.CreateAxdrLongUnsigned(2), axdr.CreateAxdrLongUnsigned(0))}
	got, err = p.Get(2, entrySel)
	if err != nil {
		t.Fatal(err)
	}
	rows = items(t, got)
	if len(rows) != 3 {
		t.Fatalf("entry gave %d rows", len(rows))
	}
	if r := items(t, rows[0]); len(r) != 2 || r[0].Value.(uint32) != 300 {
		t.Errorf("entry first row %+v", r)
	}
	// Beyond the buffer.
	entrySel.Parameters = structOf(axdr.CreateAxdrDoubleLongUnsigned(9), axdr.CreateAxdrDoubleLongUnsigned(12),
		axdr.CreateAxdrLongUnsigned(0), axdr.CreateAxdrLongUnsigned(0))
	got, _ = p.Get(2, entrySel)
	if len(items(t, got)) != 0 {
		t.Error("entries beyond the buffer were returned")
	}
	_, err = p.Get(2, &Selector{ID: 3})
	wantResult(t, err, ScopeViolated)

	// Capture objects round trip, and setting them clears the buffer.
	co, _ := p.Get(3, nil)
	if err := p.Set(3, co, nil); err != nil {
		t.Fatal(err)
	}
	if len(p.Buffer) != 0 || len(p.CaptureObjects) != 3 || p.CaptureObjects[1] != energy {
		t.Errorf("after setting capture objects: %d rows, %+v", len(p.Buffer), p.CaptureObjects)
	}
	wantResult(t, p.Set(7, axdr.CreateAxdrDoubleLongUnsigned(1), nil), ReadWriteDenied)
	wantResult(t, p.Set(2, arrayOf(nil), nil), ReadWriteDenied)
	_ = p.Capture()
	_ = p.Capture()
	if err := p.Set(8, axdr.CreateAxdrDoubleLongUnsigned(1), nil); err != nil || len(p.Buffer) != 1 {
		t.Errorf("shrinking profile entries left %d rows", len(p.Buffer))
	}
	if _, err := p.Action(1, axdr.CreateAxdrInteger(0)); err != nil || len(p.Buffer) != 0 {
		t.Errorf("reset left %d rows", len(p.Buffer))
	}
	// A failing read adds no row.
	p.CaptureObjects = append(p.CaptureObjects, CaptureObject{Class: 3, LN: "9.9.9.9.9.9", Attr: 2})
	wantResult(t, p.Capture(), ObjectUndefined)
	if len(p.Buffer) != 0 {
		t.Error("a failed capture added a row")
	}
}

// Covers: SIG-IPE-6466
func TestProfileDataIndex(t *testing.T) {
	ref := CaptureObject{Class: 1, LN: "0.0.96.1.0.255", Attr: 2, DataIndex: 2}
	res := &fakeResolver{vals: map[CaptureObject]*axdr.DlmsData{
		{Class: 1, LN: ref.LN, Attr: 2}: structOf(axdr.CreateAxdrUnsigned(1), axdr.CreateAxdrUnsigned(9)),
	}}
	p := &ProfileGeneric{LN: "1.0.99.2.0.255", CaptureObjects: []CaptureObject{ref}}
	p.Bind(res)
	if err := p.Capture(); err != nil {
		t.Fatal(err)
	}
	if v := p.Buffer[0][0]; v.Value.(uint8) != 9 {
		t.Errorf("data index picked %v", v.Value)
	}
}

// Covers: SIG-IPE-6466
func TestClock(t *testing.T) {
	ist := time.FixedZone("IST", 330*60)
	host := time.Date(2026, 10, 11, 10, 7, 20, 0, ist)
	c := &Clock{LN: "0.0.1.0.0.255", Now: func() time.Time { return host }, Location: ist, TimeZone: 330}
	v, _ := c.Get(2, nil)
	if got, ok := ParseDateTime(hexOf(t, v), nil); !ok || !got.Equal(host) {
		t.Fatalf("time %v", got)
	}
	set := time.Date(2026, 1, 1, 0, 0, 0, 0, ist)
	if err := c.Set(2, octetData(DateTime(set, ist)), nil); err != nil {
		t.Fatal(err)
	}
	host = host.Add(90 * time.Second)
	if got := c.Time(); !got.Equal(set.Add(90 * time.Second)) {
		t.Errorf("after set and 90 s: %v", got)
	}
	if _, err := c.Action(6, axdr.CreateAxdrLong(30)); err != nil {
		t.Fatal(err)
	}
	if got := c.Time(); !got.Equal(set.Add(120 * time.Second)) {
		t.Errorf("after shift: %v", got)
	}
	_, err := c.Action(6, axdr.CreateAxdrLong(901))
	wantResult(t, err, OtherReason)
	c.SetTime(time.Date(2026, 1, 1, 0, 8, 0, 0, ist))
	if _, err := c.Action(1, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	if got := c.Time(); got.Minute() != 15 || got.Second() != 0 {
		t.Errorf("adjust to quarter: %v", got)
	}
	c.SetTime(time.Date(2026, 1, 1, 0, 8, 29, 0, ist))
	_, _ = c.Action(3, axdr.CreateAxdrInteger(0))
	if got := c.Time(); got.Minute() != 8 || got.Second() != 0 {
		t.Errorf("adjust to minute: %v", got)
	}
	_, err = c.Action(2, axdr.CreateAxdrInteger(0))
	wantResult(t, err, ReadWriteDenied)
	// Preset then adjust.
	now := c.Time()
	preset := time.Date(2026, 5, 5, 5, 5, 5, 0, ist)
	_, err = c.Action(5, structOf(octetData(DateTime(preset, ist)), octetData(DateTime(now.Add(-time.Minute), ist)),
		octetData(DateTime(now.Add(time.Minute), ist))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Action(4, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	if got := c.Time(); !got.Equal(preset) {
		t.Errorf("preset: %v", got)
	}
	_, err = c.Action(4, axdr.CreateAxdrInteger(0))
	wantResult(t, err, TemporaryFailure)

	tz, _ := c.Get(3, nil)
	if tz.Value.(int16) != 330 {
		t.Errorf("time zone %v", tz.Value)
	}
	wantResult(t, c.Set(4, axdr.CreateAxdrUnsigned(0), nil), ReadWriteDenied)
	wantResult(t, c.Set(9, axdr.CreateAxdrEnum(1), nil), ReadWriteDenied)
	wantResult(t, c.Set(2, axdr.CreateAxdrUnsigned(0), nil), TypeUnmatched)
	if err := c.Set(8, axdr.CreateAxdrBoolean(true), nil); err != nil || !c.DSTEnabled {
		t.Errorf("dst enabled: %v", err)
	}
	pattern := []byte{0xFF, 0xFF, 3, 0xFE, 7, 2, 0, 0, 0, 0x80, 0, 0}
	if err := c.Set(5, octetData(pattern), nil); err != nil || !bytes.Equal(c.DSTBegin, pattern) {
		t.Errorf("dst begin: %v", err)
	}
}

// Covers: SIG-IPE-6466
func TestImageTransfer(t *testing.T) {
	var verified, activated []byte
	it := &ImageTransfer{LN: "0.0.44.0.0.255", BlockSize: 4, Enabled: true,
		OnVerify:   func(id, img []byte) error { verified = img; return nil },
		OnActivate: func(id, img []byte) error { activated = img; return nil }}
	image := []byte("firmware!")
	_, err := it.Action(2, structOf(axdr.CreateAxdrDoubleLongUnsigned(0), octetData(image[:4])))
	wantResult(t, err, TemporaryFailure)
	if _, err := it.Action(1, structOf(octetData([]byte("v2")), axdr.CreateAxdrDoubleLongUnsigned(uint32(len(image))))); err != nil {
		t.Fatal(err)
	}
	if it.Status != ImageInitiated {
		t.Fatalf("status %d", it.Status)
	}
	send := func(bn uint32, b []byte) error {
		_, err := it.Action(2, structOf(axdr.CreateAxdrDoubleLongUnsigned(bn), octetData(b)))
		return err
	}
	if err := send(0, image[0:4]); err != nil {
		t.Fatal(err)
	}
	if err := send(2, image[8:]); err != nil {
		t.Fatal(err)
	}
	bits, _ := it.Get(3, nil)
	if bits.Value.(string) != "101" {
		t.Errorf("blocks status %v", bits.Value)
	}
	first, _ := it.Get(4, nil)
	if first.Value.(uint32) != 1 {
		t.Errorf("first missing %v", first.Value)
	}
	wantResult(t, send(3, image[:1]), BlockNumberInvalid)
	wantResult(t, send(1, image[4:6]), OtherReason)
	// Verifying an incomplete image fails.
	_, err = it.Action(3, axdr.CreateAxdrInteger(0))
	wantResult(t, err, OtherReason)
	if it.Status != ImageVerificationFailed {
		t.Errorf("status %d after incomplete verify", it.Status)
	}
	// Start again and complete.
	_, _ = it.Action(1, structOf(octetData([]byte("v2")), axdr.CreateAxdrDoubleLongUnsigned(uint32(len(image)))))
	for bn := uint32(0); bn < 3; bn++ {
		end := min(int(bn+1)*4, len(image))
		if err := send(bn, image[bn*4:end]); err != nil {
			t.Fatal(err)
		}
	}
	// Activate verifies first.
	if _, err := it.Action(4, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	if it.Status != ImageActivationOK || !bytes.Equal(verified, image) || !bytes.Equal(activated, image) {
		t.Errorf("status %d verified %q activated %q", it.Status, verified, activated)
	}
	info, _ := it.Get(7, nil)
	entry := items(t, items(t, info)[0])
	if entry[0].Value.(uint32) != uint32(len(image)) || string(hexOf(t, entry[1])) != "v2" {
		t.Errorf("to activate info %+v", entry)
	}
	id, img := it.Image()
	if string(id) != "v2" || !bytes.Equal(img, image) {
		t.Errorf("Image() = %q %q", id, img)
	}
	// A refused verification.
	it.OnVerify = func(id, img []byte) error { return errors.New("bad signature") }
	_, _ = it.Action(1, structOf(octetData([]byte("v3")), axdr.CreateAxdrDoubleLongUnsigned(4)))
	_ = send(0, image[:4])
	_, err = it.Action(3, axdr.CreateAxdrInteger(0))
	wantResult(t, err, OtherReason)
	_, err = it.Action(4, axdr.CreateAxdrInteger(0))
	wantResult(t, err, TemporaryFailure)
	// Disabled transfer.
	if err := it.Set(5, axdr.CreateAxdrBoolean(false), nil); err != nil {
		t.Fatal(err)
	}
	_, err = it.Action(1, structOf(octetData([]byte("v4")), axdr.CreateAxdrDoubleLongUnsigned(4)))
	wantResult(t, err, TemporaryFailure)
	wantResult(t, it.Set(2, axdr.CreateAxdrDoubleLongUnsigned(8), nil), ReadWriteDenied)
}

// Covers: SIG-IPE-6466
func TestDisconnectControl(t *testing.T) {
	var outputs []bool
	d := &DisconnectControl{LN: "0.0.96.3.10.255", OutputState: true, ControlState: Connected, ControlMode: 0,
		OnChange: func(on bool) error { outputs = append(outputs, on); return nil }}
	_, err := d.Action(1, axdr.CreateAxdrInteger(0))
	wantResult(t, err, ReadWriteDenied)

	step := func(name string, f func() error, state uint8, out bool) {
		t.Helper()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.ControlState != state || d.OutputState != out {
			t.Fatalf("%s: state %d output %v", name, d.ControlState, d.OutputState)
		}
	}
	remoteOff := func() error { _, err := d.Action(1, axdr.CreateAxdrInteger(0)); return err }
	remoteOn := func() error { _, err := d.Action(2, axdr.CreateAxdrInteger(0)); return err }

	// Mode 1: remote reconnect arms, the customer closes.
	if err := d.Set(4, axdr.CreateAxdrEnum(1), nil); err != nil {
		t.Fatal(err)
	}
	step("remote disconnect", remoteOff, Disconnected, false)
	step("remote disconnect again", remoteOff, Disconnected, false)
	step("remote reconnect", remoteOn, ReadyForReconnection, false)
	step("manual reconnect", d.ManualReconnect, Connected, true)
	step("manual disconnect", d.ManualDisconnect, ReadyForReconnection, false)
	step("remote disconnect from ready", remoteOff, Disconnected, false)
	wantResult(t, d.ManualReconnect(), TemporaryFailure)

	// Mode 2: remote reconnect closes the switch directly.
	d.ControlMode = 2
	step("remote reconnect", remoteOn, Connected, true)
	step("local disconnect", d.LocalDisconnect, ReadyForReconnection, false)
	wantResult(t, d.LocalReconnect(), ReadWriteDenied)

	// Mode 3 has no manual disconnect.
	d.ControlMode = 3
	step("manual reconnect", d.ManualReconnect, Connected, true)
	wantResult(t, d.ManualDisconnect(), ReadWriteDenied)

	// A refused change is rolled back.
	d.OnChange = func(bool) error { return HardwareFault }
	_, err = d.Action(1, axdr.CreateAxdrInteger(0))
	wantResult(t, err, HardwareFault)
	if d.ControlState != Connected || !d.OutputState {
		t.Errorf("rollback left %d %v", d.ControlState, d.OutputState)
	}
	want := []bool{false, true, false, true, false, true}
	if len(outputs) != len(want) {
		t.Fatalf("output changes %v", outputs)
	}
	for i := range want {
		if outputs[i] != want[i] {
			t.Errorf("output changes %v, want %v", outputs, want)
			break
		}
	}
	wantResult(t, d.Set(2, axdr.CreateAxdrBoolean(false), nil), ReadWriteDenied)
	wantResult(t, d.Set(4, axdr.CreateAxdrEnum(9), nil), OtherReason)
	wantResult(t, d.Set(4, axdr.CreateAxdrUnsigned(1), nil), TypeUnmatched)
}

// Covers: SIG-IPE-6466
func TestObjectLists(t *testing.T) {
	entries := []*axdr.DlmsData{
		ObjectListEntryLN(8, 0, "0.0.1.0.0.255",
			[]AttributeAccess{{Index: 1, Mode: 1}, {Index: 2, Mode: 3}},
			[]MethodAccess{{Index: 1, Mode: 1}}),
		ObjectListEntryLN(7, 1, "1.0.99.1.0.255",
			[]AttributeAccess{{Index: 1, Mode: 1}, {Index: 2, Mode: 1, Selectors: []int8{1, 2}}}, nil),
	}
	got, err := ParseObjectListLN(*arrayOf(entries))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Class != 8 || got[0].LN != "0.0.1.0.0.255" || got[1].Version != 1 {
		t.Fatalf("parsed %+v", got)
	}
	if a := got[1].Attributes[1]; a.Mode != 1 || len(a.Selectors) != 2 || a.Selectors[1] != 2 {
		t.Errorf("selectors %+v", a)
	}
	if got[0].Attributes[0].Selectors != nil || got[0].Methods[0].Mode != 1 || len(got[1].Methods) != 0 {
		t.Errorf("access %+v", got)
	}
	// Encoded through gosem and decoded again (as a client receives it).
	// gosem writes null-data as two octets, so this entry has none.
	wire := ObjectListEntryLN(7, 1, "1.0.99.1.0.255",
		[]AttributeAccess{{Index: 1, Mode: 1, Selectors: []int8{}}, {Index: 2, Mode: 1, Selectors: []int8{1, 2}}},
		[]MethodAccess{{Index: 1, Mode: 1}})
	raw, err := wire.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := axdr.NewDataDecoder(&raw).Decode(&raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseObjectListLN(*arrayOf([]*axdr.DlmsData{&dec}))
	if err != nil || again[0].LN != "1.0.99.1.0.255" {
		t.Errorf("decoded %+v %v", again, err)
	}
	// Version 0 method access is a boolean.
	old := structOf(axdr.CreateAxdrLongUnsigned(3), axdr.CreateAxdrUnsigned(0), lnData("1.0.1.8.0.255"),
		structOf(arrayOf(nil), arrayOf([]*axdr.DlmsData{structOf(axdr.CreateAxdrInteger(1), axdr.CreateAxdrBoolean(true))})))
	v0, err := ParseObjectListLN(*arrayOf([]*axdr.DlmsData{old}))
	if err != nil || v0[0].Methods[0].Mode != 1 {
		t.Errorf("boolean method access: %+v %v", v0, err)
	}
	if _, err := ParseObjectListLN(*axdr.CreateAxdrUnsigned(1)); err == nil {
		t.Error("a non-array parsed")
	}
	if _, err := ParseObjectListLN(*arrayOf([]*axdr.DlmsData{axdr.CreateAxdrUnsigned(1)})); err == nil {
		t.Error("a bad entry parsed")
	}

	sn := arrayOf([]*axdr.DlmsData{ObjectListEntrySN(-0x5000, 3, 0, "1.0.1.8.0.255"), ObjectListEntrySN(0x0100, 8, 0, "0.0.1.0.0.255")})
	items, err := ParseObjectListSN(*sn)
	if err != nil || len(items) != 2 || items[0].BaseName != -0x5000 || items[1].Class != 8 || items[1].LN != "0.0.1.0.0.255" {
		t.Errorf("SN list %+v %v", items, err)
	}

	a := &AssociationLN{LN: "0.0.40.0.0.255", ObjectList: arrayOf(entries), ClientSAP: 48, ServerSAP: 1,
		Secret: []byte("secret"), Status: 2}
	ol, _ := a.Get(2, nil)
	if l, err := ParseObjectListLN(*ol); err != nil || len(l) != 2 {
		t.Errorf("association object list: %v", err)
	}
	a.ObjectListFunc = func() *axdr.DlmsData { return arrayOf(entries[:1]) }
	ol, _ = a.Get(2, nil)
	if l, _ := ParseObjectListLN(*ol); len(l) != 1 {
		t.Error("ObjectListFunc not used")
	}
	if err := a.Set(7, octetData([]byte("new")), nil); err != nil || string(a.Secret) != "new" {
		t.Errorf("secret set: %v", err)
	}
	wantResult(t, a.Set(8, axdr.CreateAxdrEnum(0), nil), ReadWriteDenied)
	_, err = a.Action(1, nil)
	wantResult(t, err, ReadWriteDenied)
	sa := &AssociationSN{LN: "0.0.40.0.0.255", ObjectList: sn}
	_, err = sa.Action(8, nil)
	wantResult(t, err, ReadWriteDenied)
	_, err = sa.Action(1, nil)
	wantResult(t, err, ObjectUndefined)
}

// Covers: SIG-IPE-6466
func TestScriptsSchedulesAndCalendars(t *testing.T) {
	var ran []uint16
	st := &ScriptTable{LN: "0.0.10.0.0.255", OnExecute: func(id uint16) error { ran = append(ran, id); return nil }}
	if _, err := st.Action(1, axdr.CreateAxdrLongUnsigned(2)); err != nil || len(ran) != 1 || ran[0] != 2 {
		t.Errorf("execute: %v %v", ran, err)
	}
	_, err := st.Action(1, axdr.CreateAxdrUnsigned(2))
	wantResult(t, err, TypeUnmatched)
	wantResult(t, st.Set(2, axdr.CreateAxdrUnsigned(1), nil), TypeUnmatched)

	sd := &SpecialDaysTable{LN: "0.0.11.0.0.255"}
	day := func(i uint16, id uint8) *axdr.DlmsData {
		return SpecialDay{Index: i, Date: []byte{0xFF, 0xFF, 1, 26, 0xFF}, DayID: id}.data()
	}
	_, _ = sd.Action(1, day(1, 2))
	_, _ = sd.Action(1, day(2, 3))
	_, _ = sd.Action(1, day(1, 4))
	if len(sd.Entries) != 2 || sd.Entries[0].DayID != 4 {
		t.Errorf("insert: %+v", sd.Entries)
	}
	_, _ = sd.Action(2, axdr.CreateAxdrLongUnsigned(1))
	got, _ := sd.Get(2, nil)
	if l := items(t, got); len(l) != 1 {
		t.Errorf("after delete %d entries", len(l))
	}
	if err := sd.Set(2, got, nil); err != nil || sd.Entries[0].Index != 2 {
		t.Errorf("set entries: %v", err)
	}

	sch := &Schedule{LN: "0.0.12.0.0.255"}
	entry := func(i uint16) *axdr.DlmsData {
		return structOf(axdr.CreateAxdrLongUnsigned(i), axdr.CreateAxdrBoolean(true))
	}
	for i := uint16(1); i <= 4; i++ {
		_, _ = sch.Action(2, entry(i))
	}
	_, _ = sch.Action(3, structOf(axdr.CreateAxdrLongUnsigned(2), axdr.CreateAxdrLongUnsigned(3)))
	if l, _ := arrayItems(sch.Entries); len(l) != 2 {
		t.Errorf("schedule has %d entries", len(l))
	}
	_, err = sch.Action(1, nil)
	wantResult(t, err, ReadWriteDenied)

	cal := &ActivityCalendar{LN: "0.0.13.0.0.255", NameActive: []byte("A")}
	wantResult(t, cal.Set(2, octetData([]byte("B")), nil), ReadWriteDenied)
	season := arrayOf([]*axdr.DlmsData{structOf(octetData([]byte("S1")), octetData(DateTime(time.Time{}, nil)), octetData([]byte("W1")))})
	if err := cal.Set(6, octetData([]byte("B")), nil); err != nil {
		t.Fatal(err)
	}
	if err := cal.Set(7, season, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cal.Action(1, axdr.CreateAxdrInteger(0)); err != nil {
		t.Fatal(err)
	}
	name, _ := cal.Get(2, nil)
	act, _ := cal.Get(3, nil)
	if string(hexOf(t, name)) != "B" || len(items(t, act)) != 1 {
		t.Errorf("activate: %q", hexOf(t, name))
	}

	sas := &SingleActionSchedule{LN: "0.0.15.0.0.255"}
	ref := ScriptRef{LN: "0.0.10.0.1.255", Selector: 1}
	if err := sas.Set(2, ref.data(), nil); err != nil || sas.ExecutedScript != ref {
		t.Errorf("executed script: %v", err)
	}
}

// Covers: SIG-IPE-6466
func TestPushMonitorAndRegisterActivation(t *testing.T) {
	inst := CaptureObject{Class: 3, LN: "1.0.32.7.0.255", Attr: 2}
	res := &fakeResolver{vals: map[CaptureObject]*axdr.DlmsData{inst: axdr.CreateAxdrLongUnsigned(2400)}}

	var pushed []*axdr.DlmsData
	ps := &PushSetup{LN: "0.0.25.9.0.255", PushObjectList: []CaptureObject{inst},
		Destination: PushDestination{Transport: 0, Address: []byte("192.0.2.1:4059"), Message: 0}}
	_, err := ps.Action(1, axdr.CreateAxdrInteger(0))
	wantResult(t, err, TemporaryFailure)
	ps.OnPush = func(v []*axdr.DlmsData) error { pushed = v; return nil }
	ps.Bind(res)
	if _, err := ps.Action(1, axdr.CreateAxdrInteger(0)); err != nil || len(pushed) != 1 || pushed[0].Value.(uint16) != 2400 {
		t.Errorf("push: %v %v", pushed, err)
	}
	dst, _ := ps.Get(3, nil)
	ps.Destination = PushDestination{}
	if err := ps.Set(3, dst, nil); err != nil || string(ps.Destination.Address) != "192.0.2.1:4059" {
		t.Errorf("destination round trip: %v", err)
	}
	list, _ := ps.Get(2, nil)
	if err := ps.Set(2, list, nil); err != nil || ps.PushObjectList[0] != inst {
		t.Errorf("push object list round trip: %v", err)
	}

	var scripts []ScriptRef
	up, down := ScriptRef{LN: "0.0.10.0.1.255", Selector: 1}, ScriptRef{LN: "0.0.10.0.1.255", Selector: 2}
	rm := &RegisterMonitor{LN: "0.0.16.1.0.255", MonitoredValue: ValueRef{Class: 3, LN: inst.LN, Attr: 2},
		Thresholds: arrayOf([]*axdr.DlmsData{axdr.CreateAxdrLongUnsigned(2500)}),
		Actions:    []MonitorAction{{Up: up, Down: down}},
		OnScript:   func(s ScriptRef) error { scripts = append(scripts, s); return nil }}
	rm.Bind(res)
	_ = rm.Check()
	res.vals[inst] = axdr.CreateAxdrLongUnsigned(2600)
	_ = rm.Check()
	_ = rm.Check()
	res.vals[inst] = axdr.CreateAxdrLongUnsigned(2000)
	_ = rm.Check()
	if len(scripts) != 2 || scripts[0] != up || scripts[1] != down {
		t.Errorf("monitor ran %+v", scripts)
	}
	acts, _ := rm.Get(4, nil)
	rm.Actions = nil
	if err := rm.Set(4, acts, nil); err != nil || len(rm.Actions) != 1 || rm.Actions[0].Down != down {
		t.Errorf("actions round trip: %v", err)
	}
	mv, _ := rm.Get(3, nil)
	if err := rm.Set(3, mv, nil); err != nil || rm.MonitoredValue.LN != inst.LN {
		t.Errorf("monitored value round trip: %v", err)
	}

	ra := &RegisterActivation{LN: "0.0.14.0.1.255"}
	_, _ = ra.Action(1, structOf(axdr.CreateAxdrLongUnsigned(3), lnData("1.0.1.8.1.255")))
	mask := func(name string, idx ...uint8) *axdr.DlmsData {
		l := make([]*axdr.DlmsData, len(idx))
		for i, x := range idx {
			l[i] = axdr.CreateAxdrUnsigned(x)
		}
		return structOf(octetData([]byte(name)), arrayOf(l))
	}
	_, _ = ra.Action(2, mask("T1", 1))
	_, _ = ra.Action(2, mask("T2", 1))
	_, _ = ra.Action(2, mask("T1", 1, 1))
	if l, _ := arrayItems(ra.MaskList); len(l) != 2 {
		t.Errorf("masks %d", len(l))
	}
	_, _ = ra.Action(3, octetData([]byte("T1")))
	if l, _ := arrayItems(ra.MaskList); len(l) != 1 {
		t.Errorf("masks after delete %d", len(l))
	}
	if l, _ := arrayItems(ra.RegisterAssignment); len(l) != 1 {
		t.Errorf("assignments %d", len(l))
	}
}

// Covers: SIG-IPE-6466
func TestSetupObjects(t *testing.T) {
	h := &IECHDLCSetup{LN: "0.0.22.0.0.255", CommSpeed: 5, WindowTransmit: 1, WindowReceive: 1,
		MaxInfoTransmit: 128, MaxInfoReceive: 128, InactivityTimeout: 120, DeviceAddress: 0x10}
	if err := h.Set(5, axdr.CreateAxdrLongUnsigned(256), nil); err != nil || h.MaxInfoTransmit != 256 {
		t.Errorf("max info: %v", err)
	}
	wantResult(t, h.Set(2, axdr.CreateAxdrUnsigned(5), nil), TypeUnmatched)

	ip := &IPv4Setup{LN: "0.0.25.1.0.255", IPAddress: 0xC0000201}
	_, _ = ip.Action(1, axdr.CreateAxdrDoubleLongUnsigned(0xE0000001))
	_, _ = ip.Action(1, axdr.CreateAxdrDoubleLongUnsigned(0xE0000002))
	_, _ = ip.Action(2, axdr.CreateAxdrDoubleLongUnsigned(0xE0000001))
	n, _ := ip.Action(3, axdr.CreateAxdrInteger(0))
	if n.Value.(uint16) != 1 {
		t.Errorf("multicast count %v", n.Value)
	}
	mc, _ := ip.Get(4, nil)
	if err := ip.Set(4, mc, nil); err != nil || ip.Multicast[0] != 0xE0000002 {
		t.Errorf("multicast round trip: %v", err)
	}

	tcp := &TCPUDPSetup{LN: "0.0.25.0.0.255", Port: 4059, IPReference: "0.0.25.1.0.255"}
	ref, _ := tcp.Get(3, nil)
	tcp.IPReference = ""
	if err := tcp.Set(3, ref, nil); err != nil || tcp.IPReference != "0.0.25.1.0.255" {
		t.Errorf("ip reference: %v", err)
	}

	sap := &SAPAssignment{LN: "0.0.41.0.0.255", List: []SAPEntry{{SAP: 1, Name: []byte("MTR00001")}}}
	_, _ = sap.Action(1, structOf(axdr.CreateAxdrLongUnsigned(2), octetData([]byte("MTR00002"))))
	_, _ = sap.Action(1, structOf(axdr.CreateAxdrLongUnsigned(1), octetData(nil)))
	if len(sap.List) != 1 || sap.List[0].SAP != 2 {
		t.Errorf("SAP list %+v", sap.List)
	}

	lp := &IECLocalPortSetup{LN: "0.0.20.0.0.255"}
	if err := lp.Set(7, octetData([]byte("00000000")), nil); err != nil || string(lp.PasswordP1) != "00000000" {
		t.Errorf("P1: %v", err)
	}

	var transferred *axdr.DlmsData
	ss := &SecuritySetup{LN: "0.0.43.0.0.255", SecuritySuite: 0, ServerSystemTitle: []byte("ABC12345"),
		OnKeyTransfer: func(p *axdr.DlmsData) error { transferred = p; return nil }}
	if _, err := ss.Action(1, axdr.CreateAxdrEnum(3)); err != nil || ss.SecurityPolicy != 3 {
		t.Errorf("activate: %v", err)
	}
	keys := arrayOf([]*axdr.DlmsData{structOf(axdr.CreateAxdrEnum(0), octetData(make([]byte, 24)))})
	if _, err := ss.Action(2, keys); err != nil || transferred != keys {
		t.Errorf("key transfer: %v", err)
	}
	_, err := ss.Action(3, nil)
	wantResult(t, err, ReadWriteDenied)
	_, err = ss.Action(6, nil)
	wantResult(t, err, ReadWriteDenied)
	wantResult(t, ss.Set(5, octetData([]byte("x")), nil), ReadWriteDenied)
	st, _ := ss.Get(5, nil)
	if hex.EncodeToString(hexOf(t, st)) != hex.EncodeToString([]byte("ABC12345")) {
		t.Errorf("server system title % x", hexOf(t, st))
	}

	lim := &Limiter{LN: "0.0.17.0.0.255"}
	mv := ValueRef{Class: 3, LN: "1.0.1.7.0.255", Attr: 2}
	if err := lim.Set(2, mv.data(), nil); err != nil || lim.MonitoredValue != mv {
		t.Errorf("limiter monitored value: %v", err)
	}
	wantResult(t, lim.Set(10, axdr.CreateAxdrBoolean(true), nil), ReadWriteDenied)
}

// Covers: SIG-IPE-6466
func TestGeneric(t *testing.T) {
	g := &Generic{Class: 45, LN: "0.0.25.4.0.255",
		Attrs:    map[int8]*axdr.DlmsData{2: octetData([]byte("airtelgprs.com"))},
		Writable: map[int8]bool{2: true},
		Methods:  map[int8]func(*axdr.DlmsData) (*axdr.DlmsData, error){},
	}
	if err := g.Set(2, octetData([]byte("jionet")), nil); err != nil {
		t.Fatal(err)
	}
	wantResult(t, g.Set(2, axdr.CreateAxdrUnsigned(1), nil), TypeUnmatched)
	wantResult(t, g.Set(3, octetData([]byte("0000")), nil), ReadWriteDenied)
	v, err := g.Get(4, nil)
	if err != nil || v.Tag != axdr.TagNull {
		t.Errorf("missing known attribute: %+v %v", v, err)
	}
	_, err = g.Get(5, nil)
	wantResult(t, err, ObjectUndefined)

	called := false
	g2 := &Generic{Class: 29, Ver: 2, LN: "0.0.2.1.0.255",
		Methods: map[int8]func(*axdr.DlmsData) (*axdr.DlmsData, error){
			1: func(*axdr.DlmsData) (*axdr.DlmsData, error) { called = true; return nil, nil }}}
	if _, err := g2.Action(1, nil); err != nil || !called {
		t.Errorf("method: %v", err)
	}
	_, err = (&Generic{Class: 29}).Action(1, nil)
	wantResult(t, err, ReadWriteDenied)
	_, err = (&Generic{Class: 9999, Attrs: map[int8]*axdr.DlmsData{2: axdr.CreateAxdrUnsigned(1)}}).Get(2, nil)
	if err != nil {
		t.Errorf("uncatalogued class with a set attribute: %v", err)
	}
}
