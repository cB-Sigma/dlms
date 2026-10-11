package is15959

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Covers: SIG-IPE-980
func TestCatalogueIsComplete(t *testing.T) {
	want := []string{"part1-category-A", "part1-category-B", "part1-category-C", "part2-1ph", "part2-3ph", "part3-boundary", "part3-ctpt"}
	if got := IDs(); !slices.Equal(got, want) {
		t.Fatalf("profiles = %v, want %v", got, want)
	}
	named := func(what, name, obis string) {
		if name == "" || strings.Count(name, ".") == 5 || strings.Contains(name, "Attr") {
			t.Errorf("%s %s has no catalogue name (%q)", what, obis, name)
		}
	}
	for _, id := range IDs() {
		sp, _ := Get(id)
		objects, profiles, logs, codes, push, methods := sp.Count()
		t.Logf("%s: %d objects, %d profiles, %d event logs with %d codes, %d push setups, %d commands", id, objects, profiles, logs, codes, push, methods)
		seen := map[string]bool{}
		for _, o := range sp.Objects {
			named("object", o.Name, o.OBIS)
			k := fmt.Sprintf("%s/%d", o.OBIS, o.Attr)
			if seen[k] {
				t.Errorf("%s lists %s twice", id, k)
			}
			seen[k] = true
			if o.Access == (Rights{}) {
				t.Errorf("%s: %s has no access rights", id, o.OBIS)
			}
			if o.Ref == "" || o.Group == "" {
				t.Errorf("%s: %s has no reference or group", id, o.OBIS)
			}
			if (o.Class == ClassRegister || o.Class == ClassExtendedRegister) && o.Attr == 2 && o.Unit == "" &&
				o.OBIS != "0.0.0.1.2.255" && !strings.Contains(o.Name, "owerFactor") {
				t.Errorf("%s: register %s (%s) has no unit", id, o.OBIS, o.Name)
			}
		}
		for _, p := range sp.Profiles {
			named("profile", p.Name, p.OBIS)
			if len(p.Capture) == 0 {
				t.Errorf("%s: profile %s captures nothing", id, p.OBIS)
			}
			for _, c := range p.Capture {
				named("column of "+p.Name, c.Name, c.OBIS)
			}
			if p.Scaler != "" && sp.Profile(p.Scaler) == nil {
				t.Errorf("%s: profile %s names scaler profile %s, which is not listed", id, p.OBIS, p.Scaler)
			}
		}
		for _, l := range sp.Events {
			if len(l.Codes) == 0 || l.Capture[1].OBIS != l.CodeOBIS {
				t.Errorf("%s: event log %s = %+v", id, l.OBIS, l)
			}
			for _, e := range l.Codes {
				if strings.HasPrefix(e.Name, "event ") {
					t.Errorf("%s: event code %d has no name", id, e.Code)
				}
			}
		}
		for _, b := range sp.ESW {
			for _, c := range []int{b.Occurrence, b.Restoration} {
				if _, ok := sp.EventName(c); c != 0 && !ok && c != 251 && c != 301 && c != 302 && c != 205 && c != 206 {
					t.Errorf("%s: ESW bit %d names code %d, which no log has", id, b.Bit, c)
				}
			}
		}
		for _, m := range sp.Methods {
			if m.Access == (Rights{}) || m.Ref == "" {
				t.Errorf("%s: method %s has no access or reference", id, m.Name)
			}
		}
	}
	// One name per OBIS code across every profile.
	byOBIS := map[string]string{}
	for _, id := range IDs() {
		sp, _ := Get(id)
		for _, o := range sp.Objects {
			k := fmt.Sprintf("%s/%d", o.OBIS, o.Attr)
			if n, ok := byOBIS[k]; ok && n != o.Name {
				t.Errorf("%s is %q in one profile and %q in another", k, n, o.Name)
			}
			byOBIS[k] = o.Name
		}
	}
	if A("PC:R MR:R US:RW FW:X").String() != "PC:R MR:R US:RW FW:X" {
		t.Error("access text does not round-trip")
	}
}

func has(cols []Column, obis string, attr int8) bool {
	for _, c := range cols {
		if c.OBIS == obis && c.Attr == attr {
			return true
		}
	}
	return false
}

// Covers: SIG-IPE-981
func TestCatalogueFollowsTheText(t *testing.T) {
	d1, _ := Get("part2-1ph")
	d2, _ := Get("part2-3ph")
	d3, _ := Get("part3-ctpt")
	d4, _ := Get("part3-boundary")
	a, _ := Get("part1-category-A")
	b, _ := Get("part1-category-B")
	c, _ := Get("part1-category-C")
	check := func(ok bool, what string) {
		t.Helper()
		if !ok {
			t.Error(what)
		}
	}
	// Part 1.
	check(has(a.Profile("1.0.99.1.0.255").Capture, "1.0.31.27.0.255", 2), "category A block load IR average is 1.0.31.27.0.255 (table 23 prints D=87)")
	check(has(c.Profile("1.0.94.91.0.255").Capture, "1.0.3.7.0.255", 2) && !has(c.Profile("1.0.94.91.0.255").Capture, "1.0.37.7.0.255", 2), "category C reactive power is 1.0.3.7.0.255 (table 27 prints C=37)")
	check(has(b.Profile("1.0.99.2.0.255").Capture, "1.0.94.91.1.255", 2), "category B daily load has reactive energy at high voltage (table 26)")
	check(len(c.Profile("1.0.98.1.0.255").Capture) == 2+1+8+3+8+2*9*2, "category C billing has 40 rows, MD with capture time")
	check(b.Profile("1.0.98.1.0.255") == nil && a.Profile("1.0.99.2.0.255") == nil, "category A has no daily load and B no billing profile")
	us, _ := a.Association(US)
	check(us.Client == 48 && us.Auth == "hls-aes" && us.Security == "none", "Part 1 utility settings: client 48, HLS with AES, basic security")
	check(len(a.Events) == 7 && a.EventLog("0.0.99.98.6.255").Codes[0].Code == 301, "Part 1 has seven logs, control events 301/302 in e=6")
	// Part 2 as amended.
	for _, sp := range []*Spec{d1, d2} {
		check(sp.PushSetup("0.0.25.9.0.255") != nil && sp.PushSetup("0.4.25.9.0.255") != nil && sp.PushSetup("0.0.25.9.1.255") == nil, sp.ID+": push setups are 0.b.25.9.0.255 (Amd 1)")
		check(sp.Object("0.0.44.0.0.255", 6) != nil && sp.Object("0.0.44.0.1.255", 6) == nil, sp.ID+": image transfer is 0.0.44.0.0.255 (Amd 1 item 24)")
		check(sp.Object("0.0.17.0.0.255", 3) != nil && sp.Method("load-limit").Attr == 3, sp.ID+": load limit is limiter attribute 3 (Amd 1 item 25)")
		check(sp.Object("0.0.96.3.10.255", 2) != nil && sp.Object("0.0.96.31.0.255", 2) == nil, sp.ID+": load limit status is 0.0.96.3.10.255 (Amd 1 item 38)")
		check(sp.Suite == 0, sp.ID+": security suite 0")
		ev := sp.PushSetup(PushEvent)
		check(ev.Capture[3].OBIS == EventStatusWord && ev.Capture[1].Class == ClassPushSetup, sp.ID+": event push carries the ESW")
		b3, _ := sp.ESWBit(3)
		check(b3.Occurrence == 7, sp.ID+": ESW bit 3 (over-voltage) is common to both (Amd 1 item 18)")
		for _, r := range []Role{MR, US, FW, Push} {
			as, _ := sp.Association(r)
			check(as.Setup == "0.0.43.0."+fmt.Sprint(int(r)+1)+".255", sp.ID+": security setup of "+r.String())
		}
		check(sp.Method("metering-mode") != nil && sp.Object("0.0.94.96.20.255", 2) != nil, sp.ID+": metering and payment mode (Amd 1 items 36, 37)")
		check(sp.Method("firmware-hls-secret") != nil && sp.Method("billing-reset").OBIS == "0.0.10.0.1.255", sp.ID+": key and MD reset objects (Amd 1 item 36)")
	}
	check(has(d1.Profile("1.0.99.1.0.255").Capture, "1.0.11.27.0.255", 2), "D1 block load has the average current (Amd 1 item 27)")
	check(d1.Profile("1.0.99.2.0.255").Capture[0].OBIS == ClockOBIS, "D1 daily load starts with the clock (Amd 1 item 26)")
	check(!has(d2.Profile("1.0.99.1.0.255").Capture, "1.0.5.29.0.255", 2), "D2 block load has no rows ix, x (Amd 1 item 41)")
	check(has(d2.EventLog("0.0.99.98.0.255").Capture, "1.0.31.7.0.255", 2) && !has(d2.EventLog("0.0.99.98.0.255").Capture, "1.0.3.7.0.255", 2), "D2 event capture IR is 1.0.31.7.0.255 (Amd 1 item 48)")
	check(has(d2.Profile("1.0.98.1.0.255").Capture, "1.0.8.8.0.255", 2) && len(d2.Profile("1.0.98.1.0.255").Capture) == 45+18, "D2 billing: 45 rows (Amd 1 item 44), MD rows with capture time")
	check(has(d1.EventLog("0.0.99.98.4.255").Capture, "0.0.94.91.0.255", 2), "D1 event capture has the tamper count (Amd 1 item 34)")
	_, one := d1.ESWBit(51)
	_, three := d2.ESWBit(51)
	check(one && !three, "ESW bit 51 (earth loading) is single-phase only")
	codes := func(sp *Spec, e string) []int {
		var out []int
		for _, x := range sp.EventLog(e).Codes {
			out = append(out, x.Code)
		}
		return out
	}
	check(fmt.Sprint(codes(d1, "0.0.99.98.1.255")) == "[51 52 67 68 69 70]", "D1 current events as replaced by Amd 1 item 33")
	check(slices.Contains(codes(d2, "0.0.99.98.3.255"), 166) && !slices.Contains(codes(d2, "0.0.99.98.3.255"), 156), "transaction events 161-166 added, 156 unused (Amd 1 items 29, 46)")
	check(d2.Profile("1.0.99.1.0.255").Period == 30*time.Minute, "block load default capture period 1800 s")
	// Part 3.
	for _, sp := range []*Spec{d3, d4} {
		check(sp.Method("disconnect") == nil && sp.Object("0.0.96.3.10.255", 2) == nil && sp.EventLog("0.0.99.98.6.255") == nil, sp.ID+": no disconnect control (Part 3 clause 10)")
		check(sp.Method("global-key-transfer").OBIS == "0.0.43.0.0.255", sp.ID+": global key change on 0.0.43.0.0.255 (tables 13, 26)")
		check(len(sp.Profile("1.0.94.91.0.255").Capture) == 1+28+4, sp.ID+": instantaneous has 31 rows (MD with capture time)")
	}
	check(len(d3.Profile("1.0.98.1.0.255").Capture) == 45+18 && len(d4.Profile("1.0.98.1.0.255").Capture) == 13+2, "D3 billing 45 rows, D4 13")
	check(has(d4.Profile("1.0.99.1.0.255").Capture, "1.0.16.29.0.255", 2) && !has(d3.Profile("1.0.99.1.0.255").Capture, "1.0.16.29.0.255", 2), "net block energy only for D4")
	check(d3.Method("metering-mode") != nil && d4.Method("metering-mode") == nil, "metering mode is D3's only (table 13 vs 26)")
	check(!slices.Contains(codes(d4, "0.0.99.98.3.255"), 152) && slices.Contains(codes(d3, "0.0.99.98.3.255"), 177), "D4 leaves out 152, 153, 167, 177, 178")
}
