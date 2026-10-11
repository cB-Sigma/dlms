// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"bytes"
	"testing"
	"time"
)

// Covers: SIG-IPE-6466
func TestCatalogueShape(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("empty catalogue")
	}
	seen := map[uint16]bool{}
	for i, c := range all {
		if seen[c.ID] {
			t.Errorf("class %d listed twice", c.ID)
		}
		seen[c.ID] = true
		if i > 0 && all[i-1].ID >= c.ID {
			t.Errorf("All not ascending at class %d", c.ID)
		}
		if got, ok := Lookup(c.ID); !ok || got != c {
			t.Errorf("Lookup(%d) does not return the catalogue entry", c.ID)
		}
		if len(c.Attributes) == 0 || c.Attributes[0].Index != 1 || c.Attributes[0].Name != "logicalName" {
			t.Errorf("class %d: attribute 1 is not the logical name", c.ID)
		}
		for j, a := range c.Attributes {
			if a.Index != int8(j+1) {
				t.Errorf("class %d: attribute %q has index %d, want %d", c.ID, a.Name, a.Index, j+1)
			}
		}
		for j, m := range c.Methods {
			if j > 0 && c.Methods[j-1].Index >= m.Index {
				t.Errorf("class %d: methods not ascending at %d", c.ID, m.Index)
			}
		}
		if len(c.Methods) == 0 && c.FirstMethodSN != 0 {
			t.Errorf("class %d has a method offset but no methods", c.ID)
		}
	}
	if _, ok := Lookup(9999); ok {
		t.Error("Lookup of an unknown class succeeded")
	}
}

// Covers: SIG-IPE-6466
func TestCatalogueShortNames(t *testing.T) {
	want := map[uint16]uint16{18: 0x40, 20: 0x50, 15: 0x60, 12: 0x20, 8: 0x60, 5: 0x48, 4: 0x38, 42: 0x60,
		7: 0x58, 3: 0x28, 6: 0x30, 61: 0x28, 17: 0x20, 9: 0x20, 11: 0x10, 64: 0x30, 70: 0x20, 40: 0x38, 100: 0x38}
	for id, off := range want {
		c, ok := Lookup(id)
		if !ok {
			t.Errorf("class %d missing", id)
			continue
		}
		if c.FirstMethodSN != off {
			t.Errorf("class %d: first method offset 0x%X, want 0x%X", id, c.FirstMethodSN, off)
		}
	}
	clock, _ := Lookup(8)
	if got := clock.AttributeSN(2); got != 0x08 {
		t.Errorf("clock attribute 2 offset 0x%X", got)
	}
	if got, ok := clock.MethodSN(6); !ok || got != 0x60+5*8 {
		t.Errorf("clock method 6 offset 0x%X %v", got, ok)
	}
	if _, ok := clock.MethodSN(7); ok {
		t.Error("clock method 7 has an offset")
	}
	data, _ := Lookup(1)
	if _, ok := data.MethodSN(1); ok {
		t.Error("data has a method offset")
	}
	sched, _ := Lookup(10)
	if _, ok := sched.MethodSN(1); ok {
		t.Error("schedule offset should be unknown")
	}
	if a, ok := clock.Attribute(9); !ok || a.Name != "clockBase" {
		t.Errorf("clock attribute 9 = %+v", a)
	}
	if m, ok := clock.Method(6); !ok || m.Name != "shiftTime" {
		t.Errorf("clock method 6 = %+v", m)
	}
	want2 := map[uint16]uint8{7: 1, 12: 4, 15: 3, 19: 1, 23: 1, 64: 1, 72: 1, 28: 2, 29: 2}
	for id, v := range want2 {
		if c, _ := Lookup(id); c.Version != v {
			t.Errorf("class %d version %d, want %d", id, c.Version, v)
		}
	}
}

// Covers: SIG-IPE-6466
func TestLogicalNames(t *testing.T) {
	b, err := LNOctets("1.0.32.7.0.255")
	if err != nil || !bytes.Equal(b, []byte{1, 0, 32, 7, 0, 255}) {
		t.Fatalf("LNOctets = % x, %v", b, err)
	}
	if s := LNString(b); s != "1.0.32.7.0.255" {
		t.Errorf("LNString = %q", s)
	}
	for _, bad := range []string{"1.0.32.7.0", "1.0.32.7.0.256", "a.b.c.d.e.f", ""} {
		if _, err := LNOctets(bad); err == nil {
			t.Errorf("LNOctets(%q) accepted", bad)
		}
	}
	if LNString([]byte{1, 2}) != "" {
		t.Error("LNString of a short slice")
	}
}

// Covers: SIG-IPE-6466
func TestDateTime(t *testing.T) {
	ist := time.FixedZone("IST", 330*60)
	tm := time.Date(2026, 10, 11, 16, 30, 15, 250_000_000, ist)
	b := DateTime(tm, ist)
	want := []byte{0x07, 0xEA, 10, 11, 7, 16, 30, 15, 25, 0xFE, 0xB6, 0x00}
	if !bytes.Equal(b, want) {
		t.Fatalf("DateTime = % x, want % x", b, want)
	}
	got, ok := ParseDateTime(b, nil)
	if !ok || !got.Equal(tm) {
		t.Errorf("ParseDateTime = %v %v", got, ok)
	}
	// Deviation not specified: local time in loc.
	b2 := append([]byte(nil), b...)
	b2[9], b2[10] = 0x80, 0x00
	got, ok = ParseDateTime(b2, ist)
	if !ok || !got.Equal(tm) {
		t.Errorf("unspecified deviation: %v %v", got, ok)
	}
	// UTC conversion of the same instant.
	if u := DateTime(tm, time.UTC); u[5] != 11 || u[6] != 0 || u[9] != 0 || u[10] != 0 {
		t.Errorf("UTC form % x", u)
	}
	// The zero time is the unspecified form and does not parse.
	z := DateTime(time.Time{}, ist)
	if !unspecifiedDateTime(z) || z[9] != 0x80 || z[10] != 0 {
		t.Errorf("zero time % x", z)
	}
	if _, ok := ParseDateTime(z, ist); ok {
		t.Error("unspecified date-time parsed")
	}
	if _, ok := ParseDateTime(b[:11], ist); ok {
		t.Error("short date-time parsed")
	}
	// Daylight saving flag.
	ny, err := time.LoadLocation("America/New_York")
	if err == nil {
		s := DateTime(time.Date(2026, 7, 1, 12, 0, 0, 0, ny), ny)
		if s[11]&0x80 == 0 || int16(uint16(s[9])<<8|uint16(s[10])) != 240 {
			t.Errorf("summer time form % x", s)
		}
	}
}
