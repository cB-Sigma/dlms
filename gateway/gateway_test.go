package gateway

import (
	"bytes"
	"errors"
	"testing"
)

// The prefix is the header, the network ID, the address length and the
// address, in that order, before the APDU (IEC 62056-5-3:2023 C.2).
//
// Covers: SIG-IPE-3740
func TestPrefixLayout(t *testing.T) {
	apdu := []byte{0xC0, 0x01, 0xC1, 0x00, 0x03, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, 0x02, 0x00}
	b, err := Encode(Prefix{Header: Request, Network: 2, Address: []byte{0x12, 0x34, 0x56}}, apdu)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0xE6, 0x02, 0x03, 0x12, 0x34, 0x56}, apdu...)
	if !bytes.Equal(b, want) {
		t.Fatalf("encoded % X, want % X", b, want)
	}
	p, inner, ok, err := Parse(append([]byte{0xE7}, want[1:]...))
	if !ok || err != nil || p.Header != Response || p.Network != 2 || !bytes.Equal(p.Address, []byte{0x12, 0x34, 0x56}) || !bytes.Equal(inner, apdu) {
		t.Fatalf("parsed %+v % X %v %v", p, inner, ok, err)
	}
	// A plain APDU has no prefix; only E6 and E7 start one.
	if _, inner, ok, _ := Parse(apdu); ok || !bytes.Equal(inner, apdu) {
		t.Error("a plain APDU was read as prefixed")
	}
	// One network: ID 0; an empty address is kept as empty.
	if p, inner, ok, err := Parse([]byte{0xE6, 0x00, 0x00, 0x0F}); !ok || err != nil || p.Network != 0 || len(p.Address) != 0 || !bytes.Equal(inner, []byte{0x0F}) {
		t.Errorf("zero-length address: %+v % X %v %v", p, inner, ok, err)
	}
	// A prefix cut short is an error, not a plain APDU.
	if _, _, ok, err := Parse([]byte{0xE7, 0x00, 0x04, 0x01}); !ok || !errors.Is(err, ErrShort) {
		t.Errorf("short prefix: ok %v err %v", ok, err)
	}
	if _, err := Encode(Prefix{Header: 0xE5}, apdu); err == nil {
		t.Error("header E5 encoded")
	}
	if _, err := Encode(Prefix{Header: Request, Address: make([]byte, 256)}, apdu); err == nil {
		t.Error("a 256-octet address encoded")
	}
}

// Covers: SIG-IPE-3740
func TestParseAddress(t *testing.T) {
	for in, want := range map[string]string{
		"0A1B2C": "0A1B2C", "0a:1b:2c": "0A1B2C", "0x0A-1B": "0A1B", "abc": "0ABC", "00 11 22 33 44 55 66 77": "0011223344556677",
	} {
		b, err := ParseAddress(in)
		if err != nil || FormatAddress(b) != want {
			t.Errorf("ParseAddress(%q) = %s, %v; want %s", in, FormatAddress(b), err, want)
		}
	}
	for _, bad := range []string{"", "zz", "0x"} {
		if _, err := ParseAddress(bad); err == nil {
			t.Errorf("ParseAddress(%q) accepted", bad)
		}
	}
}
