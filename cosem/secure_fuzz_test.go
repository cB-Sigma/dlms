package cosem

// Fuzz tests for the DLMS/COSEM secure layer (hardening, docs/hardening.md).
// Everything incoming comes from a meter on a serial line or TCP, so it is
// untrusted: AARE and ciphered APDUs are parsed before any key check.
// Invariants: no panic; parseTLVs only returns elements inside its input,
// and what it returns encodes back to the same bytes when the input used
// the shortest length forms; unprotect never accepts a body it cannot
// verify under authenticated policies.

import (
	"bytes"
	"testing"
)

func fuzzSecurity(suite Suite, policy byte, dedicated bool) Security {
	return Security{
		Suite: suite, Policy: policy, Dedicated: dedicated,
		SystemTitle: []byte("SGM\x00\x00\x00\x00\x01"),
		Key:         bytes.Repeat([]byte{7}, suite.KeyLen()),
		AuthKey:     bytes.Repeat([]byte{9}, suite.KeyLen()),
	}
}

func FuzzGetLen(f *testing.F) {
	for _, b := range [][]byte{{0x05}, {0x81, 0xff}, {0x82, 0x01, 0x00}, {0x83, 1, 2, 3}, {0x81}, {}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		n, sz, err := getLen(b)
		if err != nil {
			return
		}
		if sz < 1 || sz > len(b) || n < 0 {
			t.Fatalf("getLen(%x) = %d, %d", b, n, sz)
		}
		if back, s2, err := getLen(putLen(n)); err != nil || back != n || s2 > sz {
			t.Fatalf("putLen(%d) does not read back: %d %d %v", n, back, s2, err)
		}
	})
}

func FuzzParseTLVs(f *testing.F) {
	f.Add([]byte{0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01, 0xA2, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0xBE, 0x81, 0x02, 0x04, 0x00})
	f.Add([]byte{0xBE, 0x82, 0xff, 0xff})
	f.Add([]byte{0xBE})
	f.Fuzz(func(t *testing.T, b []byte) {
		items, err := parseTLVs(b)
		if err != nil {
			return
		}
		total := 0
		for _, it := range items {
			total += 1 + len(putLen(len(it.val))) + len(it.val)
		}
		if total > len(b) {
			t.Fatalf("parseTLVs(%x) returned %d bytes of elements", b, total)
		}
		enc := encodeTLVs(0x60, items)
		n, sz, err := getLen(enc[1:])
		if err != nil {
			t.Fatalf("encodeTLVs output has no length: %x", enc)
		}
		back, err := parseTLVs(enc[1+sz : 1+sz+n])
		if err != nil || len(back) != len(items) {
			t.Fatalf("encodeTLVs(%v) does not parse back: %v", items, err)
		}
		for i := range items {
			if back[i].tag != items[i].tag || !bytes.Equal(back[i].val, items[i].val) {
				t.Fatalf("element %d differs after encode: %x vs %x", i, back[i].val, items[i].val)
			}
		}
	})
}

func FuzzUnprotect(f *testing.F) {
	st := []byte("SGM\x00\x00\x00\x00\x01")
	for _, suite := range []Suite{0, 1, 2} {
		sec := fuzzSecurity(suite, SecAuthentication|SecEncryption, false)
		for _, pol := range []byte{SecAuthentication, SecEncryption, SecAuthentication | SecEncryption} {
			if p, err := Protect(suite, pol, sec.Key, sec.AuthKey, st, 42, []byte{0xC4, 0x01, 0x41, 0x00, 0x09, 0x01, 0x05}); err == nil {
				f.Add(byte(suite), p)
			}
		}
	}
	f.Add(byte(0), []byte{0x30, 0, 0, 0, 1})
	f.Add(byte(0), []byte{0xC0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, s byte, payload []byte) {
		suite := Suite(s % 3)
		sec := fuzzSecurity(suite, SecAuthentication|SecEncryption, false)
		plain, _, err := Unprotect(suite, sec.Key, sec.AuthKey, st, payload)
		if err != nil || len(payload) < 5 {
			return
		}
		if payload[0]&SecAuthentication != 0 {
			// An authenticated APDU that verified must be one we can
			// produce ourselves from the same plaintext.
			again, err := Protect(suite, payload[0]&0x30, sec.Key, sec.AuthKey, st, beUint32(payload[1:5]), plain)
			if err != nil || !bytes.Equal(again, payload) {
				t.Fatalf("unprotect accepted %x, which protect does not produce (%x, %v)", payload, again, err)
			}
		}
	})
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// FuzzIncoming feeds APDUs from the meter to a secure transport in each
// policy, before and after association, with and without a dedicated key.
func FuzzIncoming(f *testing.F) {
	aare := []byte{0x61, 0x29,
		0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x03,
		0xA2, 0x03, 0x02, 0x01, 0x00,
		0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0E,
		0xA4, 0x0A, 0x04, 0x08, 'M', 'T', 'R', 0, 0, 0, 0, 1,
		0xAA, 0x06, 0x80, 0x04, 1, 2, 3, 4}
	f.Add(byte(0x30), false, aare)
	f.Add(byte(0x30), true, append(bytes.Clone(aare), 0xBE, 0x04, 0x04, 0x02, 0x28, 0x00))
	f.Add(byte(0x00), false, []byte{0xC4, 0x01, 0x41, 0x00, 0x09, 0x01, 0x05})
	f.Add(byte(0x30), false, []byte{0xCC, 0x05, 0x30, 0, 0, 0, 1})
	f.Add(byte(0x30), true, []byte{0xD4, 0x05, 0x30, 0, 0, 0, 1})
	f.Add(byte(0x10), false, []byte{0xD8, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, policy byte, associating bool, apdu []byte) {
		policy &= 0x30
		sec := fuzzSecurity(0, policy, associating)
		tr := newSecureTransport(nil, sec, 1)
		tr.associating = associating
		if associating {
			tr.dedKey = bytes.Repeat([]byte{3}, 16)
		}
		_, llcApdu := splitLLC(apdu)
		_, _ = tr.incoming(llcApdu)
		// A second APDU after whatever state the first left behind.
		_, _ = tr.incoming([]byte{0xCC, 0x05, 0x30, 0, 0, 0, 1})
		_, _ = tr.incoming(apdu)
	})
}

// FuzzAARQ covers aarq, which rewrites the AARQ gosem builds. Its input is
// not from the meter, but a bad element length still must not panic.
func FuzzAARQ(f *testing.F) {
	f.Add([]byte{0x60, 0x0C, 0xA1, 0x03, 0x06, 0x01, 0x00, 0xBE, 0x05, 0x04, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x60, 0x05, 0xBE, 0x03, 0x04, 0x05, 0x01})
	f.Fuzz(func(t *testing.T, apdu []byte) {
		tr := newSecureTransport(nil, fuzzSecurity(0, SecAuthentication|SecEncryption, true), 1)
		_, _ = tr.outgoing(apdu)
	})
}

// Regression for docs/hardening-defects.md H-10 (found by FuzzAARQ): an AARQ whose
// user-information element announces a longer initiateRequest than it holds
// sliced out of range. It is refused with an error.
func TestAARQShortInitiateRequestIsRefused(t *testing.T) {
	for _, apdu := range [][]byte{
		{0x60, 0x05, 0xBE, 0x03, 0x04, 0x05, 0x01},
		{0x60, 0x04, 0xBE, 0x02, 0x04, 0x7F},
		{0x60},
	} {
		tr := newSecureTransport(nil, fuzzSecurity(0, SecAuthentication|SecEncryption, true), 1)
		if out, err := tr.outgoing(apdu); err == nil {
			t.Errorf("outgoing(% X) = % X, want an error", apdu, out)
		}
	}
}
