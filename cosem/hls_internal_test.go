package cosem

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The AES-GCM example of the DLMS UA Green Book (security suite 0): system
// title 4D4D4D0000BC614E, invocation counter 01234567, the keys below and
// the plaintext of a GET request.
//
// Covers: SIG-IPE-049
func TestProtectMatchesTheGreenBookExample(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	ak := mustHex(t, "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
	st := mustHex(t, "4D4D4D0000BC614E")
	plain := mustHex(t, "C0010000080000010000FF0200")
	for _, tc := range []struct {
		policy byte
		want   string
	}{
		{SecAuthentication | SecEncryption, "3001234567" + "411312FF935A47566827C467BC" + "7D825C3BE4A77C3FCC056B6B"},
		{SecAuthentication, "1001234567" + "C0010000080000010000FF0200" + "06725D910F9221D263877516"},
		{SecEncryption, "2001234567" + "411312FF935A47566827C467BC"},
	} {
		got, err := Protect(0, tc.policy, key, ak, st, 0x01234567, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, mustHex(t, tc.want)) {
			t.Errorf("policy %#x: %X, want %s", tc.policy, got, tc.want)
		}
		back, ic, err := Unprotect(0, key, ak, st, got)
		if err != nil || ic != 0x01234567 || !bytes.Equal(back, plain) {
			t.Errorf("policy %#x round trip: %X %d %v", tc.policy, back, ic, err)
		}
	}
}

// Covers: SIG-IPE-049
func TestUnprotectRefusesChangedAPDUs(t *testing.T) {
	for _, suite := range []Suite{0, 1, 2} {
		key := bytes.Repeat([]byte{7}, suite.KeyLen())
		ak := bytes.Repeat([]byte{9}, suite.KeyLen())
		st := []byte("SGM\x00\x00\x00\x00\x01")
		for _, policy := range []byte{SecAuthentication, SecAuthentication | SecEncryption} {
			p, err := Protect(suite, policy, key, ak, st, 42, []byte{0xC0, 0x01, 0x41, 0, 3})
			if err != nil {
				t.Fatal(err)
			}
			for i := range p {
				bad := bytes.Clone(p)
				bad[i] ^= 0x01
				if _, _, err := Unprotect(suite, key, ak, st, bad); err == nil {
					t.Errorf("suite %d policy %#x: a change at byte %d was accepted", suite, policy, i)
				}
			}
			if _, _, err := Unprotect(suite, key, ak, []byte("SGM\x00\x00\x00\x00\x02"), p); err == nil {
				t.Errorf("suite %d policy %#x: another sender's system title was accepted", suite, policy)
			}
		}
	}
}

// The HLS-GMAC answer is SC ‖ IC ‖ 12-byte GMAC tag, and any change to it,
// or a different challenge or key, fails verification.
//
// Covers: SIG-IPE-046
func TestGMACAnswerFormatAndTamper(t *testing.T) {
	sec := Security{Suite: 0, Key: mustHex(t, "000102030405060708090A0B0C0D0E0F"), AuthKey: mustHex(t, "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")}
	h := &HLS{Mechanism: MechGMAC, Security: sec}
	meter, ours := mustHex(t, "4D4D4D0000BC614E"), mustHex(t, "53474D0000000001")
	ctos, stoc := []byte("client-challenge"), []byte("P6wRJ21F")
	// The meter's answer to our challenge, as the meter computes it.
	ans, err := h.answer(meter, ours, ctos, stoc, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(ans) != 17 || ans[0] != 0x10 || !bytes.Equal(ans[1:5], []byte{0, 0, 0, 7}) {
		t.Fatalf("answer %X is not SC ‖ IC ‖ 12-byte tag", ans)
	}
	if err := h.check(ours, meter, ctos, stoc, ans); err != nil {
		t.Fatalf("a correct answer does not verify: %v", err)
	}
	for i := range ans {
		bad := bytes.Clone(ans)
		bad[i] ^= 1
		if h.check(ours, meter, ctos, stoc, bad) == nil {
			t.Errorf("a change at byte %d verified", i)
		}
	}
	if h.check(ours, meter, []byte("other-challenge!"), stoc, ans) == nil {
		t.Error("an answer to another challenge verified")
	}
	other := &HLS{Mechanism: MechGMAC, Security: Security{Key: sec.Key, AuthKey: mustHex(t, "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDE")}}
	if other.check(ours, meter, ctos, stoc, ans) == nil {
		t.Error("an answer made with another authentication key verified")
	}
}
