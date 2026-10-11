package cosem

import (
	"bytes"
	"fmt"
	"testing"
)

// The system titles of a meter and a client in the tests.
var (
	meterST  = []byte("LNT\x00\x00\x01\x23\x45")
	clientST = []byte("SGM\x00\x00\x00\x00\x01")
)

// A general-ciphering APDU with any changed byte, a changed header field
// or another sender does not open; general-glo/ded APDUs likewise. (The
// general ciphering and signing exchanges with a simulated meter are
// tested in the dlms-sim module.)
//
// Covers: SIG-IPE-067
func TestGeneralCipheringTamper(t *testing.T) {
	for _, suite := range []Suite{0, 1, 2} {
		n := suite.KeyLen()
		sec := Security{Suite: suite, Policy: 0x30, SystemTitle: clientST, Key: bytes.Repeat([]byte{1}, n), AuthKey: bytes.Repeat([]byte{2}, n),
			MasterKey: bytes.Repeat([]byte{3}, n), GeneralKey: GenKeyWrapped}
		h := generalHeader{transactionID: []byte{1, 2, 3, 4, 5, 6, 7, 8}, originator: clientST, recipient: meterST, dateTime: cosemNow(), other: []byte("x")}
		key, ki, err := sec.originatorKey(h)
		if err != nil {
			t.Fatal(err)
		}
		plain := []byte{0xC0, 0x01, 0xC1, 0, 3, 1, 0, 12, 7, 0, 255, 2, 0}
		p, err := protectAAD(suite, 0x30, key, sec.AuthKey, clientST, 9, plain, h.encode())
		if err != nil {
			t.Fatal(err)
		}
		apdu := (&generalCiphering{generalHeader: h, keyInfo: ki, content: p}).encode()
		open := func(b []byte) error {
			g, err := decodeGeneralCiphering(b)
			if err != nil {
				return err
			}
			k, err := sec.recipientKey(g, nil)
			if err != nil {
				return err
			}
			got, _, err := unprotectAAD(suite, k, sec.AuthKey, g.originator, g.content, g.generalHeader.encode())
			if err == nil && !bytes.Equal(got, plain) {
				return fmt.Errorf("opened to %X", got)
			}
			return err
		}
		if err := open(apdu); err != nil {
			t.Fatalf("suite %d: the untouched APDU does not open: %v", suite, err)
		}
		for i := 1; i < len(apdu); i++ {
			bad := bytes.Clone(apdu)
			bad[i] ^= 0x01
			if open(bad) == nil {
				t.Errorf("suite %d: a change at byte %d opened", suite, i)
			}
		}
		// general-glo: another system title does not open.
		p2, _ := Protect(suite, 0x30, sec.Key, sec.AuthKey, clientST, 10, plain)
		st, content, err := decodeGeneralGloDed(encodeGeneralGloDed(TagGeneralGlo, clientST, p2))
		if err != nil || !bytes.Equal(st, clientST) {
			t.Fatalf("general-glo round trip: %v", err)
		}
		if _, _, err := Unprotect(suite, sec.Key, sec.AuthKey, meterST, content); err == nil {
			t.Errorf("suite %d: general-glo content opened under another system title", suite)
		}
	}
}

// Decoding general-ciphering, general-glo/ded and general-signing APDUs
// never panics and never reads past the end.
func FuzzGeneralAPDUs(f *testing.F) {
	h := generalHeader{transactionID: []byte{1}, originator: clientST, recipient: meterST, dateTime: cosemNow()}
	f.Add((&generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoAgreed, params: []byte{1}, data: []byte{9, 9}}, content: []byte{0x30, 0, 0, 0, 1}}).encode())
	f.Add((&generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoWrapped, data: make([]byte, 24)}, content: []byte{1}}).encode())
	f.Add((&generalSigning{generalHeader: h, content: []byte{0xC4}, signature: make([]byte, 64)}).encode())
	f.Add(encodeGeneralGloDed(TagGeneralGlo, clientST, []byte{0x30, 0, 0, 0, 1}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 {
			return
		}
		for _, tag := range []byte{TagGeneralCiphering, TagGeneralSigning, TagGeneralGlo} {
			in := append([]byte{tag}, b[1:]...)
			if g, err := decodeGeneralCiphering(in); err == nil {
				// What decodes re-encodes to something that decodes the same.
				again, err := decodeGeneralCiphering(g.encode())
				if err != nil || !bytes.Equal(again.encode(), g.encode()) {
					t.Errorf("general-ciphering %X does not round trip: %v", in, err)
				}
			}
			_, _ = decodeGeneralSigning(in)
			_, _, _ = decodeGeneralGloDed(in)
		}
	})
}
