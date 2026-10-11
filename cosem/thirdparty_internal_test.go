package cosem

import (
	"bytes"
	"testing"
)

// tpST is a third party's system title.
var tpST = []byte("TPH\x00\x00\x00\x00\x07")

// General-ciphering with neither authentication nor encryption (Figure
// 32, Table 28 "none"): SC with A and E clear, then the APDU, no counter
// or tag. It is read only for the third party; our own layer must be
// protected, and a compressed, key-set or other-suite one is refused.
// (The third-party exchanges with a simulated meter are tested in the
// dlms-sim module.)
//
// Covers: SIG-IPE-657
func TestGeneralCipheringWithoutProtection(t *testing.T) {
	res := []byte{0xC4, 0x01, 0x41, 0x00, 0x12, 0x5A, 0x0A}
	if got := protectNone(1, res); !bytes.Equal(got, append([]byte{0x01}, res...)) {
		t.Fatalf("protectNone %X", got)
	}
	for _, tc := range []struct {
		content []byte
		ok      bool
	}{
		{protectNone(1, res), true},
		{protectNone(2, res), false},          // another suite
		{append([]byte{0x81}, res...), false}, // compressed, compression off
		{append([]byte{0x41}, res...), false}, // key-set bit
		{append([]byte{0x11}, res...), false}, // authenticated: not a no-protection layer
		{[]byte{0x01}, false},                 // empty
	} {
		got, err := openNone(1, nil, tc.content)
		if (err == nil) != tc.ok || (tc.ok && !bytes.Equal(got, res)) {
			t.Errorf("openNone(%X) = %X, %v", tc.content, got, err)
		}
	}
	meter, us := []byte("LNT\x00\x00\x01\x23\x45"), []byte("SGM\x00\x00\x00\x00\x01")
	tr := &SecureTransport{sec: Security{Suite: 1, Policy: 0x10, SystemTitle: us, Key: bytes.Repeat([]byte{1}, 16), AuthKey: bytes.Repeat([]byte{2}, 16)}, meterST: meter, lastRecvIC: map[bool]uint32{}, txKeys: map[string][]byte{}}
	h := generalHeader{transactionID: []byte{1}, originator: meter, recipient: us}
	g := &generalCiphering{generalHeader: h, content: protectNone(1, res)}
	tr.txKeys["\x01"] = tr.sec.Key
	if _, err := tr.incoming(g.encode()); err == nil {
		t.Error("an unprotected general-ciphering APDU for us was accepted on a protected association")
	}
	// For the third party, inside our protected layer, it is read.
	tr.sec.ThirdParty = &ThirdPartyLayer{systemTitle: tpST}
	inner := (&generalCiphering{generalHeader: generalHeader{transactionID: []byte{2}, originator: meter, recipient: tpST}, content: protectNone(1, res)}).encode()
	gp, err := protectAAD(1, 0x10, tr.sec.Key, tr.sec.AuthKey, meter, 5, inner, h.encode())
	if err != nil {
		t.Fatal(err)
	}
	outer := &generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoIdentified, keyID: KeyGlobalUnicast}, content: gp}
	if got, err := tr.incoming(outer.encode()); err != nil || !bytes.Equal(got, res) {
		t.Errorf("J.3 response: %X %v", got, err)
	}
	// Without our layer it is refused on a protected association.
	if _, err := tr.incoming(inner); err == nil {
		t.Error("the third party's layer alone was accepted on a protected association")
	}
}
