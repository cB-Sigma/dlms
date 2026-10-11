package cosem

import (
	"bytes"
	"testing"
)

// releaseTransport is the association of annex E: ciphered context, the
// E.1 InitiateRequest (with its dedicated key) sent in the AARQ.
func releaseTransport(t *testing.T) *SecureTransport {
	t.Helper()
	return &SecureTransport{
		sec:     Security{Suite: 0, Policy: SecAuthentication | SecEncryption, SystemTitle: vh(t, vecST), Key: vh(t, vecEK), AuthKey: vh(t, vecAK)},
		meterST: vh(t, vecST), initReq: vh(t, vecInitReq), dedKey: vh(t, "00112233445566778899AABBCCDDEEFF"),
		nextIC: vecIC, lastRecvIC: map[bool]uint32{},
	}
}

// Annex E.7 (page 315): the RLRQ of a ciphered association carries the
// protected InitiateRequest; with the example's counter our RLRQ is the
// example byte for byte. The counter it takes is reserved before the
// release, so a caller recording usedIC never hands it out again.
//
// Covers: SIG-IPE-658
func TestIEC6205653AnnexE7CipheredRLRQ(t *testing.T) {
	tr := releaseTransport(t)
	if got := tr.UsedIC(); got != vecIC+1 {
		t.Errorf("usedIC before the release = %#x, want the RLRQ's counter reserved (%#x)", got, vecIC+1)
	}
	got, err := tr.outgoing([]byte{0x62, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	want := vh(t, "6239"+"800100"+"BE340432"+"2130"+"3001234567"+vecInitReqC)
	if !bytes.Equal(got, want) {
		t.Errorf("RLRQ\n got %X\nwant %X", got, want)
	}
	if c, _ := tr.Release(); !c || tr.UsedIC() != vecIC+1 {
		t.Errorf("after the RLRQ: ciphered %v, usedIC %#x", c, tr.UsedIC())
	}
	// An association without a ciphered context releases as gosem built it.
	plain := &SecureTransport{lastRecvIC: map[bool]uint32{}}
	if got, _ := plain.outgoing([]byte{0x62, 0x00}); !bytes.Equal(got, []byte{0x62, 0x00}) {
		t.Errorf("plain RLRQ changed to %X", got)
	}
}

// Annex E.8 (page 316): the RLRE's ciphered InitiateResponse is checked and
// removed before gosem sees the RLRE; one that does not decipher, repeats
// a counter, or answers a release we did not cipher is discarded (6.3).
//
// Covers: SIG-IPE-658
func TestIEC6205653AnnexE8CipheredRLRE(t *testing.T) {
	rlre := vh(t, "6328"+"800100"+"BE230421"+"281F"+"3001234567"+vecInitResC)
	tr := releaseTransport(t)
	if _, err := tr.outgoing([]byte{0x62, 0x00}); err != nil {
		t.Fatal(err)
	}
	got, err := tr.incoming(rlre)
	if err != nil || !bytes.Equal(got, vh(t, "6303800100")) {
		t.Fatalf("RLRE opened to %X, %v", got, err)
	}
	if c, v := tr.Release(); !c || !v {
		t.Errorf("release ciphered %v verified %v", c, v)
	}
	// The same RLRE again repeats the counter.
	if _, err := tr.incoming(rlre); err == nil {
		t.Error("a replayed RLRE was accepted")
	}
	// Any changed byte of the ciphered InitiateResponse.
	for i := 13; i < len(rlre); i++ {
		tr := releaseTransport(t)
		_, _ = tr.outgoing([]byte{0x62, 0x00})
		bad := bytes.Clone(rlre)
		bad[i] ^= 1
		if _, err := tr.incoming(bad); err == nil {
			t.Errorf("an RLRE changed at byte %d was accepted", i)
		}
	}
	// A ciphered RLRE to a release we did not cipher.
	fresh := releaseTransport(t)
	if _, err := fresh.incoming(rlre); err == nil {
		t.Error("a ciphered RLRE was accepted without a ciphered RLRQ")
	}
	// A plain RLRE still releases, but is not verified.
	tr = releaseTransport(t)
	_, _ = tr.outgoing([]byte{0x62, 0x00})
	if got, err := tr.incoming(vh(t, "6303800100")); err != nil || !bytes.Equal(got, vh(t, "6303800100")) {
		t.Errorf("plain RLRE: %X %v", got, err)
	}
	if c, v := tr.Release(); !c || v {
		t.Errorf("plain RLRE after a ciphered RLRQ: ciphered %v verified %v", c, v)
	}
	// With a dedicated key, an authentication-only InitiateResponse is refused.
	tr = releaseTransport(t)
	_, _ = tr.outgoing([]byte{0x62, 0x00})
	p, _ := Protect(0, SecAuthentication, tr.sec.Key, tr.sec.AuthKey, tr.meterST, vecIC+5, vh(t, vecInitRes))
	ui := concat([]byte{0x28}, putLen(len(p)), p)
	if _, err := tr.incoming(encodeTLVs(0x63, []tlv{{0x80, []byte{0}}, {0xBE, concat([]byte{0x04}, putLen(len(ui)), ui)}})); err == nil {
		t.Error("an authentication-only RLRE InitiateResponse was accepted after a dedicated key")
	}
}
