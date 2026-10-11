package cosem

import (
	"bytes"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Only unconfirmed set and action requests go out; a confirmed request, a
// request before the AA, and an AA without the broadcast key are refused.
// (Broadcasts to simulated meters are tested in the dlms-sim module.)
//
// Covers: SIG-IPE-660
func TestBroadcastAssociationRefusals(t *testing.T) {
	b := &Broadcaster{Send: func([]byte) error { return nil }, Security: Security{Policy: 0x30, SystemTitle: []byte("SGM\x00\x00\x00\x00\x01"), Key: bytes.Repeat([]byte{1}, 16)}}
	if err := b.Associate(); err == nil {
		t.Error("a broadcast AA without the broadcast key was opened")
	}
	b.Security.BroadcastKey = bytes.Repeat([]byte{3}, 16)
	confirmed, _ := gdlms.CreateSetRequestNormal(0x41, *gdlms.CreateAttributeDescriptor(1, "0.0.96.14.0.255", 2), nil, *axdr.CreateAxdrUnsigned(2)).Encode()
	if err := b.Request(confirmed); err == nil {
		t.Error("a request was sent before the AA")
	}
	var sent [][]byte
	b.Send = func(a []byte) error { sent = append(sent, a); return nil }
	if err := b.Associate(); err != nil {
		t.Fatal(err)
	}
	if err := b.Request(confirmed); err == nil {
		t.Error("a confirmed request was broadcast")
	}
	get, _ := gdlms.CreateGetRequestNormal(InvokeUnconfirmed, *gdlms.CreateAttributeDescriptor(1, "0.0.96.14.0.255", 2), nil).Encode()
	if err := b.Request(get); err == nil {
		t.Error("a get request was broadcast")
	}
	// The AARQ proposes response-allowed FALSE under the broadcast key,
	// and names no responding party.
	aarq := sent[0]
	items, _ := parseTLVs(aarq[2:])
	var ui []byte
	for _, it := range items {
		if it.tag == 0xBE {
			ui = it.val
		}
	}
	if len(ui) < 5 || ui[2] != 0x21 || ui[4]&SecBroadcastKey == 0 {
		t.Fatalf("user-information %X", ui)
	}
	plain, _, err := UnprotectKeys(0, nil, b.Security.BroadcastKey, nil, b.Security.SystemTitle, ui[4:], nil)
	if err != nil || !bytes.Equal(plain[:4], []byte{0x01, 0x00, 0x01, 0x00}) {
		t.Errorf("initiate request %X %v: want no dedicated key and response-allowed FALSE", plain, err)
	}
}
