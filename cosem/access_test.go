// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

import (
	"bytes"
	"encoding/hex"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// An ACCESS request of every kind encodes as laid out in IEC 62056-5-3
// (long invoke ID, date-time, specifications, then the list of data) and
// decodes back; a response round trips the same way.
//
// Covers: SIG-IPE-6462
func TestAccessCodec(t *testing.T) {
	rng := axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrLongUnsigned(1), axdr.CreateAxdrLongUnsigned(2),
		axdr.CreateAxdrLongUnsigned(1), axdr.CreateAxdrLongUnsigned(0)})
	req := &AccessRequest{InvokeID: AccessConfirmed | AccessBreakOnError | 7, Time: bytes.Repeat([]byte{0xFF}, 12), Items: []AccessItem{
		{Kind: AccessGet, Class: 3, OBIS: "1.0.1.8.0.255", ID: 2},
		{Kind: AccessSet, Class: 1, OBIS: "0.0.96.1.1.255", ID: 2, Data: axdr.CreateAxdrOctetString("CAFE")},
		{Kind: AccessAction, Class: 70, OBIS: "0.0.96.3.10.255", ID: 1, Data: axdr.CreateAxdrInteger(0)},
		{Kind: AccessGetWithSelection, Class: 7, OBIS: "1.0.99.1.0.255", ID: 2, Selector: 2, Parameters: rng},
		{Kind: AccessSetWithSelection, Class: 7, OBIS: "1.0.99.1.0.255", ID: 2, Selector: 2, Parameters: rng, Data: &axdr.DlmsData{Tag: axdr.TagNull}},
	}}
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Tag, invoke ID with confirmed and break-on-error, the date-time's length.
	if hex.EncodeToString(b[:6]) != "d9600000070c" {
		t.Errorf("head %X", b[:6])
	}
	if b[0] != TagAccessRequest || b[5] != 12 || b[18] != 5 || b[19] != byte(AccessGet) {
		t.Fatalf("layout %X", b)
	}
	back, err := DecodeAccessRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := back.Encode()
	if err != nil || !bytes.Equal(again, b) {
		t.Fatalf("round trip:\n %X\n %X %v", b, again, err)
	}
	if back.Items[0].Data != nil || back.Items[3].Selector != 2 || back.Items[4].Data == nil {
		t.Errorf("decoded %+v", back.Items)
	}

	resp := &AccessResponse{InvokeID: 7, Results: []AccessResult{
		{Kind: AccessGet, Data: *axdr.CreateAxdrDoubleLongUnsigned(12345)},
		{Kind: AccessSet, Result: 3},
		{Kind: AccessAction},
	}}
	rb, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DecodeAccessResponse(rb)
	if err != nil || len(r2.Results) != 3 || r2.Results[1].Result != 3 || r2.Results[0].Data.Value != uint32(12345) || r2.Results[2].Data.Tag != axdr.TagNull {
		t.Fatalf("response %+v %v", r2, err)
	}
	if r2.Results[1].String() != "read-write denied (3)" {
		t.Errorf("result text %q", r2.Results[1].String())
	}
	for _, bad := range [][]byte{nil, {0xD9}, {0xD9, 0, 0, 0, 1, 0, 1, 9}, b[:len(b)-1], append(append([]byte{}, b...), 0)} {
		if _, err := DecodeAccessRequest(bad); err == nil {
			t.Errorf("malformed request %X decoded", bad)
		}
	}
	if _, err := DecodeAccessResponse(rb[:len(rb)-1]); err == nil {
		t.Error("a truncated response decoded")
	}
}

// Covers: SIG-IPE-6462
func FuzzAccessDecode(f *testing.F) {
	f.Add([]byte{0xD9, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 96, 1, 0, 255, 2, 1, 0})
	f.Add([]byte{0xDA, 0x40, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := DecodeAccessRequest(b); err == nil {
			_, _ = r.Encode()
		}
		if r, err := DecodeAccessResponse(b); err == nil {
			_, _ = r.Encode()
		}
		_, _ = readResponseItem(b)
	})
}

// A short name read response item: data, an error, a data block.
//
// Covers: SIG-IPE-6463
func TestReadResponseItem(t *testing.T) {
	for _, tc := range []struct {
		apdu   string
		choice byte
	}{
		{"0c0100120001", 0},
		{"0c010104", 1},
		{"0c010200000103aabbcc", 2},
	} {
		b, _ := hex.DecodeString(tc.apdu)
		it, err := readResponseItem(b)
		if err != nil || it.choice != tc.choice {
			t.Errorf("%s: %+v %v", tc.apdu, it, err)
		}
	}
	if off, ok := SNMethodOffset(12, 8); !ok || off != 0x58 {
		t.Errorf("association SN method 8 at %#x", off)
	}
	if _, ok := SNMethodOffset(1, 1); ok {
		t.Error("class 1 has no methods")
	}
}
