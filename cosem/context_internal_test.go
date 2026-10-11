// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

import (
	"bytes"
	"testing"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// gosemAARQ is the AARQ gosem builds for HLS-GMAC with our system title:
// it always names the ciphering context.
func gosemAARQ(t *testing.T) []byte {
	t.Helper()
	set, err := gdlms.NewSettingsWithoutAuthentication()
	if err != nil {
		t.Fatal(err)
	}
	set.Authentication, set.Password = gdlms.Authentication(MechGMAC), []byte("0123456789abcdef")
	set.Ciphering.SystemTitle = clientST
	aarq, err := gdlms.EncodeAARQ(&set)
	if err != nil {
		t.Fatal(err)
	}
	return aarq
}

func contextOf(t *testing.T, aarq []byte) byte {
	t.Helper()
	items, err := parseTLVs(aarq[2:])
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.tag == 0xA1 {
			return it.val[len(it.val)-1]
		}
	}
	t.Fatal("no application context name")
	return 0
}

// The application context is selectable: automatic keeps gosem's choice
// (ciphering when our system title is sent), "ln" proposes logical name
// referencing without ciphering for HLS-GMAC with unprotected APDUs (the
// default of Gurux meters, which refuse the ciphering context with
// diagnostic 2), "ln-ciphering" the ciphering context; the rest of the
// AARQ is unchanged.
//
// Covers: SIG-IPE-046
func TestApplicationContextSelectable(t *testing.T) {
	aarq := gosemAARQ(t)
	if c := contextOf(t, aarq); c != ContextLNCiphering {
		t.Fatalf("gosem proposes context %d, want 3", c)
	}
	for _, tc := range []struct {
		setting string
		want    byte
	}{{"", ContextLNCiphering}, {"auto", ContextLNCiphering}, {"ln", ContextLN}, {"ln-ciphering", ContextLNCiphering},
		{"sn", ContextSN}, {"sn-ciphering", ContextSNCiphering}, {"referencing sn", ContextSNCiphering}} {
		cfg := SecurityConfig{Name: "M", Authentication: "hls-gmac", Security: "none", ApplicationContext: tc.setting,
			BlockCipherKey: "000102030405060708090A0B0C0D0E0F", AuthenticationKey: "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"}
		if tc.setting == "referencing sn" {
			// Short names with the automatic context: the next arc of
			// gosem's (3, ciphering), so 4.
			cfg.ApplicationContext, cfg.Referencing = "", "sn"
		}
		h, _, err := cfg.Build()
		if err != nil {
			t.Fatalf("%q: %v", tc.setting, err)
		}
		st := newSecureTransport(nil, h.Security, 1)
		out, err := st.aarq(aarq)
		if err != nil {
			t.Fatalf("%q: %v", tc.setting, err)
		}
		if c := contextOf(t, out); c != tc.want {
			t.Errorf("%q: context %d, want %d", tc.setting, c, tc.want)
		}
		if len(out) != len(aarq) || !bytes.Equal(out[13:], aarq[13:]) {
			t.Errorf("%q: the rest of the AARQ changed:\n%X\n%X", tc.setting, out, aarq)
		}
	}
	// Protected APDUs need the ciphering context; unknown names are refused.
	for _, bad := range []SecurityConfig{
		{Name: "M", Authentication: "hls-gmac", Security: "authenticated", ApplicationContext: "ln",
			BlockCipherKey: "000102030405060708090A0B0C0D0E0F", AuthenticationKey: "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"},
		{Name: "M", Authentication: "low", Password: "x", ApplicationContext: "short"},
		{Name: "M", Authentication: "low", Password: "x", ApplicationContext: "ln", Referencing: "sn"},
		{Name: "M", Authentication: "hls-gmac", Security: "authenticated", ApplicationContext: "sn",
			BlockCipherKey: "000102030405060708090A0B0C0D0E0F", AuthenticationKey: "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"},
	} {
		if _, _, err := bad.Build(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
