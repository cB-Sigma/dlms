// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/cosem"
)

// Gurux publishes unit tests with hexadecimal vectors only in its Android
// library (Gurux.DLMS.Android, Java/DLMS/src/test, GPL-2.0). They are
// fetched at test time from this commit and never kept here. Of them:
//
//   - GXSymmetricTest: AES-GCM authentication, encryption and
//     authenticated encryption of one GET request (the DLMS UA example
//     data): checked against Protect and Unprotect below. Its key
//     agreement tests have their assertions commented out, so they prove
//     nothing and are not used.
//   - Aes1Test: AES key wrap (RFC 3394 data) used for key transfer:
//     checked against WrapKey and UnwrapKey below.
//   - AccessServiceTest: an ACCESS service request and response (IEC
//     62056-5-3 access, tags 0xD9 and 0xDA): checked against
//     AccessRequest and DecodeAccessResponse below.
const guruxAndroidCommit = "d3489a440b861a534e3226c3fbd1e85643f563b2"

func fetchGurux(t *testing.T, path string) string {
	t.Helper()
	if os.Getenv("SIGMA_DLMS_INTEROP") != "1" {
		t.Skip("fetches Gurux's published test vectors; set SIGMA_DLMS_INTEROP=1 to run")
	}
	url := "https://raw.githubusercontent.com/Gurux/Gurux.DLMS.Android/" + guruxAndroidCommit + "/" + path
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("fetching %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return b
}

// method is the source of one test method, up to the next one.
func method(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "void "+name+"(")
	if i < 0 {
		t.Fatalf("no method %s in the Gurux source", name)
	}
	body := src[i:]
	if j := strings.Index(body[1:], "@Test"); j >= 0 {
		body = body[:j+1]
	}
	return body
}

func TestGuruxVectorsAESGCM(t *testing.T) {
	src := fetchGurux(t, "Java/DLMS/src/test/java/gurux/dlms/secure/GXSymmetricTest.java")
	str := regexp.MustCompile(`String (expected|data) = "([0-9A-F ]+)"`)
	keys := regexp.MustCompile(`hexToBytes\("([0-9A-F]+)"\)`)
	counter := regexp.MustCompile(`SUITE_0,\s*0x([0-9A-F]{8})`)
	for _, tc := range []struct {
		name   string
		policy byte
	}{
		{"authenticationTest", cosem.SecAuthentication},
		{"encryptionTest", cosem.SecEncryption},
		{"authenticatedEncryptionTest", cosem.SecAuthentication | cosem.SecEncryption},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := method(t, src, tc.name)
			v := map[string][]byte{}
			for _, m := range str.FindAllStringSubmatch(body, -1) {
				v[m[1]] = unhex(t, m[2])
			}
			k := keys.FindAllStringSubmatch(body, -1)
			ic := counter.FindStringSubmatch(body)
			if v["expected"] == nil || v["data"] == nil || len(k) < 3 || ic == nil {
				t.Fatalf("the Gurux test is not in the expected form:\n%s", body)
			}
			st, key, ak := unhex(t, k[0][1]), unhex(t, k[1][1]), unhex(t, k[2][1])
			n, _ := strconv.ParseUint(ic[1], 16, 32)
			got, err := cosem.Protect(0, tc.policy, key, ak, st, uint32(n), v["data"])
			if err != nil {
				t.Fatal(err)
			}
			body5 := got[5:] // after SC and IC
			want := v["expected"]
			if tc.policy == cosem.SecAuthentication {
				// Gurux's vector is the tag alone.
				body5 = body5[len(v["data"]):]
			}
			if hex.EncodeToString(body5) != hex.EncodeToString(want) {
				t.Fatalf("Protect: %X, Gurux expects %X", body5, want)
			}
			plain, gotIC, err := cosem.Unprotect(0, key, ak, st, got)
			if err != nil || gotIC != uint32(n) || hex.EncodeToString(plain) != hex.EncodeToString(v["data"]) {
				t.Fatalf("Unprotect: %X ic %X %v", plain, gotIC, err)
			}
			t.Logf("%s: %X", tc.name, want)
		})
	}
}

// AccessServiceTest builds an ACCESS request of two gets (data
// 0.0.96.1.0.255 value, clock time) and two sets (activity calendar
// 0.0.13.0.0.255 attributes 7 and 8, with the values its test gives),
// unconfirmed with invoke ID 1, and parses an ACCESS response. Our encoder
// must give the same octets, our decoder must read both back, and the
// response must decode to two octet strings, two null-data and four
// successes.
func TestGuruxVectorsAccess(t *testing.T) {
	src := fetchGurux(t, "Java/DLMS/src/test/java/gurux/dlms/AccessServiceTest.java")
	req := method(t, src, "accessRequestTest")
	exp := regexp.MustCompile(`String expected =\s*"([0-9A-F]+)"`).FindStringSubmatch(req)
	vals := regexp.MustCompile(`hexToBytes\(\s*"([0-9A-F]+)"\)`).FindAllStringSubmatch(req, -1)
	if exp == nil || len(vals) != 2 {
		t.Fatalf("the Gurux request test is not in the expected form:\n%s", req)
	}
	data := func(s string) *axdr.DlmsData {
		b := unhex(t, s)
		d, err := axdr.NewDataDecoder(&b).Decode(&b)
		if err != nil || len(b) != 0 {
			t.Fatalf("value %s: %v (%d octets left)", s, err, len(b))
		}
		return &d
	}
	items := []cosem.AccessItem{
		{Kind: cosem.AccessGet, Class: 1, OBIS: "0.0.96.1.0.255", ID: 2},
		{Kind: cosem.AccessGet, Class: 8, OBIS: "0.0.1.0.0.255", ID: 2},
		{Kind: cosem.AccessSet, Class: 20, OBIS: "0.0.13.0.0.255", ID: 7, Data: data(vals[0][1])},
		{Kind: cosem.AccessSet, Class: 20, OBIS: "0.0.13.0.0.255", ID: 8, Data: data(vals[1][1])},
	}
	got, err := (&cosem.AccessRequest{InvokeID: 1, Items: items}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != strings.ToLower(exp[1]) {
		t.Fatalf("access request:\n ours  %X\n Gurux %s", got, exp[1])
	}
	back, err := cosem.DecodeAccessRequest(unhex(t, exp[1]))
	if err != nil || back.InvokeID != 1 || len(back.Items) != 4 || back.Items[3].Data == nil {
		t.Fatalf("decoding Gurux's request: %+v %v", back, err)
	}
	again, _ := back.Encode()
	if hex.EncodeToString(again) != strings.ToLower(exp[1]) {
		t.Errorf("request decoded and encoded again: %X", again)
	}

	resp := method(t, src, "accessResponseTest")
	rexp := regexp.MustCompile(`hexToBytes\(\s*"([0-9A-F]+)"\)`).FindStringSubmatch(resp)
	if rexp == nil {
		t.Fatalf("the Gurux response test is not in the expected form:\n%s", resp)
	}
	r, err := cosem.DecodeAccessResponse(unhex(t, rexp[1]))
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []cosem.AccessKind{cosem.AccessGet, cosem.AccessGet, cosem.AccessSet, cosem.AccessSet}
	if len(r.Results) != 4 {
		t.Fatalf("response results %+v", r.Results)
	}
	for i, res := range r.Results {
		if res.Kind != wantKinds[i] || res.Result != 0 {
			t.Errorf("result %d: %v %v", i, res.Kind, res)
		}
	}
	if r.Results[0].Data.Tag != axdr.TagOctetString || r.Results[1].Data.Tag != axdr.TagOctetString ||
		r.Results[2].Data.Tag != axdr.TagNull || r.Results[3].Data.Tag != axdr.TagNull {
		t.Errorf("response data %+v", r.Results)
	}
	t.Logf("serial %v, clock %v", r.Results[0].Data.Value, r.Results[1].Data.Value)
	out, err := r.Encode()
	if err != nil || hex.EncodeToString(out) != strings.ToLower(rexp[1]) {
		t.Errorf("response decoded and encoded again: %X %v", out, err)
	}
}

func TestGuruxVectorsKeyWrap(t *testing.T) {
	src := fetchGurux(t, "Java/DLMS/src/test/java/gurux/dlms/secure/Aes1Test.java")
	re := regexp.MustCompile(`test\(\s*"([0-9A-F]+)",\s*"([0-9A-F]+)",\s*"([0-9A-F]+)"\)`)
	all := re.FindAllStringSubmatch(src, -1)
	if len(all) == 0 {
		t.Fatal("no vectors in the Gurux source")
	}
	for _, m := range all {
		kek, key, want := unhex(t, m[1]), unhex(t, m[2]), unhex(t, m[3])
		got, err := cosem.WrapKey(kek, key)
		if err != nil {
			t.Fatalf("WrapKey(%d-octet KEK, %d-octet key): %v", len(kek), len(key), err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("WrapKey: %X, Gurux expects %X", got, want)
		}
		back, err := cosem.UnwrapKey(kek, want)
		if err != nil || hex.EncodeToString(back) != hex.EncodeToString(key) {
			t.Errorf("UnwrapKey: %X %v", back, err)
		}
	}
	t.Logf("%d key wrap vectors", len(all))
}
