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
//     62056-5-3 access, tags 0xD9 and 0xDA). Our client does not
//     implement the ACCESS service, so they are not decoded.
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
