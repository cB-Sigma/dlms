// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/server"
)

// gpki is the key material of a client and server pair for general
// ciphering and signing, and a third party.
type gpki struct {
	serverSign, serverKA, clientSign, clientKA, tpSign, tpKA *ecdsa.PrivateKey
}

func newGPKI(t *testing.T, suite int) gpki {
	c := elliptic.P256()
	if suite == 2 {
		c = elliptic.P384()
	}
	return gpki{ecKey(t, c), ecKey(t, c), ecKey(t, c), ecKey(t, c), ecKey(t, c), ecKey(t, c)}
}

var (
	master16 = bytes.Repeat([]byte{0x55}, 16)
	master32 = bytes.Repeat([]byte{0x66}, 32)
	tpST     = []byte("TPHEAD01")
)

// generalMeter is a server with one HLS-GMAC client (address 48) in the
// suite and policy given, with every general-ciphering key and signing.
func generalMeter(t *testing.T, suite int, policy byte, k gpki, configure func(*server.Association)) (*server.Server, string) {
	t.Helper()
	key, ak, master := key16, ak16, master16
	if suite == 2 {
		key, ak, master = key32, ak32, master32
	}
	s := meter(t, 30, nil, false)
	a := &server.Association{ClientAddress: 48, Mechanism: 5, Policy: policy, Suite: byte(suite), Key: key, AuthKey: ak,
		MasterKey: master}
	if suite != 0 {
		a.SigningKey, a.ClientKey = k.serverSign, &k.clientSign.PublicKey
		a.KAKey, a.ClientKAKey = k.serverKA, &k.clientKA.PublicKey
	}
	if configure != nil {
		configure(a)
	}
	s.Associations = []*server.Association{{ClientAddress: 16}, a}
	return s, listen(t, s, overWrapper)
}

func generalSecurity(t *testing.T, suite int, policy byte, k gpki) cosem.SecurityConfig {
	hx := hex.EncodeToString
	key, ak, master := key16, ak16, master16
	if suite == 2 {
		key, ak, master = key32, ak32, master32
	}
	sec := map[byte]string{0x10: "authenticated", 0x20: "encrypted", 0x30: "authenticated-encrypted"}[policy]
	c := cosem.SecurityConfig{Authentication: "hls-gmac", Security: sec, Suite: suite, BlockCipherKey: hx(key), AuthenticationKey: hx(ak),
		MasterKey: hx(master)}
	if suite != 0 {
		c.SigningKey, c.MeterSigningKey = privPEM(t, k.clientSign), pubPEM(t, &k.serverSign.PublicKey)
		c.KeyAgreementKey, c.MeterKAKey = privPEM(t, k.clientKA), pubPEM(t, &k.serverKA.PublicKey)
	}
	return c
}

// Every general-ciphering key-info (identified, wrapped, one-pass and
// static agreed keys) in each suite and policy it applies to, with and
// without general signing: the server opens each request, answers under a
// fresh key of the same kind, and our client reads a register and a
// profile in blocks through it.
//
// Covers: SIG-IPE-067, SIG-IPE-068
func TestGeneralCiphering(t *testing.T) {
	for _, suite := range []int{0, 1, 2} {
		k := newGPKI(t, suite)
		for _, policy := range []byte{0x10, 0x20, 0x30} {
			keys := []string{"identified", "wrapped"}
			if suite != 0 {
				keys = append(keys, "agreed-one-pass", "agreed-static")
			}
			for _, gk := range keys {
				for _, signing := range []bool{false, true} {
					if signing && suite == 0 {
						continue
					}
					t.Run(fmt.Sprintf("suite%d/policy%x/%s/signed=%v", suite, policy, gk, signing), func(t *testing.T) {
						s, addr := generalMeter(t, suite, policy, k, func(a *server.Association) { a.Signing = signing })
						sec := generalSecurity(t, suite, policy, k)
						sec.Ciphering, sec.GeneralKey, sec.Signing = "general", gk, signing
						for i := 0; i < 2; i++ {
							c := connect(t, overWrapper, addr, 48, sec)
							readRegister(t, c)
							if _, err := c.Get(7, profileLN, 2); err != nil {
								t.Fatalf("profile: %v", err)
							}
							c.Close()
						}
						st := s.Stats()
						if st.GeneralCiphering < 4 || st.GeneralGlo+st.GeneralDed+st.ServiceSpecific != 0 {
							t.Errorf("forms seen %+v", st)
						}
						if signing && (st.Signed < 4 || st.BadSignatures != 0) {
							t.Errorf("signed %d, refused %d", st.Signed, st.BadSignatures)
						}
					})
				}
			}
		}
	}
}

// With signing required, an unsigned client is refused; a client signing
// with a key the server does not trust is refused; a general-ciphering
// request under a master key the server does not hold does not open.
//
// Covers: SIG-IPE-068
func TestGeneralRefusals(t *testing.T) {
	k := newGPKI(t, 1)
	_, addr := generalMeter(t, 1, 0x30, k, func(a *server.Association) { a.Signing = true })
	sec := generalSecurity(t, 1, 0x30, k)
	sec.Ciphering = "general-glo"
	if _, err := tryConnect(overWrapper, addr, 48, sec); err == nil {
		t.Error("an unsigned client was served with signing required")
	}

	other := newGPKI(t, 1)
	s, addr := generalMeter(t, 1, 0x30, k, func(a *server.Association) { a.ClientKey = &other.clientSign.PublicKey })
	sec = generalSecurity(t, 1, 0x30, k)
	sec.Ciphering, sec.Signing = "general-glo", true
	if _, err := tryConnect(overWrapper, addr, 48, sec); err == nil {
		t.Error("a client signing with an untrusted key was served")
	}
	if s.Stats().BadSignatures == 0 {
		t.Error("no signature refused")
	}

	_, addr = generalMeter(t, 1, 0x30, k, func(a *server.Association) { a.MasterKey = bytes.Repeat([]byte{0x77}, 16) })
	sec = generalSecurity(t, 1, 0x30, k)
	sec.Ciphering, sec.GeneralKey = "general", "wrapped"
	if _, err := tryConnect(overWrapper, addr, 48, sec); err == nil {
		t.Error("a key wrapped under another master key opened")
	}

	// Settings the server cannot serve.
	bad := &server.Server{SystemTitle: serverST, Associations: []*server.Association{{ClientAddress: 48, Mechanism: 5, Policy: 0x30,
		Key: key16, AuthKey: ak16, Signing: true}}}
	if _, err := bad.ListenWrapper("127.0.0.1:0"); err == nil {
		_ = bad.Close()
		t.Error("signing without keys was accepted")
	}
}

// V.44 compression on the server side: compressed requests in general-glo,
// general-ded and general ciphering are decompressed, and with
// CompressAnswers the answers are compressed; a server without the
// setting refuses compressed requests.
//
// Covers: SIG-IPE-659
func TestServerCompression(t *testing.T) {
	big := &cosem.Compression{Enabled: true, CompressRequests: true}
	for _, suite := range []int{1, 2} {
		k := newGPKI(t, suite)
		for _, form := range []string{"general-glo", "general-ded", "general"} {
			t.Run(fmt.Sprintf("suite%d/%s", suite, form), func(t *testing.T) {
				s, addr := generalMeter(t, suite, 0x30, k, func(a *server.Association) {
					a.Compression, a.CompressAnswers = big, true
				})
				// A long repetitive value compresses well both ways.
				if o, ok := s.Object(1, bigLN); ok {
					_ = o.Set(2, axdr.CreateAxdrOctetString(hex.EncodeToString(bytes.Repeat([]byte("ABCD"), 60))), nil)
				}
				sec := generalSecurity(t, suite, 0x30, k)
				sec.Ciphering, sec.DedicatedKey, sec.Compression = form, form == "general-ded", big
				c := connect(t, overWrapper, addr, 48, sec)
				v, err := c.Get(1, bigLN, 2)
				if err != nil {
					t.Fatal(err)
				}
				if s, _ := v.Value.(string); len(s) != 480 {
					t.Fatalf("value %v", v.Value)
				}
				// A long SET is compressed on the way in.
				if err := c.Association().Client.SetRequest(gdlms.CreateAttributeDescriptor(1, bigLN, 2), axdr.CreateAxdrOctetString(hex.EncodeToString(bytes.Repeat([]byte("WXYZ"), 50)))); err != nil {
					t.Fatal(err)
				}
				if s.Stats().Compressed == 0 {
					t.Error("no compressed request was decompressed")
				}
			})
		}
	}
	k := newGPKI(t, 1)
	_, addr := generalMeter(t, 1, 0x30, k, nil)
	sec := generalSecurity(t, 1, 0x30, k)
	sec.Ciphering, sec.Compression = "general-glo", big
	c := connect(t, overWrapper, addr, 48, sec)
	if err := c.Association().Client.SetRequest(gdlms.CreateAttributeDescriptor(1, bigLN, 2), axdr.CreateAxdrOctetString(hex.EncodeToString(bytes.Repeat([]byte("WXYZ"), 50)))); err == nil {
		t.Error("a compressed request was taken by a server without compression")
	}
}

// Third-party layers on the server (annex J): a request the third party
// signed, ciphered with an agreed key, or both, inside the client's
// general-glo, general-ded or general ciphering; the answer carries the
// server's layers for the third party inside the client's, or an
// unprotected layer (J.3).
//
// Covers: SIG-IPE-664
func TestServerThirdParty(t *testing.T) {
	type tc struct {
		ciphering, key string
		tpSecurity     string
		tpKey          string
		signed         bool
	}
	var cases []tc
	for _, signed := range []bool{true, false} {
		cases = append(cases,
			tc{"general", "identified", "", "", signed},
			tc{"general", "agreed-one-pass", "", "", signed},
			tc{"general-glo", "", "", "", signed},
			tc{"general-ded", "", "", "", signed},
			tc{"general-glo", "", "authenticated-encrypted", "agreed-one-pass", signed},
			tc{"general", "identified", "authenticated", "agreed-static", signed},
		)
	}
	for _, suite := range []int{1, 2} {
		k := newGPKI(t, suite)
		ak := ak16
		if suite == 2 {
			ak = ak32
		}
		for _, c := range cases {
			name := fmt.Sprintf("suite%d/%s/%s/tp-%s-%s/signedAnswers=%v", suite, c.ciphering, c.key, c.tpSecurity, c.tpKey, c.signed)
			t.Run(name, func(t *testing.T) {
				s, addr := generalMeter(t, suite, 0x30, k, func(a *server.Association) {
					a.ThirdParties = []cosem.ResponderThirdParty{{SystemTitle: tpST, SignKey: &k.tpSign.PublicKey,
						KAKey: &k.tpKA.PublicKey, AuthKey: ak, SignAnswers: c.signed}}
				})
				sec := generalSecurity(t, suite, 0x30, k)
				sec.Ciphering, sec.GeneralKey, sec.DedicatedKey = c.ciphering, c.key, c.ciphering == "general-ded"
				signed := c.signed
				ciphered := c.tpSecurity != ""
				sec.ThirdParty = &cosem.ThirdParty{SystemTitle: hex.EncodeToString(tpST), SigningKey: privPEM(t, k.tpSign),
					Security: c.tpSecurity, GeneralKey: c.tpKey, KeyAgreementKey: privPEM(t, k.tpKA),
					SignedResponses: &signed, CipheredResponses: &ciphered}
				if c.tpSecurity != "" {
					sec.ThirdParty.AuthenticationKey = hex.EncodeToString(ak)
				}
				cl := connect(t, overWrapper, addr, 48, sec)
				readRegister(t, cl)
				if st := s.Stats(); st.ThirdParty < 2 || st.BadSignatures != 0 {
					t.Errorf("third-party requests %d, refused %d", st.ThirdParty, st.BadSignatures)
				}
			})
		}
	}
	// A third party the server does not know is refused.
	k := newGPKI(t, 1)
	other := newGPKI(t, 1)
	_, addr := generalMeter(t, 1, 0x30, k, func(a *server.Association) {
		a.ThirdParties = []cosem.ResponderThirdParty{{SystemTitle: tpST, SignKey: &other.tpSign.PublicKey}}
	})
	sec := generalSecurity(t, 1, 0x30, k)
	sec.Ciphering = "general-glo"
	no := false
	sec.ThirdParty = &cosem.ThirdParty{SystemTitle: hex.EncodeToString(tpST), SigningKey: privPEM(t, k.tpSign), SignedResponses: &no}
	if c, err := tryConnect(overWrapper, addr, 48, sec); err == nil {
		if _, err := c.Get(3, registerLN, 2); err == nil {
			t.Error("a request signed by an unknown key for the third party was answered")
		}
		c.Close()
	}
}
