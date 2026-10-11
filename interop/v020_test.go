// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
	"github.com/cB-Sigma/dlms/wrapper"
)

// snConnect opens a short name association with the Gurux example's
// short name server (HDLC on 4060, the wrapper on 4062).
func snConnect(t *testing.T, s *server, l link, client int, sec cosem.SecurityConfig) *cosem.Client {
	t.Helper()
	sec.Name, sec.Referencing = "gurux-sn", "sn"
	h, _, err := sec.Build()
	if err != nil {
		t.Fatal(err)
	}
	tr := func(c int) (gdlms.Transport, error) {
		if l == overWrapper {
			w, err := wrapper.New("tcp", s.snWrapper, c, 1, 10*time.Second)
			if err != nil {
				return nil, err
			}
			return counting{w}, nil
		}
		line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", s.snHDLC, 5*time.Second) }})
		if err != nil {
			return nil, err
		}
		return hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(1, 0, 1)})
	}
	c := cosem.NewClient(cosem.ClientConfig{Transport: tr, ClientAddress: client, HLS: h, Password: []byte(sec.Password),
		Timeout: 20 * time.Second, Name: "gurux-sn", Where: l.String()})
	if err := c.Connect(); err != nil {
		t.Fatalf("short name association of client %d over the %s: %v", client, l, err)
	}
	t.Cleanup(c.Close)
	return c
}

// Short name referencing against Gurux's short name server: the object
// list, the logical device name, the clock, a register with its scaler,
// the profile's columns and its whole buffer (data blocks), with
// low-level security and HLS mechanism 2.
func TestShortNamesAgainstGurux(t *testing.T) {
	s := needPeer(t)
	for _, l := range []link{overWrapper, overHDLC} {
		for _, sec := range []cosem.SecurityConfig{
			{Authentication: "low", Password: "Gurux"},
			{Authentication: "hls-aes", Password: guruxHLSKey},
		} {
			t.Run(l.String()+"/"+sec.Authentication, func(t *testing.T) {
				c := snConnect(t, s, l, 17, sec)
				a := c.Association()
				if err := a.ReadObjectListSN(); err != nil {
					t.Fatal(err)
				}
				base, err := a.BaseName(1, ldn)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("logical device name at base name %#04x: %q", base, readText(t, c, ldn))
				readClock(t, c)
				readRegister(t, c)
				pb, err := a.BaseName(7, profile)
				if err != nil {
					t.Fatal(err)
				}
				cols, err := a.ReadSN(pb + 2*8)
				if err != nil {
					t.Fatalf("capture objects: %v", err)
				}
				if parsed, err := cosem.ParseCaptureObjects(cols, profile); err != nil || len(parsed) != 2 {
					t.Fatalf("capture objects %v %v", parsed, err)
				}
				before := sent.Load()
				v, err := a.ReadSN(pb + 8)
				if err != nil {
					t.Fatalf("buffer: %v", err)
				}
				rows, _ := v.Value.([]*axdr.DlmsData)
				t.Logf("whole buffer: %d rows in %d requests", len(rows), sent.Load()-before)
				if len(rows) < 1000 {
					t.Errorf("buffer of %d rows", len(rows))
				}
			})
		}
	}
}

// The ACCESS service against Gurux's logical name server: three gets in
// one request (Gurux's server answers gets; it acknowledges sets and
// actions without doing them, so they are not checked here). The
// example offers ACCESS to clients 18 to 24 (not to 16 and 17): client
// 18 with HLS mechanism 2, and client 21 with HLS-GMAC and authenticated
// and encrypted APDUs, where ACCESS travels in general-glo-ciphering.
func TestAccessAgainstGurux(t *testing.T) {
	s := needPeer(t)
	t.Run("hls-aes", func(t *testing.T) {
		accessGurux(t, connect(t, s, overWrapper, 18, cosem.SecurityConfig{Authentication: "hls-aes", Password: guruxHLSKey}, ""))
	})
	t.Run("hls-gmac-ciphered", func(t *testing.T) {
		accessGurux(t, connect(t, s, overWrapper, 21, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted",
			BlockCipherKey: hex.EncodeToString(s.bk), AuthenticationKey: hex.EncodeToString(s.ak)}, ""))
	})
}

func accessGurux(t *testing.T, c *cosem.Client) {
	t.Helper()
	res, err := c.Access(
		cosem.AccessItem{Kind: cosem.AccessGet, Class: 1, OBIS: ldn, ID: 2},
		cosem.AccessItem{Kind: cosem.AccessGet, Class: 8, OBIS: clockLN, ID: 2},
		cosem.AccessItem{Kind: cosem.AccessGet, Class: 3, OBIS: register, ID: 3},
	)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r.Result != 0 {
			t.Errorf("item %d: %v", i, r)
		}
	}
	name, _ := cosem.Readable(res[0].Data, time.UTC, false).(string)
	if !strings.HasPrefix(name, "GRX") {
		t.Errorf("logical device name %q", name)
	}
	if _, _, err := cosem.ScalerUnit(res[2].Data); err != nil {
		t.Errorf("scaler_unit: %v", err)
	}
	t.Logf("access: %q, clock %v, scaler_unit %v", name, res[1].Data.Value, res[2].Data.Value)
}

// connectConf is connect with a proposed conformance block.
func connectConf(t *testing.T, s *server, client int, sec cosem.SecurityConfig, conf uint32) *cosem.Client {
	t.Helper()
	sec.Name = "gurux"
	h, _, err := sec.Build()
	if err != nil {
		t.Fatal(err)
	}
	c := cosem.NewClient(cosem.ClientConfig{Transport: func(c int) (gdlms.Transport, error) {
		return wrapper.New("tcp", s.wrapper, c, 1, 10*time.Second)
	}, ClientAddress: client, HLS: h, Timeout: 20 * time.Second, Name: "gurux", Where: "wrapper", Conformance: conf,
		InvocationCounter: &cosem.FrameCounterObject{OBIS: "0.0.43.1.8.255"}})
	if err := c.Connect(); err != nil {
		t.Fatalf("association of client %d: %v", client, err)
	}
	t.Cleanup(c.Close)
	return c
}

// Security suite 1 and general ciphering against Gurux's server: client
// 22 (HLS-SHA256) with the example's suite 1 security setup, and client
// 21 (HLS-GMAC, suite 0) in general-glo ciphering and with a dedicated key
// (general protection proposed); each reads the clock and a register.
func TestSuite1AndGeneralCipheringAgainstGurux(t *testing.T) {
	s := needPeer(t)
	keys := func(sec cosem.SecurityConfig) cosem.SecurityConfig {
		sec.Security, sec.BlockCipherKey, sec.AuthenticationKey = "authenticated-encrypted", hex.EncodeToString(s.bk), hex.EncodeToString(s.ak)
		return sec
	}
	conf := cosem.ConformanceGet | cosem.ConformanceSet | cosem.ConformanceAction | cosem.ConformanceSelectiveAccess |
		cosem.ConformanceBlockGetOrRead | cosem.ConformanceBlockSetOrWrite | cosem.ConformanceGeneralProtection
	for _, tc := range []struct {
		name   string
		client int
		sec    cosem.SecurityConfig
	}{
		{"suite 1 hls-sha256", 22, keys(cosem.SecurityConfig{Authentication: "hls-sha256", Password: "Gurux", Suite: 1})},
		{"suite 0 general-glo", 21, keys(cosem.SecurityConfig{Authentication: "hls-gmac", Ciphering: "general-glo"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := connectConf(t, s, tc.client, tc.sec, conf)
			readClock(t, c)
			readRegister(t, c)
		})
	}
	// A dedicated key: the association (the key in the ciphered initiate
	// request, HLS passes 3 and 4 under the global key) is accepted; the
	// example then answers requests ciphered under the dedicated key
	// (ded-get or general-ded) with exception 1/2, so reads under it are
	// logged, not checked, here (they are checked against Gurux's Python
	// client and our server, and against dlms-sim).
	for _, tc := range []struct {
		name string
		sec  cosem.SecurityConfig
	}{
		{"dedicated key associates", keys(cosem.SecurityConfig{Authentication: "hls-gmac", DedicatedKey: true})},
		{"general-ded associates", keys(cosem.SecurityConfig{Authentication: "hls-gmac", Ciphering: "general-ded", DedicatedKey: true})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := connectConf(t, s, 21, tc.sec, conf)
			if _, err := c.Get(8, clockLN, 2); err != nil {
				t.Logf("a read under the dedicated key: %v", err)
			}
		})
	}
}
