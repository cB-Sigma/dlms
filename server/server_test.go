// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
	"github.com/cB-Sigma/dlms/server"
	"github.com/cB-Sigma/dlms/wrapper"
)

var (
	serverST = []byte("SGMSRV01")
	key16    = bytes.Repeat([]byte{0x11}, 16)
	ak16     = bytes.Repeat([]byte{0x22}, 16)
	key32    = bytes.Repeat([]byte{0x33}, 32)
	ak32     = bytes.Repeat([]byte{0x44}, 32)
	hlsKey   = []byte("0123456789ABCDEF")
)

const (
	registerLN = "1.0.32.7.0.255"
	clockLN    = "0.0.1.0.0.255"
	serialLN   = "0.0.96.1.0.255"
	bigLN      = "0.0.96.1.1.255"
	profileLN  = "1.0.99.1.0.255"
	relayLN    = "0.0.96.3.10.255"
	icLN       = "0.0.43.1.0.255"
)

type keys struct {
	clientSign, serverSign *ecdsa.PrivateKey
}

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func privPEM(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
}

func pubPEM(t *testing.T, k *ecdsa.PublicKey) string {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// meter is a server with a register, the clock, two data objects, a
// profile of rows hourly entries, a disconnect control and an invocation
// counter object.
func meter(t *testing.T, rows int, k *keys, sn bool) *server.Server {
	t.Helper()
	loc := time.UTC
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, loc)
	reg := &classes.Register{LN: registerLN, Value: axdr.CreateAxdrLongUnsigned(23050), Scaler: -2, Unit: 35}
	clk := &classes.Clock{LN: clockLN, Location: loc}
	prof := &classes.ProfileGeneric{LN: profileLN, Location: loc, CapturePeriod: 3600,
		CaptureObjects: []classes.CaptureObject{{Class: 8, LN: clockLN, Attr: 2}, {Class: 3, LN: registerLN, Attr: 2}}}
	for i := 0; i < rows; i++ {
		prof.Buffer = append(prof.Buffer, []*axdr.DlmsData{
			axdr.CreateAxdrOctetString(hex.EncodeToString(classes.DateTime(start.Add(time.Duration(i)*time.Hour), loc))),
			axdr.CreateAxdrLongUnsigned(uint16(i)),
		})
	}
	s := &server.Server{SystemTitle: serverST, ShortNames: sn}
	s.Add(reg, clk, prof,
		&classes.Data{LN: serialLN, Value: axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("SGM0001")))},
		&classes.Data{LN: bigLN, Value: axdr.CreateAxdrOctetString("")},
		&classes.Data{LN: icLN, Value: axdr.CreateAxdrDoubleLongUnsigned(0)},
		&classes.DisconnectControl{LN: relayLN, OutputState: true, ControlState: 1, ControlMode: 1})
	s.Associations = []*server.Association{
		{ClientAddress: 16},
		{ClientAddress: 32, Mechanism: 1, Secret: []byte("ABCDEFGH")},
		{ClientAddress: 33, Mechanism: 2, Secret: hlsKey},
		{ClientAddress: 34, Mechanism: 3, Secret: []byte("md5secret")},
		{ClientAddress: 35, Mechanism: 4, Secret: []byte("sha1secret")},
		{ClientAddress: 36, Mechanism: 6, Secret: []byte("sha256secret")},
		{ClientAddress: 47, Mechanism: 5, Policy: 0x30, Key: key16, AuthKey: ak16, InvocationCounter: icLN},
		{ClientAddress: 48, Mechanism: 5, Policy: 0x30, Key: key16, AuthKey: ak16},
		{ClientAddress: 49, Mechanism: 5, Policy: 0x30, Suite: 1, Key: key16, AuthKey: ak16},
		{ClientAddress: 50, Mechanism: 5, Policy: 0x30, Suite: 2, Key: key32, AuthKey: ak32},
		{ClientAddress: 51, Mechanism: 5, Policy: 0x10, Key: key16, AuthKey: ak16},
		{ClientAddress: 52, Mechanism: 1, Secret: []byte("ABCDEFGH"), Policy: 0x20, Key: key16, AuthKey: ak16},
		{ClientAddress: 64, Mechanism: 1, Secret: []byte("READONLY"), Allow: func(class uint16, ln string, id int8, op server.Op) bool {
			return op == server.OpRead
		}},
	}
	if k != nil {
		s.Associations = append(s.Associations, &server.Association{ClientAddress: 53, Mechanism: 7, Policy: 0x30, Suite: 1,
			Key: key16, AuthKey: ak16, SigningKey: k.serverSign, ClientKey: &k.clientSign.PublicKey})
	}
	s.Logf = func(f string, a ...any) { t.Logf("server: "+f, a...) }
	return s
}

type link int

const (
	overWrapper link = iota
	overHDLC
	overUDP
)

func (l link) String() string { return [...]string{"wrapper", "HDLC", "UDP"}[l] }

func listen(t *testing.T, s *server.Server, l link) string {
	t.Helper()
	var addr string
	var err error
	switch l {
	case overWrapper:
		addr, err = s.ListenWrapper("127.0.0.1:0")
	case overHDLC:
		addr, err = s.ListenHDLC("127.0.0.1:0")
	case overUDP:
		addr, err = s.ListenUDP("127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return addr
}

func transport(l link, addr string) func(int) (gdlms.Transport, error) {
	return func(c int) (gdlms.Transport, error) {
		switch l {
		case overHDLC:
			line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 5*time.Second) }})
			if err != nil {
				return nil, err
			}
			return hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(1, 0, 1)})
		case overUDP:
			return wrapper.New("udp", addr, c, 1, 5*time.Second)
		}
		return wrapper.New("tcp", addr, c, 1, 5*time.Second)
	}
}

func connect(t *testing.T, l link, addr string, client int, sec cosem.SecurityConfig) *cosem.Client {
	t.Helper()
	c, err := tryConnect(l, addr, client, sec)
	if err != nil {
		t.Fatalf("client %d over %v: %v", client, l, err)
	}
	t.Cleanup(c.Close)
	return c
}

func tryConnect(l link, addr string, client int, sec cosem.SecurityConfig) (*cosem.Client, error) {
	sec.Name = "server"
	h, _, err := sec.Build()
	if err != nil {
		return nil, err
	}
	cfg := cosem.ClientConfig{Transport: transport(l, addr), ClientAddress: client, HLS: h, Password: []byte(sec.Password),
		Timeout: 5 * time.Second, Name: "server", Where: l.String()}
	c := cosem.NewClient(cfg)
	return c, c.Connect()
}

func readRegister(t *testing.T, c *cosem.Client) {
	t.Helper()
	v, err := c.Get(3, registerLN, 2)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n, _ := cosem.Number(v); n != 23050 {
		t.Fatalf("register value %v", v.Value)
	}
	su, err := c.Get(3, registerLN, 3)
	if err != nil {
		t.Fatal(err)
	}
	if sc, unit, err := cosem.ScalerUnit(su); err != nil || sc != -2 || unit != 35 {
		t.Fatalf("scaler_unit %d %d %v", sc, unit, err)
	}
}

// Every authentication mechanism and security suite, over the wrapper
// on TCP and UDP and over HDLC: the association opens and a register is
// read.
//
// Covers: SIG-IPE-6461
func TestAssociations(t *testing.T) {
	k := &keys{clientSign: ecKey(t, elliptic.P256()), serverSign: ecKey(t, elliptic.P256())}
	hx := hex.EncodeToString
	cases := []struct {
		name   string
		client int
		sec    cosem.SecurityConfig
	}{
		{"none", 16, cosem.SecurityConfig{Authentication: "none"}},
		{"low", 32, cosem.SecurityConfig{Authentication: "low", Password: "ABCDEFGH"}},
		{"hls-aes", 33, cosem.SecurityConfig{Authentication: "hls-aes", Password: string(hlsKey)}},
		{"hls-md5", 34, cosem.SecurityConfig{Authentication: "hls-md5", Password: "md5secret"}},
		{"hls-sha1", 35, cosem.SecurityConfig{Authentication: "hls-sha1", Password: "sha1secret"}},
		{"hls-sha256", 36, cosem.SecurityConfig{Authentication: "hls-sha256", Password: "sha256secret"}},
		{"gmac suite 0", 48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}},
		{"gmac suite 0 dedicated", 48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16), DedicatedKey: true}},
		{"gmac suite 0 general-glo", 48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16), Ciphering: "general-glo"}},
		{"gmac suite 0 general-ded", 48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16), DedicatedKey: true, Ciphering: "general-ded"}},
		{"gmac suite 1", 49, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", Suite: 1, BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}},
		{"gmac suite 2", 50, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", Suite: 2, BlockCipherKey: hx(key32), AuthenticationKey: hx(ak32)}},
		{"gmac authenticated only", 51, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}},
		{"low encrypted", 52, cosem.SecurityConfig{Authentication: "low", Password: "ABCDEFGH", Security: "encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}},
		{"ecdsa suite 1", 53, cosem.SecurityConfig{Authentication: "hls-ecdsa", Security: "authenticated-encrypted", Suite: 1, BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16),
			SigningKey: privPEM(t, k.clientSign), MeterSigningKey: pubPEM(t, &k.serverSign.PublicKey)}},
	}
	for _, l := range []link{overWrapper, overHDLC, overUDP} {
		s := meter(t, 4, k, false)
		addr := listen(t, s, l)
		for _, tc := range cases {
			t.Run(l.String()+"/"+tc.name, func(t *testing.T) {
				c := connect(t, l, addr, tc.client, tc.sec)
				readRegister(t, c)
			})
		}
	}
}

// Wrong secrets, keys and unknown clients are refused; a replayed
// invocation counter is refused.
//
// Covers: SIG-IPE-6461
func TestRefusals(t *testing.T) {
	s := meter(t, 4, nil, false)
	addr := listen(t, s, overWrapper)
	hx := hex.EncodeToString
	for name, tc := range map[string]struct {
		client int
		sec    cosem.SecurityConfig
	}{
		"wrong password":       {32, cosem.SecurityConfig{Authentication: "low", Password: "WRONGPWD"}},
		"wrong HLS secret":     {33, cosem.SecurityConfig{Authentication: "hls-aes", Password: "FEDCBA9876543210"}},
		"wrong key":            {48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(ak16), AuthenticationKey: hx(ak16)}},
		"wrong mechanism":      {48, cosem.SecurityConfig{Authentication: "low", Password: "x"}},
		"unknown client":       {99, cosem.SecurityConfig{Authentication: "none"}},
		"plain where ciphered": {48, cosem.SecurityConfig{Authentication: "hls-gmac", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := tryConnect(overWrapper, addr, tc.client, tc.sec)
			if err == nil {
				c.Close()
				t.Fatal("accepted")
			}
			t.Logf("refused: %v", err)
		})
	}
	// The client's counter is kept: a fresh client starting from 1 again
	// is refused, one starting past it is accepted.
	sec := cosem.SecurityConfig{Name: "s", Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)}
	c := connect(t, overWrapper, addr, 47, sec)
	readRegister(t, c)
	c.Close()
	if _, err := tryConnect(overWrapper, addr, 47, sec); err == nil {
		t.Error("a replayed invocation counter was accepted")
	}
	h, _, _ := sec.Build()
	c2 := cosem.NewClient(cosem.ClientConfig{Transport: transport(overWrapper, addr), ClientAddress: 47, HLS: h,
		InvocationCounter: &cosem.FrameCounterObject{OBIS: icLN}, Timeout: 5 * time.Second})
	if err := c2.Connect(); err != nil {
		t.Fatalf("with the counter read first: %v", err)
	}
	c2.Close()
}

// GET of a profile's whole buffer in blocks and by range, SET of a value
// larger than the PDU in blocks, ACTION, rights.
//
// Covers: SIG-IPE-6461
func TestServices(t *testing.T) {
	for _, l := range []link{overWrapper, overHDLC} {
		t.Run(l.String(), func(t *testing.T) {
			s := meter(t, 500, nil, false)
			addr := listen(t, s, l)
			hx := hex.EncodeToString
			c := connect(t, l, addr, 48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted",
				BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)})
			cl := c.Association().Client
			v, err := c.Get(7, profileLN, 2)
			if err != nil {
				t.Fatal(err)
			}
			if rows, _ := v.Value.([]*axdr.DlmsData); len(rows) != 500 {
				t.Fatalf("buffer of %d rows", len(rows))
			}
			cols, err := cosem.ReadCaptureObjects(cl, profileLN)
			if err != nil || len(cols) != 2 {
				t.Fatalf("capture objects %v %v", cols, err)
			}
			from := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
			rows, err := cosem.ReadProfileRange(cl, profileLN, cols[0], from, from.Add(5*time.Hour), time.UTC)
			if err != nil || len(rows) != 6 {
				t.Fatalf("by range: %d rows, %v", len(rows), err)
			}
			big := strings.Repeat("0123456789", 300)
			if err := cl.SetRequest(gdlms.CreateAttributeDescriptor(1, bigLN, 2), axdr.CreateAxdrOctetString(hx([]byte(big)))); err != nil {
				t.Fatalf("set in blocks: %v", err)
			}
			back, err := c.Get(1, bigLN, 2)
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := hex.DecodeString(back.Value.(string)); string(b) != big {
				t.Fatalf("read back %d octets", len(b))
			}
			if err := cl.ActionRequest(gdlms.CreateMethodDescriptor(70, relayLN, 1), axdr.CreateAxdrInteger(0)); err != nil {
				t.Fatalf("remote disconnect: %v", err)
			}
			st, err := c.Get(70, relayLN, 2)
			if err != nil || st.Value != false {
				t.Fatalf("output state after disconnect %v %v", st.Value, err)
			}
			if _, err := c.Get(1, "0.0.96.99.0.255", 2); err == nil {
				t.Error("an undefined object was read")
			}
			ro := connect(t, l, addr, 64, cosem.SecurityConfig{Authentication: "low", Password: "READONLY"})
			if err := ro.Association().Client.SetRequest(gdlms.CreateAttributeDescriptor(1, bigLN, 2), axdr.CreateAxdrOctetString("00")); err == nil {
				t.Error("a read-only association wrote")
			}
		})
	}
}

// The ACCESS service: gets, a set and an action in one request, and a
// failure that does not stop the others.
//
// Covers: SIG-IPE-6462
func TestAccess(t *testing.T) {
	hx := hex.EncodeToString
	for _, sec := range []cosem.SecurityConfig{
		{Authentication: "low", Password: "ABCDEFGH"},
		{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16)},
	} {
		client := 32
		if sec.Security != "" {
			client = 48
		}
		t.Run(sec.Authentication, func(t *testing.T) {
			addr := listen(t, meter(t, 4, nil, false), overWrapper)
			c := connect(t, overWrapper, addr, client, sec)
			res, err := c.Access(
				cosem.AccessItem{Kind: cosem.AccessGet, Class: 3, OBIS: registerLN, ID: 2},
				cosem.AccessItem{Kind: cosem.AccessSet, Class: 1, OBIS: bigLN, ID: 2, Data: axdr.CreateAxdrOctetString("CAFE")},
				cosem.AccessItem{Kind: cosem.AccessGet, Class: 1, OBIS: "0.0.96.99.0.255", ID: 2},
				cosem.AccessItem{Kind: cosem.AccessAction, Class: 70, OBIS: relayLN, ID: 1, Data: axdr.CreateAxdrInteger(0)},
				cosem.AccessItem{Kind: cosem.AccessGet, Class: 1, OBIS: bigLN, ID: 2},
			)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := cosem.Number(res[0].Data); res[0].Result != 0 || n != 23050 {
				t.Errorf("get %v %v", res[0], res[0].Data.Value)
			}
			if res[1].Result != 0 || res[2].Result != 4 || res[3].Result != 0 {
				t.Errorf("results %v %v %v", res[1], res[2], res[3])
			}
			if res[4].Data.Value != "cafe" && res[4].Data.Value != "CAFE" {
				t.Errorf("read after set %v", res[4].Data.Value)
			}
		})
	}
}

// Short name referencing: the object list, reads (with data blocks),
// writes, a method, and HLS through the association SN object.
//
// Covers: SIG-IPE-6463
func TestShortNames(t *testing.T) {
	hx := hex.EncodeToString
	for _, l := range []link{overWrapper, overHDLC} {
		s := meter(t, 300, nil, true)
		addr := listen(t, s, l)
		for _, tc := range []struct {
			client int
			sec    cosem.SecurityConfig
		}{
			{32, cosem.SecurityConfig{Authentication: "low", Password: "ABCDEFGH", Referencing: "sn"}},
			{33, cosem.SecurityConfig{Authentication: "hls-aes", Password: string(hlsKey), Referencing: "sn"}},
			{48, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted", BlockCipherKey: hx(key16), AuthenticationKey: hx(ak16), Referencing: "sn"}},
		} {
			t.Run(fmt.Sprintf("%v/%s", l, tc.sec.Authentication), func(t *testing.T) {
				c := connect(t, l, addr, tc.client, tc.sec)
				a := c.Association()
				if !a.ShortNames() {
					t.Fatal("not a short name association")
				}
				readRegister(t, c)
				v, err := c.Get(7, profileLN, 2)
				if err != nil {
					t.Fatal(err)
				}
				if rows, _ := v.Value.([]*axdr.DlmsData); len(rows) != 300 {
					t.Fatalf("buffer of %d rows", len(rows))
				}
				if err := a.SetSN(1, bigLN, 2, axdr.CreateAxdrOctetString("BEEF")); err != nil {
					t.Fatal(err)
				}
				if v, _ := c.Get(1, bigLN, 2); v.Value != "beef" && v.Value != "BEEF" {
					t.Fatalf("read back %v", v.Value)
				}
				base, err := a.BaseName(70, relayLN)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := a.ActionSN(70, base, 1, axdr.CreateAxdrInteger(0)); err != nil {
					t.Fatalf("remote disconnect: %v", err)
				}
				if v, _ := c.Get(70, relayLN, 2); v.Value != false {
					t.Fatalf("output state %v", v.Value)
				}
				_, _ = a.ActionSN(70, base, 2, axdr.CreateAxdrInteger(0))
			})
		}
	}
}

// A data-notification pushed to a listener: plain and in
// general-glo-ciphering.
//
// Covers: SIG-IPE-6464
func TestPush(t *testing.T) {
	s := meter(t, 4, nil, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, apdu, err := wrapper.ReadWPDU(c)
			c.Close()
			if err == nil {
				got <- apdu
			}
		}
	}()
	body := axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("SGM0001"))), axdr.CreateAxdrLongUnsigned(23050)})
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if err := s.PushTo("tcp", ln.Addr().String(), body, server.PushOptions{Time: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	n, err := cosem.DecodeDataNotification(<-got, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plain push: %+v", n)
	sec := &server.Association{Policy: 0x30, Key: key16, AuthKey: ak16}
	if err := s.PushTo("tcp", ln.Addr().String(), body, server.PushOptions{Security: sec}); err != nil {
		t.Fatal(err)
	}
	apdu := <-got
	_, n2, err := cosem.OpenProtectedPush(apdu, []cosem.PushSource{{ID: "m", SystemTitle: serverST, Security: &cosem.Security{Policy: 0x30, Key: key16, AuthKey: ak16}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("protected push: %+v", n2)
}

// exchange sends a raw APDU on the client's association.
func exchange(t *testing.T, c *cosem.Client, apdu string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(apdu, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	back, err := c.Association().Exchange(b)
	if err != nil {
		t.Fatalf("%s: %v", apdu, err)
	}
	return back
}

// GET and ACTION with list, ACTION with parameter blocks both ways, and
// general block transfer, as raw APDUs.
//
// Covers: SIG-IPE-6461
func TestRawServices(t *testing.T) {
	s := meter(t, 200, nil, false)
	s.GBT = true
	echo := &classes.Generic{Class: 9, LN: "0.0.10.0.0.255", Methods: map[int8]func(*axdr.DlmsData) (*axdr.DlmsData, error){
		1: func(p *axdr.DlmsData) (*axdr.DlmsData, error) { return p, nil },
	}}
	s.Add(echo)
	addr := listen(t, s, overWrapper)
	h, _, _ := (&cosem.SecurityConfig{Authentication: "low", Password: "ABCDEFGH"}).Build()
	base := cosem.ConformanceGet | cosem.ConformanceSet | cosem.ConformanceAction | cosem.ConformanceSelectiveAccess |
		cosem.ConformanceBlockGetOrRead | cosem.ConformanceBlockAction | cosem.ConformanceMultipleReferences
	open := func(conf uint32) *cosem.Client {
		c := cosem.NewClient(cosem.ClientConfig{Transport: transport(overWrapper, addr), ClientAddress: 32, HLS: h, Password: []byte("ABCDEFGH"),
			Timeout: 5 * time.Second, Conformance: conf})
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	c := open(base)

	// get-request-with-list: the register and an undefined object.
	back := exchange(t, c, "C0 03 41 02 0003 0100200700FF 02 00 0001 00006063 00FF 02 00")
	if hex.EncodeToString(back) != "c4034102"+"00125a0a"+"0104" {
		t.Errorf("get with list: %X", back)
	}
	// action-request-with-list: the echo twice.
	back = exchange(t, c, "C3 03 42 02 0009 00000A0000FF 01 0009 00000A0000FF 01 02 12 0005 0F 07")
	if hex.EncodeToString(back) != "c7034202"+"000100120005"+"0001000f07" {
		t.Errorf("action with list: %X", back)
	}
	// action-request-with-first-pblock and with-pblock: a 300-octet
	// parameter in two blocks; the 300-octet answer comes back in
	// parameter blocks, fetched with next-pblock.
	param := append([]byte{0x09, 0x82, 0x01, 0x2C}, bytes.Repeat([]byte{0xAB}, 300)...)
	first := fmt.Sprintf("C3 04 43 0009 00000A0000FF 01 00 00000001 81A0 %X", param[:160])
	back = exchange(t, c, first)
	if hex.EncodeToString(back) != "c7044300000001" {
		t.Fatalf("first pblock acknowledged %X", back)
	}
	back = exchange(t, c, fmt.Sprintf("C3 06 43 01 00000002 81%02X %X", len(param)-160, param[160:]))
	var got []byte
	for n := uint32(1); ; n++ {
		if len(back) < 9 || back[0] != 0xC7 || back[1] != 0x02 {
			t.Fatalf("answer block %d: %X", n, back)
		}
		l, sz := cosem.DecodeLength(back[8:])
		got = append(got, back[8+sz:8+sz+l]...)
		if back[3] == 1 {
			break
		}
		back = exchange(t, c, fmt.Sprintf("C3 02 43 %08X", n))
	}
	if !bytes.Equal(got, param) {
		t.Fatalf("echoed %d octets", len(got))
	}
	c.Close()
	c = open(base | cosem.ConformanceGeneralBlockTransfer)
	// General block transfer: the profile's buffer asked for in one GBT
	// block; the answer comes in GBT blocks, each acknowledged.
	req := "C0 01 44 0007 0100630100FF 02 00"
	rb, _ := hex.DecodeString(strings.ReplaceAll(req, " ", ""))
	back = exchange(t, c, fmt.Sprintf("E0 81 0001 0000 %02X %s", len(rb), strings.ReplaceAll(req, " ", "")))
	var resp []byte
	for i := 0; ; i++ {
		if len(back) < 6 || back[0] != 0xE0 {
			t.Fatalf("GBT block %d: %X", i, back)
		}
		l, sz := cosem.DecodeLength(back[6:])
		resp = append(resp, back[6+sz:6+sz+l]...)
		if back[1]&0x80 != 0 {
			break
		}
		back = exchange(t, c, fmt.Sprintf("E0 01 0002 %04X 00", uint16(back[2])<<8|uint16(back[3])))
	}
	if len(resp) < 4 || resp[0] != 0xC4 || resp[1] != 0x01 || resp[3] != 0x00 {
		t.Fatalf("GBT answer %X", resp[:min(len(resp), 16)])
	}
	d, _, err := axdrDecode(resp[4:])
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := d.Value.([]*axdr.DlmsData); len(rows) != 200 {
		t.Fatalf("GBT buffer of %d rows", len(rows))
	}
	if st := s.Stats(); st.GBTBlocks < 2 || st.Blocks < 2 {
		t.Errorf("stats %+v", st)
	}
}

func axdrDecode(b []byte) (axdr.DlmsData, []byte, error) {
	src := b
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	return d, src, err
}

// Image transfer: the client's state machine against the server's image
// transfer object (initiate, blocks, verify, activate), and a transfer
// resumed after an interruption.
//
// Covers: SIG-IPE-6465
func TestImageTransfer(t *testing.T) {
	s := meter(t, 4, nil, false)
	var verified, activated []byte
	img := &classes.ImageTransfer{LN: "0.0.44.0.0.255", BlockSize: 96, Enabled: true,
		OnVerify:   func(id, b []byte) error { verified = b; return nil },
		OnActivate: func(id, b []byte) error { activated = b; return nil }}
	s.Add(img)
	addr := listen(t, s, overWrapper)
	c := connect(t, overWrapper, addr, 32, cosem.SecurityConfig{Authentication: "low", Password: "ABCDEFGH"})
	image := bytes.Repeat([]byte("firmware-"), 111)
	// An interrupted transfer: initiated, three blocks sent.
	cl := c.Association().Client
	octs := func(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }
	if err := cl.ActionRequest(gdlms.CreateMethodDescriptor(18, "0.0.44.0.0.255", 1),
		axdr.CreateAxdrStructure([]*axdr.DlmsData{octs([]byte("FW-2")), axdr.CreateAxdrDoubleLongUnsigned(uint32(len(image)))})); err != nil {
		t.Fatal(err)
	}
	for bn := 0; bn < 3; bn++ {
		if err := cl.ActionRequest(gdlms.CreateMethodDescriptor(18, "0.0.44.0.0.255", 2),
			axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrDoubleLongUnsigned(uint32(bn)), octs(image[bn*96 : (bn+1)*96])})); err != nil {
			t.Fatal(err)
		}
	}
	res, err := c.TransferImage(cosem.ImageTransfer{Identifier: []byte("FW-2"), Image: image, Activate: true, Poll: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed || res.Blocks != 11 || res.Sent != 8 || res.Status != cosem.ImageActivationOK {
		t.Errorf("result %+v", res)
	}
	if !bytes.Equal(verified, image) || !bytes.Equal(activated, image) {
		t.Errorf("the meter verified %d and activated %d octets", len(verified), len(activated))
	}
	// A verification failure is reported.
	img.Lock()
	img.OnVerify = func(id, b []byte) error { return fmt.Errorf("bad signature") }
	img.Unlock()
	if _, err := c.TransferImage(cosem.ImageTransfer{Identifier: []byte("FW-3"), Image: image[:200], Poll: 10 * time.Millisecond}); err == nil {
		t.Error("a failed verification was not reported")
	}
}
