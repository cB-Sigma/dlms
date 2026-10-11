// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package concentrator_test

import (
	"bytes"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/concentrator"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/gateway"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
	"github.com/cB-Sigma/dlms/server"
	"github.com/cB-Sigma/dlms/wrapper"
)

var (
	key = bytes.Repeat([]byte{0x11}, 16)
	ak  = bytes.Repeat([]byte{0x22}, 16)
)

const registerLN = "1.0.32.7.0.255"

// meter is a server with one register holding v, the public client and an
// HLS-GMAC client (48) with authenticated and encrypted APDUs.
func meter(t *testing.T, st string, v uint16) *server.Server {
	t.Helper()
	s := &server.Server{SystemTitle: []byte(st)}
	s.Add(&classes.Register{LN: registerLN, Value: axdr.CreateAxdrLongUnsigned(v), Scaler: -2, Unit: 35},
		&classes.Clock{LN: "0.0.1.0.0.255", Location: time.UTC})
	s.Associations = []*server.Association{{ClientAddress: 16},
		{ClientAddress: 48, Mechanism: 5, Policy: 0x30, Key: key, AuthKey: ak}}
	s.Logf = func(f string, a ...any) { t.Logf(st+": "+f, a...) }
	return s
}

func read(t *testing.T, g *cosem.Gateway, d cosem.GatewayDest, client int, secured bool) uint16 {
	t.Helper()
	var h *cosem.HLS
	if secured {
		var err error
		sc := cosem.SecurityConfig{Name: d.Name, Authentication: "hls-gmac", Security: "authenticated-encrypted",
			BlockCipherKey: hex.EncodeToString(key), AuthenticationKey: hex.EncodeToString(ak)}
		h, _, err = sc.Build()
		if err != nil {
			t.Fatal(err)
		}
	}
	c := cosem.NewClient(cosem.ClientConfig{Transport: func(cl int) (gdlms.Transport, error) {
		d.Client = uint16(cl)
		return g.Transport(d), nil
	}, ClientAddress: client, HLS: h, Name: d.Name, Where: "DCU", Timeout: 5 * time.Second})
	if err := c.Connect(); err != nil {
		t.Fatalf("%s: %v", d.Name, err)
	}
	defer c.Close()
	v, err := c.Get(3, registerLN, 2)
	if err != nil {
		t.Fatalf("%s: %v", d.Name, err)
	}
	return v.Value.(uint16)
}

// Gateway mode and logical-device mode on one connection: two meters in
// the process, a meter reached over the wrapper and one over HDLC through
// a converter, each behind its network and address, and a logical device;
// HLS-GMAC with ciphered APDUs end to end through the prefix.
func TestModes(t *testing.T) {
	ipMeter := meter(t, "SGMIP001", 3000)
	ipAddr, err := ipMeter.ListenWrapper("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ipMeter.Close() })
	serialMeter := meter(t, "SGMHD001", 4000)
	hdlcAddr, err := serialMeter.ListenHDLC("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serialMeter.Close() })

	dcu := &concentrator.Concentrator{
		Meters: []concentrator.Meter{
			{Network: 1, Address: []byte{0x0A, 0x01}, Device: concentrator.Local(meter(t, "SGMLOC01", 1000))},
			{Network: 1, Address: []byte{0x0A, 0x02}, Device: concentrator.Local(meter(t, "SGMLOC02", 2000))},
			{Network: 2, Address: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, Device: &concentrator.Transport{
				Dial: func(c, s int) (gdlms.Transport, error) { return wrapper.New("tcp", ipAddr, c, s, 5*time.Second) }}},
			{Network: 3, Address: []byte{0x11}, Device: &concentrator.Transport{
				Dial: func(c, s int) (gdlms.Transport, error) {
					line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", hdlcAddr, 5*time.Second) }})
					if err != nil {
						return nil, err
					}
					return hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(s, 0, 1)})
				}}},
		},
		Logical: map[uint16]concentrator.Downstream{17: concentrator.LogicalDevice(meter(t, "SGMLOG17", 1700))},
		Logf:    func(f string, a ...any) { t.Logf("dcu: "+f, a...) },
	}
	addr, err := dcu.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcu.Close() })
	g := cosem.NewGateway(cosem.GatewayConfig{ID: "DCU", Address: addr, Timeout: 5 * time.Second})
	t.Cleanup(g.Close)

	cases := []struct {
		d    cosem.GatewayDest
		want uint16
	}{
		{cosem.GatewayDest{Network: 1, Address: []byte{0x0A, 0x01}, Server: 1, Name: "local 1"}, 1000},
		{cosem.GatewayDest{Network: 1, Address: []byte{0x0A, 0x02}, Server: 1, Name: "local 2"}, 2000},
		{cosem.GatewayDest{Network: 2, Address: []byte{1, 2, 3, 4, 5, 6}, Server: 1, Name: "wrapper"}, 3000},
		{cosem.GatewayDest{Network: 3, Address: []byte{0x11}, Server: 1, Name: "hdlc"}, 4000},
		{cosem.GatewayDest{Logical: true, Server: 17, Name: "logical 17"}, 1700},
	}
	for i := 0; i < 2; i++ {
		for _, c := range cases {
			c.d.Timeout = 5 * time.Second
			if v := read(t, g, c.d, 16, false); v != c.want {
				t.Errorf("%s public: %d", c.d.Name, v)
			}
			if v := read(t, g, c.d, 48, true); v != c.want {
				t.Errorf("%s HLS-GMAC: %d", c.d.Name, v)
			}
		}
	}
	// Concurrent reads of different meters on the one connection.
	var wg sync.WaitGroup
	for _, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.d.Timeout = 5 * time.Second
			if v := read(t, g, c.d, 48, true); v != c.want {
				t.Errorf("%s concurrent: %d", c.d.Name, v)
			}
		}()
	}
	wg.Wait()
	st := dcu.Stats()
	if st.Accepts != 1 || st.Routed["0A01"] == 0 || st.Routed["010203040506"] == 0 || st.Logical == 0 {
		t.Errorf("stats %+v", st)
	}
}

// Unknown addresses and unreachable meters are dropped (the head end times
// out); a meter's push is forwarded with its prefix; the answer prefix can
// be changed.
func TestUnknownUnreachablePush(t *testing.T) {
	dcu := &concentrator.Concentrator{
		Meters: []concentrator.Meter{
			{Network: 0, Address: []byte{0x01}, Device: concentrator.Local(meter(t, "SGMLOC01", 1000))},
			{Network: 0, Address: []byte{0x02}, Device: &concentrator.Transport{
				Dial: func(c, s int) (gdlms.Transport, error) { return wrapper.New("tcp", "127.0.0.1:1", c, s, time.Second) }}},
		},
	}
	addr, err := dcu.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcu.Close() })
	pushes := make(chan []byte, 4)
	g := cosem.NewGateway(cosem.GatewayConfig{ID: "DCU", Address: addr, Timeout: 2 * time.Second,
		Push: func(pre *gateway.Prefix, src uint16, apdu []byte) {
			if pre != nil && pre.Network == 0 && string(pre.Address) == "\x01" {
				pushes <- apdu
			}
		}})
	t.Cleanup(g.Close)
	if v := read(t, g, cosem.GatewayDest{Address: []byte{0x01}, Server: 1, Name: "ok", Timeout: 2 * time.Second}, 16, false); v != 1000 {
		t.Fatalf("read %d", v)
	}
	for _, a := range [][]byte{{0x02}, {0x03}} {
		d := cosem.GatewayDest{Address: a, Server: 1, Name: "gone", Timeout: time.Second, Client: 16}
		c := cosem.NewClient(cosem.ClientConfig{Transport: func(int) (gdlms.Transport, error) { return g.Transport(d), nil },
			ClientAddress: 16, Timeout: time.Second})
		if err := c.Connect(); err == nil {
			c.Close()
			t.Errorf("address %X answered", a)
		}
	}
	st := dcu.Stats()
	if st.Unknown == 0 || st.Unreachable == 0 {
		t.Errorf("stats %+v", st)
	}
	note := []byte{0x0F, 0, 0, 0, 1, 0x00, 0x12, 0x03, 0xE8}
	if err := dcu.Forward(0, []byte{0x01}, 1, note); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-pushes:
		if !bytes.Equal(got, note) {
			t.Errorf("push % X", got)
		}
	case <-time.After(3 * time.Second):
		t.Error("the push did not arrive")
	}
}

// A request without the prefix after a prefixed AARQ (as Gurux's client
// sends ciphered APDUs) goes to the meter the AARQ reached and is answered
// without a prefix; Strict drops it.
func TestStickyPrefix(t *testing.T) {
	aarq := []byte{0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
		0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0}
	get := []byte{0xC0, 0x01, 0xC1, 0x00, 0x03, 1, 0, 32, 7, 0, 255, 0x02, 0x00}
	for _, strict := range []bool{false, true} {
		dcu := &concentrator.Concentrator{Strict: strict,
			Meters: []concentrator.Meter{{Address: []byte{0x01}, Device: concentrator.Local(meter(t, "SGMLOC01", 1000))}}}
		addr, err := dcu.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := gateway.Encode(gateway.Prefix{Header: gateway.Request, Address: []byte{0x01}}, aarq)
		out, _ := wrapper.Encode(16, 1, req)
		_, _ = c.Write(out)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := wrapper.ReadWPDU(c); err != nil {
			t.Fatal(err)
		}
		out, _ = wrapper.Encode(16, 1, get)
		_, _ = c.Write(out)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, b, err := wrapper.ReadWPDU(c)
		switch {
		case strict && err == nil:
			t.Errorf("strict: answered % X", b)
		case !strict && (err != nil || len(b) == 0 || b[0] != 0xC4):
			t.Errorf("not strict: % X %v", b, err)
		}
		c.Close()
		dcu.Close()
	}
}

// ForwardTo dials the head end's push listener; ResponsePrefix changes the
// answers' prefix.
func TestForwardToAndResponsePrefix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, b, err := wrapper.ReadWPDU(c)
		if err == nil {
			got <- b
		}
	}()
	dcu := &concentrator.Concentrator{PushHeader: gateway.Response}
	if err := dcu.ForwardTo(ln.Addr().String(), 4, []byte{0xAA}, 1, []byte{0x0F, 1}); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !bytes.Equal(b, []byte{0xE7, 4, 1, 0xAA, 0x0F, 1}) {
		t.Errorf("forwarded % X", b)
	}

	dcu = &concentrator.Concentrator{
		Meters: []concentrator.Meter{{Address: []byte{0x01}, Device: concentrator.Local(meter(t, "SGMLOC01", 1000))}},
		ResponsePrefix: func(p gateway.Prefix) gateway.Prefix {
			return gateway.Prefix{Header: gateway.Response, Network: p.Network, Address: []byte{0xFF}}
		},
	}
	addr, err := dcu.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dcu.Close()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	aarq := []byte{0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
		0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0}
	req, _ := gateway.Encode(gateway.Prefix{Header: gateway.Request, Address: []byte{0x01}}, aarq)
	out, _ := wrapper.Encode(16, 1, req)
	if _, err := c.Write(out); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, b, err := wrapper.ReadWPDU(c)
	if err != nil {
		t.Fatal(err)
	}
	p, apdu, ok, _ := gateway.Parse(b)
	if !ok || !bytes.Equal(p.Address, []byte{0xFF}) || len(apdu) == 0 || apdu[0] != 0x61 {
		t.Errorf("answer % X", b)
	}
}
