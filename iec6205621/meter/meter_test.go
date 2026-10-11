// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meter_test

import (
	"bufio"
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/iec6205621"
	"github.com/cB-Sigma/dlms/iec6205621/meter"
	"github.com/cB-Sigma/dlms/phy"
	"github.com/cB-Sigma/dlms/server"
)

func registers() map[string]string {
	return map[string]string{
		"0.0.0": "12345678", "1.8.0": "001234.5*kWh", "32.7.0": "231.4*V", "C.1.0": "12345678",
	}
}

func start(t testing.TB, m *meter.Meter) *meter.Meter {
	t.Helper()
	if err := m.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m
}

func config(addr string) *iec6205621.SessionConfig {
	return &iec6205621.SessionConfig{Line: iec6205621.Line{TCP: true, Address: addr, Emulate7E1: true},
		MaxBaud: 19200, Timeout: time.Second, ReadCommand: "R1", WriteCommand: "W1"}
}

// A mode C readout through a converter with the parity emulated.
//
// Covers: SIG-IPE-628
func TestReadout(t *testing.T) {
	m := start(t, &meter.Meter{Manufacturer: "ISk", BaudChar: '5', Model: "MT174", Registers: registers()})
	s, _, err := iec6205621.OpenSession(context.Background(), config(m.Addr()), '0', false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.CloseLine()
	ds, err := s.ReadData()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range ds {
		got[d.Address] = d.Value + "*" + d.Unit
	}
	if got["1.8.0"] != "001234.5*kWh" || got["32.7.0"] != "231.4*V" {
		t.Errorf("data sets %v", got)
	}
	if _, _, parity := m.Counts(); parity != 0 {
		t.Errorf("%d parity errors", parity)
	}
}

// Programming mode: P1, R1, W1; a wrong password is refused.
//
// Covers: SIG-IPE-628
func TestProgramming(t *testing.T) {
	m := start(t, &meter.Meter{Manufacturer: "ISk", BaudChar: '5', Model: "MT174", Password: "00000000", Registers: registers()})
	s, err := iec6205621.OpenProgramming(context.Background(), config(m.Addr()), "00000000")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := s.Read("1.8.0()")
	if err != nil || len(ds) != 1 || ds[0].Value != "001234.5" {
		t.Fatalf("read 1.8.0: %v %v", ds, err)
	}
	if err := s.WriteValue("C.1.0", "87654321"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if w := m.Writes(); !slices.Contains(w, "C.1.0(87654321)") {
		t.Errorf("writes %v", w)
	}
	if _, err := iec6205621.OpenProgramming(context.Background(), config(m.Addr()), "11111111"); err == nil {
		t.Error("a wrong password opened programming mode")
	}
}

// Mode E: the sign-on and the binary option select at 300 baud, the
// switch confirm, then HDLC to a server of package server on the same
// connection, read with this module's client.
//
// Covers: SIG-IPE-628
func TestModeEToServer(t *testing.T) {
	dl := &server.Server{}
	dl.Add(&classes.Register{LN: "1.0.32.7.0.255", Value: axdr.CreateAxdrLongUnsigned(23140), Scaler: -2, Unit: 35})
	dl.Associations = []*server.Association{{ClientAddress: 16}}
	m := start(t, &meter.Meter{Manufacturer: "LGZ", BaudChar: '5', Escapes: `\2`, Model: "ZMD", Registers: registers(), DLMS: dl})

	c, err := net.DialTimeout("tcp", m.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	if _, err := c.Write(iec6205621.WithParity([]byte("/?!\r\n"))); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	ident, err := r.ReadString(0x0A) // the identification, parity bits on
	if err != nil {
		t.Fatal(err)
	}
	id, err := iec6205621.ParseIdentification(string(strip(ident)))
	if err != nil || id.Mode != iec6205621.ModeE {
		t.Fatalf("identification %q: %+v %v", ident, id, err)
	}
	if _, err := c.Write(iec6205621.WithParity(iec6205621.OptionSelect('2', '0', '2'))); err != nil {
		t.Fatal(err)
	}
	want := iec6205621.WithParity(iec6205621.ModeEConfirm('0'))
	got := make([]byte, len(want))
	for i := range got {
		if got[i], err = r.ReadByte(); err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != string(want) {
		t.Fatalf("switch confirm % X, want % X", got, want)
	}
	_ = c.SetReadDeadline(time.Time{})
	bin := &readerConn{Conn: c, r: r}
	cl := cosem.NewClient(cosem.ClientConfig{Transport: func(client int) (gdlms.Transport, error) {
		line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return bin, nil }})
		if err != nil {
			return nil, err
		}
		return hdlc.NewClient(line, hdlc.Config{Client: client, Server: hdlc.ServerAddress(1, 0, 1)})
	}, ClientAddress: 16, Timeout: 3 * time.Second})
	if err := cl.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	v, err := cl.Get(3, "1.0.32.7.0.255", 2)
	if err != nil || v.Value.(uint16) != 23140 {
		t.Fatalf("voltage %v %v", v.Value, err)
	}
	if o := m.Options(); len(o) != 1 || o[0] != "2 0 2" {
		t.Errorf("option selects %v", o)
	}
}

func strip(s string) []byte {
	b := []byte(s)
	for i := range b {
		b[i] &= 0x7f
	}
	return b
}

// readerConn reads through the buffered reader the sign-on used.
type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.r.Read(b) }
