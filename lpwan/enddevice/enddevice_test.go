// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enddevice_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/dlms/lpwan/enddevice"
	"github.com/cB-Sigma/dlms/server"
	"github.com/cB-Sigma/dlms/wrapper"
)

// A public client's AARQ (logical names, no ciphering) and a GET of a
// register's value.
var (
	aarq = []byte{0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
		0xBE, 0x10, 0x04, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0}
	getVoltage = []byte{0xC0, 0x01, 0xC1, 0x00, 0x03, 1, 0, 32, 7, 0, 255, 0x02, 0x00}
	voltage    = []byte{0xC4, 0x01, 0xC1, 0x00, 0x12, 0x5A, 0x0A}
)

func meter(t *testing.T) *server.Server {
	t.Helper()
	s := &server.Server{}
	s.Add(&classes.Register{LN: "1.0.32.7.0.255", Value: axdr.CreateAxdrLongUnsigned(23050), Scaler: -2, Unit: 35})
	s.Associations = []*server.Association{{ClientAddress: 16}}
	return s
}

// A server of package server behind a LoRaWAN radio answers the head end
// (package lpwan's bridge) through SCHC, with fragmentation both ways where
// the payload limit needs it, for each header choice; a push goes up.
//
// Covers: SIG-IPE-3774
func TestLoRaWAN(t *testing.T) {
	for _, c := range []struct {
		name               string
		header             string
		maxPayload, upload int
	}{
		{"wrapper", "wrapper", 51, 51},
		{"wrapper fragmented", "wrapper", 11, 11},
		{"ipv6 udp wrapper", "ipv6/udp/wrapper", 51, 51},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := lpwan.BridgeSettings{Header: c.header, MaxPayload: c.maxPayload}
			if err := s.Check(); err != nil {
				t.Fatal(err)
			}
			ns := lpwan.NewMemNS()
			b, err := lpwan.NewBridge(s, ns, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := b.Add(lpwan.DeviceOptions{Meter: lpwan.MeterLoRaWAN{DevEUI: "70b3d57ed005a1c1"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = b.Run(ctx) }()
			<-ns.Ready()
			d := &enddevice.LoRaWAN{Handler: enddevice.ServerHandler(meter(t)), DevEUI: "70b3d57ed005a1c1",
				Radio: enddevice.MemRadio(ns, "70b3d57ed005a1c1", s.Class), Settings: s, UplinkPayload: c.upload, Poll: 20 * time.Millisecond}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			defer d.Stop()
			_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			for _, req := range [][]byte{aarq, getVoltage} {
				out, _ := wrapper.Encode(16, 1, req)
				if _, err := conn.Write(out); err != nil {
					t.Fatal(err)
				}
				h, apdu, err := wrapper.ReadWPDU(conn)
				if err != nil {
					t.Fatal(err)
				}
				if h.Src != 1 || h.Dst != 16 {
					t.Fatalf("answer %+v", h)
				}
				if req[0] == 0x60 && apdu[0] != 0x61 {
					t.Fatalf("AARE % X", apdu)
				}
				if req[0] == 0xC0 && !bytes.Equal(apdu, voltage) {
					t.Fatalf("GET answer % X", apdu)
				}
			}
			if d.Served() != 2 {
				t.Errorf("served %d", d.Served())
			}
			note := []byte{0x0F, 0, 0, 0, 1, 0x00, 0x12, 0x5A, 0x0A}
			if err := d.Push(1, note); err != nil {
				t.Fatal(err)
			}
			h, apdu, err := wrapper.ReadWPDU(conn)
			if err != nil || !bytes.Equal(apdu, note) || h.Dst != 1 {
				t.Fatalf("push %+v % X %v", h, apdu, err)
			}
		})
	}
}

// An NB-IoT meter wakes, pushes from a fresh port, answers the head end
// while awake and sleeps after ActiveTime.
//
// Covers: SIG-IPE-3774
func TestNBIoT(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	d := &enddevice.NBIoT{Handler: enddevice.ServerHandler(meter(t)), Server: pc.LocalAddr().String(), ActiveTime: 500 * time.Millisecond}
	note := []byte{0x0F, 0, 0, 0, 1, 0x00, 0x12, 0x5A, 0x0A}
	done, err := d.CallAsync(1, note)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, apdu, err := wrapper.ParseDatagram(buf[:n]); err != nil || !bytes.Equal(apdu, note) {
		t.Fatalf("push % X %v", buf[:n], err)
	}
	for _, req := range [][]byte{aarq, getVoltage} {
		out, _ := wrapper.Encode(16, 1, req)
		if _, err := pc.WriteTo(out, from); err != nil {
			t.Fatal(err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, apdu, _ := wrapper.ParseDatagram(buf[:n])
		if req[0] == 0xC0 && !bytes.Equal(apdu, voltage) {
			t.Fatalf("GET answer % X", apdu)
		}
	}
	<-done
	if d.Awake() || d.Calls() != 1 || d.Served() != 2 {
		t.Errorf("awake %v calls %d served %d", d.Awake(), d.Calls(), d.Served())
	}
}
