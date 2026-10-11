// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/concentrator"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/is15959"
	ismeter "github.com/cB-Sigma/dlms/is15959/meter"
	"github.com/cB-Sigma/dlms/phy"
)

// Gurux's client through our data concentrator (package concentrator):
// gateway mode to a meter in the concentrator's process and to a meter it
// reaches over HDLC, and logical-device mode; no security, low-level
// security and HLS-GMAC with authenticated and encrypted APDUs end to end.
func TestGuruxClientThroughConcentrator(t *testing.T) {
	needPython(t)
	local, _, _ := ourServer(t, 30, false, false)
	local.Logf = func(f string, a ...any) { t.Logf("local meter: "+f, a...) }
	remote, _, remoteHDLC := ourServer(t, 30, false, false)
	_ = remote
	logical, _, _ := ourServer(t, 30, false, false)
	dcu := &concentrator.Concentrator{
		Meters: []concentrator.Meter{
			{Network: 1, Address: []byte{0x0A, 0x01}, Device: concentrator.Local(local)},
			{Network: 2, Address: []byte{0x12, 0x34, 0x56}, Device: &concentrator.Transport{
				Dial: func(c, s int) (gdlms.Transport, error) {
					line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", remoteHDLC, 5*time.Second) }})
					if err != nil {
						return nil, err
					}
					return hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(s, 0, 1)})
				}}},
		},
		Logical: map[uint16]concentrator.Downstream{17: concentrator.LogicalDevice(logical)},
		Logf:    func(f string, a ...any) { t.Logf("dcu: "+f, a...) },
	}
	addr, err := dcu.Listen(serverListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcu.Close() })
	for _, dest := range []struct {
		name string
		args []string
	}{
		{"gateway/local", []string{"--gateway", "1:0A01"}},
		{"gateway/hdlc", []string{"--gateway", "2:123456"}},
		{"logical-device-17", []string{"--server-address", "17"}},
	} {
		t.Run(dest.name+"/public", func(t *testing.T) {
			guruxClient(t, addr, append([]string{"--client", "16", "--get", gClock, "--get", gSerial}, dest.args...)...)
		})
		t.Run(dest.name+"/low", func(t *testing.T) {
			guruxClient(t, addr, append([]string{"--client", "32", "--auth", "low", "--password", "ABCDEFGH",
				"--get", gVoltage, "--get", gScaler, "--profile", gProfile}, dest.args...)...)
		})
		t.Run(dest.name+"/hls-gmac", func(t *testing.T) {
			guruxClient(t, addr, append([]string{"--client", "49", "--auth", "gmac", "--security", "authenc",
				"--block-key", ifKey, "--auth-key", ifAK, "--get", gClock, "--get", gVoltage}, dest.args...)...)
		})
	}
	st := dcu.Stats()
	t.Logf("concentrator: %+v", st)
	if st.Routed["0A01"] == 0 || st.Routed["123456"] == 0 || st.Logical == 0 {
		t.Errorf("a mode was not used: %+v", st)
	}
}

// Gurux's client against an IS 15959 meter built by package is15959/meter
// (Part 2, three-phase): the public client, the meter reader with
// low-level security and encrypted APDUs, the utility settings client with
// HLS mechanism 2 and authenticated and encrypted APDUs; nameplate,
// registers with scaler and unit, and the block load profile.
func TestGuruxClientAgainstIS15959Meter(t *testing.T) {
	needPython(t)
	spec, _ := is15959.Get("part2-3ph")
	m, err := ismeter.New(spec, ismeter.Options{Serial: "40001234"})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := m.ListenWrapper(serverListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	hx := hex.EncodeToString
	for _, a := range m.Associations {
		var args []string
		switch a.Role {
		case is15959.PC:
			args = []string{"--client", "16"}
		case is15959.MR:
			args = []string{"--client", "32", "--auth", "low", "--password", string(a.Secret), "--security", "enc",
				"--block-key", hx(a.Key), "--auth-key", hx(a.AuthKey)}
		case is15959.US:
			args = []string{"--client", "48", "--auth", "hls", "--password", string(a.Secret), "--security", "authenc",
				"--block-key", hx(a.Key), "--auth-key", hx(a.AuthKey)}
		default:
			continue
		}
		t.Run(a.Role.String(), func(t *testing.T) {
			args := append(args, "--get", "1:0.0.96.1.0.255:2", "--get", gClock)
			if a.Role != is15959.PC {
				args = append(args, "--get", "3:1.0.32.7.0.255:2", "--get", "3:1.0.32.7.0.255:3", "--profile", "1.0.99.1.0.255", "--range-hours", "24")
			}
			guruxClient(t, addr, args...)
		})
	}
}
