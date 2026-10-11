// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meter_test

import (
	"encoding/hex"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/is15959/meter"
	"github.com/cB-Sigma/dlms/wrapper"
)

func connect(t *testing.T, addr string, client int, sec cosem.SecurityConfig) *cosem.Client {
	t.Helper()
	sec.Name = "is15959"
	h, _, err := sec.Build()
	if err != nil {
		t.Fatal(err)
	}
	c := cosem.NewClient(cosem.ClientConfig{Transport: func(cl int) (gdlms.Transport, error) {
		return wrapper.New("tcp", addr, cl, 1, 5*time.Second)
	}, ClientAddress: client, HLS: h, Password: []byte(sec.Password), Timeout: 5 * time.Second})
	if err := c.Connect(); err != nil {
		t.Fatalf("client %d: %v", client, err)
	}
	t.Cleanup(c.Close)
	return c
}

// Every profile builds a meter whose public client, meter reader
// (low-level security, encrypted APDUs) and utility settings (HLS,
// authenticated and encrypted APDUs) associate and read the nameplate, a
// register with its scaler and unit, and a profile; the access rights of
// the profile are enforced.
//
// Covers: SIG-IPE-6461
func TestEveryProfile(t *testing.T) {
	for _, id := range is15959.IDs() {
		t.Run(id, func(t *testing.T) {
			spec, _ := is15959.Get(id)
			m, err := meter.New(spec, meter.Options{Serial: "12345678"})
			if err != nil {
				t.Fatal(err)
			}
			addr, err := m.ListenWrapper("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			o := m.Options
			hx := hex.EncodeToString
			for _, a := range m.Associations {
				var sec cosem.SecurityConfig
				switch {
				case a.Role == is15959.Push || a.Role == is15959.IHD || a.Role == is15959.FW:
					continue
				case a.Mechanism == 0:
					sec = cosem.SecurityConfig{Authentication: "none"}
				case a.Mechanism == 1:
					sec = cosem.SecurityConfig{Authentication: "low", Password: o.Password}
				case a.Mechanism == 2:
					sec = cosem.SecurityConfig{Authentication: "hls-aes", Password: string(a.Secret)}
				default:
					sec = cosem.SecurityConfig{Authentication: "hls-gmac"}
				}
				if a.Policy != 0 {
					sec.Security = map[byte]string{0x10: "authenticated", 0x20: "encrypted", 0x30: "authenticated-encrypted"}[a.Policy]
					sec.BlockCipherKey, sec.AuthenticationKey = hx(a.Key), hx(a.AuthKey)
				}
				c := connect(t, addr, int(a.Client), sec)
				if a.Role == is15959.PC {
					continue
				}
				v, err := c.Get(1, "0.0.96.1.0.255", 2)
				if err != nil {
					t.Fatalf("%v: serial: %v", a.Role, err)
				}
				if s, _ := v.Value.(string); s != hx([]byte("12345678")) {
					t.Errorf("%v: serial %v", a.Role, v.Value)
				}
				if spec.Object("1.0.12.7.0.255", 2) != nil || spec.Object("1.0.32.7.0.255", 2) != nil {
					ln := "1.0.12.7.0.255"
					if spec.Object(ln, 2) == nil {
						ln = "1.0.32.7.0.255"
					}
					su, err := c.Get(3, ln, 3)
					if err != nil {
						t.Fatalf("%v: scaler_unit: %v", a.Role, err)
					}
					if sc, unit, err := cosem.ScalerUnit(su); err != nil || sc != -2 || unit != 35 {
						t.Errorf("%v: voltage scaler %d unit %d %v", a.Role, sc, unit, err)
					}
				}
				for _, p := range spec.Profiles {
					rights := p.Access.Of(a.Role)
					_, err := c.Get(7, p.OBIS, 2)
					switch {
					case rights&is15959.Read != 0 && err != nil:
						t.Errorf("%v: profile %s: %v", a.Role, p.OBIS, err)
					case rights&is15959.Read == 0 && rights != 0 && err == nil:
						t.Errorf("%v: profile %s read without the right", a.Role, p.OBIS)
					}
					break
				}
			}
		})
	}
}

// The meter acts on its methods: a remote disconnect and reconnect log
// events 301 and 302 in the control log; the billing script captures a
// billing entry; RaiseEvent logs an event.
//
// Covers: SIG-IPE-6461
func TestActions(t *testing.T) {
	spec, _ := is15959.Get("part2-3ph")
	m, err := meter.New(spec, meter.Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := m.ListenWrapper("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var us meter.Association
	for _, a := range m.Associations {
		if a.Role == is15959.US {
			us = a
		}
	}
	hx := hex.EncodeToString
	c := connect(t, addr, int(us.Client), cosem.SecurityConfig{Authentication: "hls-aes", Password: string(us.Secret),
		Security: "authenticated-encrypted", BlockCipherKey: hx(us.Key), AuthenticationKey: hx(us.AuthKey)})
	var control *is15959.EventLog
	for i := range spec.Events {
		for _, e := range spec.Events[i].Codes {
			if e.Code == 301 {
				control = &spec.Events[i]
			}
		}
	}
	if control == nil {
		t.Fatal("the profile has no control log")
	}
	before, _ := m.Object(7, control.OBIS)
	n0 := rowsOf(t, before)
	for _, method := range []int8{1, 2} {
		if err := c.Association().Client.ActionRequest(gdlms.CreateMethodDescriptor(70, is15959.DisconnectControl, method), axdr.CreateAxdrInteger(0)); err != nil {
			t.Fatalf("method %d: %v", method, err)
		}
	}
	if n := rowsOf(t, before); n != n0+2 {
		t.Errorf("control log entries %d, want %d", n, n0+2)
	}
	if v, err := c.Get(1, control.CodeOBIS, 2); err != nil || v.Value.(uint16) != 302 {
		t.Errorf("event code %v %v", v.Value, err)
	}
	if !m.RaiseEvent(302, time.Now()) {
		t.Error("RaiseEvent found no log")
	}
	m.Recapture(time.Now())
}

func rowsOf(t *testing.T, o classes.Object) int {
	t.Helper()
	pg, ok := o.(*classes.ProfileGeneric)
	if !ok {
		t.Fatalf("%T is not a profile", o)
	}
	pg.Lock()
	defer pg.Unlock()
	return len(pg.Buffer)
}
