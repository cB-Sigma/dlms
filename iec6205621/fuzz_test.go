package iec6205621

import (
	"bytes"
	"testing"
	"time"
)

// Covers: SIG-IPE-290
// Covers: SIG-IPE-1261
func FuzzMessages(f *testing.F) {
	f.Add(Block("", "1.8.0(001234.5*kWh)\r\n!\r\n", false, ETX))
	f.Add(Block("P0", "(12345678)", true, ETX))
	f.Add([]byte("/ISk5MT174\r\n"))
	f.Add([]byte("P.01(2609230000)(00)(15)(1)(1.5.0)(kW)\r\n(1)(2)\r\n"))
	f.Add([]byte("/XXX3Ident\r\n\r\n1.8.0(1*kWh)\r\n!\r\n"))
	f.Add([]byte("1.8.0(1*kWh)\r\n!\r\n"))
	f.Add([]byte(`/XXX5\2\KIdent`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := ReadMessage(bytes.NewReader(b), true); err == nil {
			if ds, err := ParseDataSets(m.Data); err == nil {
				_, _ = ParseProfile(ds, "P.01", time.UTC)
			}
		}
		_, _ = ParseIdentification(string(b))
		if m, err := ReadDataMessage(bytes.NewReader(b)); err == nil {
			_, _ = ParseDataSets(m.Data)
		}
		if push, err := ReadPush(bytes.NewReader(b)); err == nil {
			_, _ = ParseDataSets(push.Data)
		}
		if ds, err := ParseDataSets(string(b)); err == nil {
			_, _ = ParseProfile(ds, "P.01", time.UTC)
			for _, d := range ds {
				_ = PointName(d.Address)
			}
		}
	})
}
