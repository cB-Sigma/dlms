package cosem

import (
	"encoding/hex"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Covers: SIG-IPE-6400
func TestReadableOctetStrings(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+1800)
	oct := func(h string) axdr.DlmsData { return *axdr.CreateAxdrOctetString(h) }
	cases := []struct {
		name string
		d    axdr.DlmsData
		want any
	}{
		// The demo meter's nameplate as it read before the fix.
		{"manufacturer", oct("5349474d412053494d"), "SIGMA SIM"},
		{"serial number", oct("3030303031343031"), "00001401"},
		{"device id", oct("53474d3030303031343031"), "SGM00001401"},
		{"firmware version", oct("5635"), "V5"},
		// Maximum demand capture time: a COSEM date-time, deviation not
		// specified, so the meter's local time (IST).
		{"capture time", oct("07ea091c0101112900800000"), "2026-09-27T19:47:41Z"},
		// Neither text nor a date: stays hexadecimal.
		{"system title", oct("4d4d4d0000bc614e"), "4d4d4d0000bc614e"},
		{"key", oct(hex.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})), "000102030405060708090a0b"},
		{"number", *axdr.CreateAxdrLongUnsigned(5635), float64(5635)},
	}
	for _, c := range cases {
		if got := Readable(c.d, ist, false); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
