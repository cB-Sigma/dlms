package hdlc

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Annex A.1: the two-octet frame 03 3F has the FCS 5B EC (sent least
// significant octet first), and a good frame leaves 0xF0B8 (A.3). Annex
// A.3 prints the table the fast method uses; some of its entries.
//
// Covers: SIG-IPE-1200
func TestFCSAnnexA(t *testing.T) {
	if got := FCS([]byte{0x03, 0x3F}); got != 0xEC5B {
		t.Fatalf("FCS(03 3F) = %04X, want EC5B (octets 5B EC)", got)
	}
	if !GoodFCS([]byte{0x03, 0x3F, 0x5B, 0xEC}) {
		t.Error("03 3F 5B EC does not leave the good FCS value F0B8")
	}
	if GoodFCS([]byte{0x03, 0x3E, 0x5B, 0xEC}) {
		t.Error("a corrupted frame passed the FCS check")
	}
	for i, want := range map[int]uint16{0: 0x0000, 1: 0x1189, 2: 0x2312, 7: 0x74BF, 8: 0x8C48, 0x80: 0x8408, 0x81: 0x9581, 0xF8: 0x7BC7, 0xFF: 0x0F78} {
		if fcsTable[i] != want {
			t.Errorf("fcstab[%#x] = %04X, want %04X", i, fcsTable[i], want)
		}
	}
}

// 6.4.2.3: client 3A to server upper 1234, lower 3FFF (all-station) with
// four-octet addressing gives the address octets 48 68 FE FF and 75.
//
// Covers: SIG-IPE-1201
func TestAddressExample(t *testing.T) {
	dest := ServerAddress(0x1234, AllStation2, 4)
	d, err := dest.Encode()
	if err != nil || !bytes.Equal(d, []byte{0x48, 0x68, 0xFE, 0xFF}) {
		t.Fatalf("destination % X %v, want 48 68 FE FF", d, err)
	}
	s, _ := ClientAddress(0x3A).Encode()
	if !bytes.Equal(s, []byte{0x75}) {
		t.Fatalf("source % X, want 75", s)
	}
	got, n, err := DecodeAddress(append(d, s...))
	if err != nil || n != 4 || got != dest || !got.LowerAllStation() || got.UpperAllStation() {
		t.Errorf("decoded %v (%d octets, %v)", got, n, err)
	}
	// One and two octets: seven bits a part.
	for _, a := range []Address{ServerAddress(1, 0, 1), ServerAddress(0x7F, 0, 1), ServerAddress(1, 0x11, 2), ServerAddress(0x7F, 0x7F, 2), ServerAddress(1, 0x3FFE, 4)} {
		b, err := a.Encode()
		if err != nil || len(b) != a.Size || b[len(b)-1]&1 != 1 {
			t.Errorf("%v: % X %v", a, b, err)
			continue
		}
		for _, x := range b[:len(b)-1] {
			if x&1 != 0 {
				t.Errorf("%v: extension bit set before the last octet: % X", a, b)
			}
		}
		if back, _, err := DecodeAddress(b); err != nil || back != a {
			t.Errorf("%v came back as %v (%v)", a, back, err)
		}
	}
	// Three octets, five octets and an unterminated field are refused.
	for _, b := range [][]byte{{0x02, 0x04, 0x07}, {0x02, 0x02, 0x02, 0x02, 0x03}, {0x02, 0x02}} {
		if _, _, err := DecodeAddress(b); err == nil {
			t.Errorf("% X was accepted", b)
		}
	}
	for _, a := range []Address{{Upper: 0x80, Size: 1}, {Upper: 1, Lower: 0x80, Size: 2}, {Upper: 0x4000, Lower: 1, Size: 4}, {Upper: 1, Size: 3}} {
		if _, err := a.Encode(); err == nil {
			t.Errorf("%+v was encoded", a)
		}
	}
	// Table 4 reserved values.
	if AllStationFor(1) != 0x7F || AllStationFor(2) != 0x7F || AllStationFor(4) != 0x3FFF || CallingFor(1) != 0x7E || CallingFor(4) != 0x3FFE {
		t.Error("reserved addresses differ from Table 4")
	}
}

// Table 7: the control field of each frame type, with and without P/F.
//
// Covers: SIG-IPE-1202
func TestControlTable7(t *testing.T) {
	cases := []struct {
		c    Control
		want byte
	}{
		{Control{Kind: KindI, NR: 5, NS: 3, PF: true}, 0xB6},
		{Control{Kind: KindI, NR: 0, NS: 0}, 0x00},
		{Control{Kind: KindRR, NR: 3, PF: true}, 0x71},
		{Control{Kind: KindRR, NR: 7}, 0xE1},
		{Control{Kind: KindRNR, NR: 2, PF: true}, 0x55},
		{Control{Kind: KindSNRM, PF: true}, 0x93},
		{Control{Kind: KindDISC, PF: true}, 0x53},
		{Control{Kind: KindUA, PF: true}, 0x73},
		{Control{Kind: KindDM, PF: true}, 0x1F},
		{Control{Kind: KindDM}, 0x0F},
		{Control{Kind: KindFRMR, PF: true}, 0x97},
		{Control{Kind: KindUI}, 0x03},
		{Control{Kind: KindUI, PF: true}, 0x13},
	}
	for _, tc := range cases {
		if got := tc.c.Byte(); got != tc.want {
			t.Errorf("%v %+v = %02X, want %02X", tc.c.Kind, tc.c, got, tc.want)
		}
		if back := ParseControl(tc.want); back != tc.c {
			t.Errorf("%02X parsed as %+v, want %+v", tc.want, back, tc.c)
		}
	}
	for _, b := range []byte{0x09, 0x0D, 0x2F, 0xE3} { // REJ, SREJ, SABM, XID: not in the repertoire
		if k := ParseControl(b).Kind; k != KindUnknown {
			t.Errorf("%02X parsed as %v", b, k)
		}
	}
}

// 6.4.1: format type 3 with the segmentation bit and 11-bit length; one
// check sequence without information, HCS and FCS with it; frames
// without flags, too short, with a wrong length or check sequence, or with
// an all-station or no-station source are invalid (6.4.4.2.3).
//
// Covers: SIG-IPE-1200, SIG-IPE-1201
func TestFrameFormat(t *testing.T) {
	snrm := Frame{Dest: ServerAddress(1, 0x11, 2), Src: ClientAddress(0x10), Control: 0x93}
	b, err := snrm.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// 7E A0 08 02 23 21 93 HCS 7E: length 8, no information, one FCS.
	if !bytes.Equal(b[:7], []byte{0x7E, 0xA0, 0x08, 0x02, 0x23, 0x21, 0x93}) || len(b) != 10 || b[9] != 0x7E || !GoodFCS(b[1:9]) {
		t.Fatalf("SNRM % X", b)
	}
	i := Frame{Segmented: true, Dest: ClientAddress(0x10), Src: ServerAddress(1, 0x11, 2), Control: 0x10, Info: []byte{0xE6, 0xE7, 0x00, 0xC4}}
	b, _ = i.Encode()
	if b[1] != 0xA8 || int(b[2]) != len(b)-2 || !GoodFCS(b[1:9]) || !GoodFCS(b[1:len(b)-1]) {
		t.Fatalf("segmented I % X", b)
	}
	back, err := Decode(b)
	if err != nil || !back.Segmented || back.Control != 0x10 || !bytes.Equal(back.Info, i.Info) || back.Src != i.Src {
		t.Fatalf("decoded %+v %v", back, err)
	}
	bad := func(name string, mutate func([]byte) []byte, want error) {
		t.Helper()
		c := mutate(append([]byte(nil), b...))
		if _, err := Decode(c); err == nil || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	bad("no closing flag", func(c []byte) []byte { return c[:len(c)-1] }, ErrInvalid)
	bad("format type 1", func(c []byte) []byte { c[1] = 0x88 | c[1]&0x07; return c }, ErrInvalid)
	bad("wrong length", func(c []byte) []byte { c[2]++; return c }, ErrInvalid)
	bad("header octet changed", func(c []byte) []byte { c[5] ^= 0x10; return c }, ErrHCS)
	bad("information changed", func(c []byte) []byte { c[len(c)-4] ^= 1; return c }, ErrFCS)
	for _, src := range []Address{ServerAddress(AllStation, 0x11, 2), ServerAddress(1, AllStation, 2), ServerAddress(1, NoStation, 2), ClientAddress(AllStation)} {
		f := Frame{Dest: ClientAddress(0x10), Src: src, Control: 0x73}
		raw, _ := f.Encode()
		if _, err := Decode(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("source %v: %v, want invalid", src, err)
		}
	}
	// The information field may be up to 2030 octets, which fits the
	// 11-bit length with four-octet addressing.
	big := Frame{Dest: ServerAddress(1, 0x3FFD, 4), Src: ClientAddress(0x10), Control: 0x10, Info: make([]byte, MaxInfo)}
	if raw, err := big.Encode(); err != nil || len(raw) > MaxFrameLength+2 {
		t.Errorf("2030 octets: %d %v", len(raw), err)
	}
	big.Info = make([]byte, 2040)
	if _, err := big.Encode(); err == nil {
		t.Error("an information field past the 11-bit length was encoded")
	}
}

// 6.4.4.4.3.2: the negotiation field with the defaults (one-octet lengths)
// and the two-octet form of version 1 of the HDLC setup class, and Table
// 8's example with its result for both stations.
//
// Covers: SIG-IPE-1203
func TestNegotiation(t *testing.T) {
	one := []byte{0x81, 0x80, 0x12, 0x05, 0x01, 0x80, 0x06, 0x01, 0x80, 0x07, 0x04, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01}
	two := []byte{0x81, 0x80, 0x14, 0x05, 0x02, 0x00, 0x80, 0x06, 0x02, 0x00, 0x80, 0x07, 0x04, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01}
	if got := Defaults().Encode(nil); !bytes.Equal(got, one) {
		t.Errorf("defaults % X, want % X", got, one)
	}
	for _, b := range [][]byte{one, two, nil, {0x81, 0x80, 0x00}} {
		p, _, err := DecodeParams(b)
		if err != nil || p != Defaults() {
			t.Errorf("% X: %+v %v, want the defaults", b, p, err)
		}
	}
	if p := (Params{MaxInfoTX: 0x80, MaxInfoRX: 0x100, WindowTX: 1, WindowRX: 1}).Encode(nil); p[2] != 0x14 || p[4] != 2 {
		t.Errorf("a length over 255 does not use the two-octet form: % X", p)
	}
	// A value 0 or an absent parameter means the default.
	p, _, err := DecodeParams([]byte{0x81, 0x80, 0x06, 0x08, 0x04, 0x00, 0x00, 0x00, 0x07})
	if err != nil || p != (Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 1, WindowRX: 7}) {
		t.Errorf("only window-receive: %+v %v", p, err)
	}
	// Other parameters reject the SNRM (answered with DM).
	for _, b := range [][]byte{{0x81, 0x80, 0x03, 0x09, 0x01, 0x01}, {0x80, 0x80, 0x00}, {0x81, 0x80, 0x05, 0x05, 0x01}} {
		if _, _, err := DecodeParams(b); !errors.Is(err, ErrParams) {
			t.Errorf("% X: %v, want refused", b, err)
		}
	}
	// A user data subfield rides along (IEC 62056-7-6 9.3).
	enc := Defaults().Encode([]byte("hi"))
	if _, user, err := DecodeParams(enc); err != nil || string(user) != "hi" {
		t.Errorf("user data %q %v", user, err)
	}
	// Table 8.
	proposed := Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 1, WindowRX: 7}
	secondary := Params{MaxInfoTX: 128, MaxInfoRX: 64, WindowTX: 7, WindowRX: 7}
	res := Negotiate(proposed, secondary)
	if res != (Params{MaxInfoTX: 128, MaxInfoRX: 64, WindowTX: 7, WindowRX: 1}) {
		t.Errorf("Table 8 result %+v", res)
	}
	// Client to server 40h octets and window 1; server to client 80h and 7.
	if c := bounded(res.Mirror(), proposed); c != (Params{MaxInfoTX: 64, MaxInfoRX: 128, WindowTX: 1, WindowRX: 7}) {
		t.Errorf("the client's view %+v", c)
	}
}

// Figure 11: two frames sharing one flag; idle flags between frames; a gap
// longer than the inter-octet time-out drops a partial frame; 6.4.4.9.2: a
// frame with a header error takes the frames concatenated to it along.
//
// Covers: SIG-IPE-1206
func TestScanner(t *testing.T) {
	rr, _ := Frame{Dest: ClientAddress(0x10), Src: ServerAddress(1, 0x11, 2), Control: 0x31}.Encode()
	ui, _ := Frame{Dest: ClientAddress(0x01), Src: ServerAddress(1, 0x11, 2), Control: 0x03, Info: []byte{0xE6, 0xE7, 0, 1}}.Encode()
	shared := append(append([]byte(nil), rr...), ui[1:]...) // one flag between them
	var s Scanner
	got := s.Feed(shared, time.Now())
	if len(got) != 2 || !bytes.Equal(got[0], rr) || !bytes.Equal(got[1], ui) {
		t.Fatalf("shared flag: %d frames % X", len(got), got)
	}
	idle := append(append([]byte{0x7E, 0x7E, 0x7E}, rr...), 0x7E, 0x7E)
	idle = append(idle, ui...)
	if got := s.Feed(idle, time.Now()); len(got) != 2 {
		t.Errorf("idle flags: %d frames", len(got))
	}
	// Byte by byte works.
	var n int
	for _, x := range shared {
		n += len(s.Feed([]byte{x}, time.Now()))
	}
	if n != 2 {
		t.Errorf("byte by byte: %d frames", n)
	}
	// A gap past the inter-octet time-out ends the partial frame.
	s = Scanner{InterOctet: 25 * time.Millisecond}
	t0 := time.Now()
	s.Feed(rr[:5], t0)
	if got := s.Feed(rr[5:], t0.Add(30*time.Millisecond)); len(got) != 0 {
		t.Error("a frame broken by a gap was taken")
	}
	s.Feed(rr[:5], t0)
	if got := s.Feed(rr[5:], t0.Add(10*time.Millisecond)); len(got) != 1 {
		t.Error("a frame within the inter-octet time was lost")
	}
}
