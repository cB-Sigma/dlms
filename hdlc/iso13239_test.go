package hdlc

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
)

// ISO/IEC 13239:2002 draws fields as bit strings in transmission order:
// bit 1 is sent first and is the lowest order bit of its octet. bitsLSB
// turns such a string (bit 1 first) into the octet it describes.
func bitsLSB(s string) byte {
	var b byte
	for i, c := range strings.ReplaceAll(s, " ", "") {
		if c == '1' {
			b |= 1 << i
		}
	}
	return b
}

// setBits sets bit n (1 = first sent) of a field to v's bits, lowest first,
// the way 13239 Figures 18a and 18b number them.
func setBits(field []byte, first, width, v int) {
	for i := 0; i < width; i++ {
		if v>>i&1 == 1 {
			n := first + i - 1
			field[n/8] |= 1 << (n % 8)
		}
	}
}

// 13239 5.5.3.2.1 Figure 11 and 5.5.3.2.2 Figure 12: the mode-setting
// format identifier and the HDLC parameters group identifier, and
// 5.5.3.2.3.1 Figure 14: the user data subfield identifier is all ones. The
// user data subfield (5.5.3.1.3 Figure 10) is the identifier and the data,
// with no length, and always comes last (5.5.3.2); a DISC carries only the
// format identifier and user data (Table 9). The old 0xF0 form is the
// user-defined parameters group, which we refuse like any group other than
// the HDLC parameters.
//
// Covers: SIG-IPE-2700, SIG-IPE-2701
func TestISO13239UserDataSubfield(t *testing.T) {
	if formatID != bitsLSB("10000001") || groupParams != bitsLSB("00000001") || userDataID != bitsLSB("11111111") {
		t.Fatalf("identifiers %#x %#x %#x do not match Figures 11, 12 and 14", formatID, groupParams, userDataID)
	}
	if bitsLSB("00001111") != 0xF0 {
		t.Fatal("the user-defined parameters group is 0xF0")
	}
	data := []byte{0x80, 0x05, 0x02, 0xFF, 0x00} // looks like a group and parameters: still data
	enc := Defaults().Encode(data)
	head := Defaults().Encode(nil)
	want := append(append(append([]byte(nil), head...), 0xFF), data...)
	if !bytes.Equal(enc, want) {
		t.Fatalf("SNRM field % X, want % X", enc, want)
	}
	p, user, err := DecodeParams(enc)
	if err != nil || p != Defaults() || !bytes.Equal(user, data) {
		t.Fatalf("decoded %+v % X %v", p, user, err)
	}
	// Format identifier and user data only: the parameters keep their
	// defaults (a DISC, or an SNRM with nothing to negotiate).
	disc := EncodeUserData([]byte("bye"))
	if !bytes.Equal(disc, []byte{0x81, 0xFF, 'b', 'y', 'e'}) {
		t.Fatalf("DISC field % X", disc)
	}
	if p, user, err := DecodeParams(disc); err != nil || p != Defaults() || string(user) != "bye" {
		t.Fatalf("DISC decoded %+v %q %v", p, user, err)
	}
	if EncodeUserData(nil) != nil {
		t.Error("no user data must mean no information field")
	}
	// Parameters, then user data with a non-default window.
	q := Params{MaxInfoTX: 300, MaxInfoRX: 128, WindowTX: 7, WindowRX: 3}
	if p, user, err := DecodeParams(q.Encode([]byte{1})); err != nil || p != q || !bytes.Equal(user, []byte{1}) {
		t.Errorf("parameters and user data: %+v % X %v", p, user, err)
	}
	// The user-defined parameters group (our earlier reading, F-231) is
	// not user data.
	for _, b := range [][]byte{{0x81, 0xF0, 0x02, 'h', 'i'}, {0x81, 0x80, 0x00, 0xF0, 0x02, 'h', 'i'}} {
		if _, _, err := DecodeParams(b); !errors.Is(err, ErrParams) {
			t.Errorf("% X: %v, want refused", b, err)
		}
	}
}

// 13239 5.5.3.4.2 Figures 18a and 18b: the FRMR information field, built
// here from the figures' bit numbers. Modulo 8: rejected control field bits
// 1-8, a zero bit 9, V(S) bits 10-12, C/R bit 13, V(R) bits 14-16, W X Y Z
// bits 17-20. Modulo 128: control bits 1-16, zero bit 17, V(S) 18-24, C/R
// 25, V(R) 26-32, W X Y Z 33-36. X comes with W. Padding to the octet is
// ignored on receipt.
//
// Covers: SIG-IPE-2702
func TestISO13239FRMRLayout(t *testing.T) {
	type tc struct {
		r FrameReject
	}
	for _, c := range []tc{
		{FrameReject{Modulo: 8, Control: 0x19, VS: 3, VR: 5, W: true}},
		{FrameReject{Modulo: 8, Control: 0x11, VS: 7, VR: 1, Response: true, W: true, X: true}},
		{FrameReject{Modulo: 8, Control: 0x32, VS: 0, VR: 6, Y: true}},
		{FrameReject{Modulo: 8, Control: 0xF1, VS: 2, VR: 7, Z: true}},
		{FrameReject{Modulo: 128, Control: 0x1234, VS: 100, VR: 7, Response: true, Z: true}},
		{FrameReject{Modulo: 128, Control: 0x0087, VS: 127, VR: 64, W: true, Y: true}},
	} {
		r := c.r
		b2i := func(v bool) int {
			if v {
				return 1
			}
			return 0
		}
		var want []byte
		reasons := b2i(r.W) | b2i(r.X)<<1 | b2i(r.Y)<<2 | b2i(r.Z)<<3
		if r.Modulo == 8 {
			want = make([]byte, 3)
			setBits(want, 1, 8, int(r.Control))
			setBits(want, 10, 3, r.VS)
			setBits(want, 13, 1, b2i(r.Response))
			setBits(want, 14, 3, r.VR)
			setBits(want, 17, 4, reasons)
		} else {
			want = make([]byte, 5)
			setBits(want, 1, 16, int(r.Control))
			setBits(want, 18, 7, r.VS)
			setBits(want, 25, 1, b2i(r.Response))
			setBits(want, 26, 7, r.VR)
			setBits(want, 33, 4, reasons)
		}
		got := r.Encode()
		if !bytes.Equal(got, want) {
			t.Errorf("%+v: % X, want % X", r, got, want)
		}
		back, err := DecodeFrameReject(append(got, 0x00), r.Modulo) // padded
		if err != nil || back != r {
			t.Errorf("% X decoded %+v %v, want %+v", got, back, err, r)
		}
	}
	// Figure 18a worked by hand: REJ with P rejected (W), V(S) 3, V(R) 5.
	if got := (FrameReject{Modulo: 8, Control: 0x19, VS: 3, VR: 5, W: true}).Encode(); !bytes.Equal(got, []byte{0x19, 0xA6, 0x01}) {
		t.Errorf("hand vector % X, want 19 A6 01", got)
	}
	if _, err := DecodeFrameReject([]byte{0x19, 0xA6}, 8); !errors.Is(err, ErrFRMRField) {
		t.Errorf("short field: %v", err)
	}
	if _, err := DecodeFrameReject([]byte{1, 2, 3, 4}, 128); !errors.Is(err, ErrFRMRField) {
		t.Errorf("short modulo 128 field: %v", err)
	}
	for r, want := range map[FrameReject]string{
		{W: true}:          "control field undefined or not implemented",
		{W: true, X: true}: "information field not permitted with this frame",
		{Y: true}:          "information field too long",
		{Z: true}:          "invalid N(R)",
		{}:                 "unspecified",
	} {
		if r.Reason() != want {
			t.Errorf("%+v: %q, want %q", r, r.Reason(), want)
		}
	}
}

// crcBitwise is the 16-bit check of 13239 4.2.5.2 and annex A worked the
// long way: the polynomial x^16+x^12+x^5+1 in its natural (not reflected)
// form, the bits fed in transmission order (each octet lowest bit first),
// the register preset to reg.
func crcBitwise(reg uint16, b []byte) uint16 {
	for _, c := range b {
		for i := 0; i < 8; i++ {
			in := uint16(c>>i) & 1
			top := reg >> 15
			reg <<= 1
			if top^in == 1 {
				reg ^= 0x1021
			}
		}
	}
	return reg
}

func reverse16(v uint16) uint16 {
	var r uint16
	for i := 0; i < 16; i++ {
		r = r<<1 | v>>i&1
	}
	return r
}

// 13239 4.2.5.2 and annex A: with the register preset to ones, a frame and
// its FCS leave the remainder 0001 1101 0000 1111 (x^15 to x^0), 0x1D0F,
// which our reflected table method holds bit-reversed as 0xF0B8. Annex A's
// alternative, a zero preset with the first 16 bits inverted, gives the
// same FCS, and inverting the received FCS brings the register to zero.
//
// Covers: SIG-IPE-2703
func TestISO13239FCS(t *testing.T) {
	if reverse16(0x1D0F) != 0xF0B8 {
		t.Fatal("0x1D0F reversed is 0xF0B8")
	}
	var frames [][]byte
	for _, f := range []Frame{
		{Dest: ServerAddress(1, 0x11, 2), Src: ClientAddress(0x10), Control: 0x93},
		{Dest: ClientAddress(0x10), Src: ServerAddress(0x1234, 0x3FFE, 4), Control: 0x10, Info: pattern(40, 3)},
	} {
		b, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, b[1:len(b)-1])
	}
	frames = append(frames, []byte{0x03, 0x3F, 0x5B, 0xEC})
	for _, fr := range frames {
		if got := crcBitwise(0xFFFF, fr); got != 0x1D0F {
			t.Errorf("% X: remainder %04X, want 1D0F", fr, got)
		}
		if !GoodFCS(fr) {
			t.Errorf("% X: GoodFCS false", fr)
		}
		data := fr[:len(fr)-2]
		// Zero preset, first 16 bits inverted, remainder inverted.
		inv := append([]byte(nil), data...)
		inv[0], inv[1] = ^inv[0], ^inv[1]
		fcs := reverse16(crcBitwise(0, inv)) ^ 0xFFFF
		if fcs != FCS(data) {
			t.Errorf("% X: zero-preset FCS %04X, table FCS %04X", data, fcs, FCS(data))
		}
		// Receiver: zero preset, first 16 bits and the FCS inverted.
		rx := append([]byte(nil), fr...)
		rx[0], rx[1] = ^rx[0], ^rx[1]
		rx[len(rx)-2], rx[len(rx)-1] = ^rx[len(rx)-2], ^rx[len(rx)-1]
		if got := crcBitwise(0, rx); got != 0 {
			t.Errorf("% X: register %04X after the inverted FCS, want 0", fr, got)
		}
	}
}

// 13239 4.9 Table 2 and annex H.4: frame format type 3 is 1010 in the top
// four bits, then the segmentation bit, then an 11-bit length of the octets
// between the flags; frames are 7 to 2047 octets; a frame without an
// information field has one check sequence (the FCS), with one it has an
// HCS after the control field as well, of the same polynomial. Lengths
// shorter than a frame (0 is an abort, 1 to 4 invalid, 4.9.2) are refused.
//
// Covers: SIG-IPE-2704
func TestISO13239FrameFormatType3(t *testing.T) {
	// Table 2 writes the format field most significant bit first.
	if formatType3>>4 != 0b1010 || segmentBit != 1<<3 || MaxFrameLength != 2047 {
		t.Fatalf("format %#x segment %#x max %d", formatType3, segmentBit, MaxFrameLength)
	}
	f := Frame{Dest: ClientAddress(0x10), Src: ServerAddress(1, 0x11, 2), Control: 0x10, Info: []byte{1, 2, 3}, Segmented: true}
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if b[1]&0xF0 != 0xA0 || b[1]&0x08 == 0 || int(b[1]&7)<<8|int(b[2]) != len(b)-2 {
		t.Errorf("format field % X for %d octets", b[1:3], len(b)-2)
	}
	// HCS over format, addresses and control; FCS over all but itself.
	hdr := 2 + 1 + 2 + 1
	if h := FCS(b[1 : 1+hdr]); uint16(b[1+hdr])|uint16(b[2+hdr])<<8 != h {
		t.Error("the HCS does not cover the header")
	}
	noInfo := Frame{Dest: ClientAddress(0x10), Src: ServerAddress(1, 0x11, 2), Control: 0x73}
	b, _ = noInfo.Encode()
	if len(b) != 2+hdr+2 {
		t.Errorf("a frame without information has %d octets, want one check sequence only", len(b))
	}
	// The largest frame fits, one more octet does not.
	big := Frame{Dest: ClientAddress(0x10), Src: ClientAddress(0x11), Control: 0x10, Info: make([]byte, 2047-2-1-1-1-2-2)}
	if _, err := big.Encode(); err != nil {
		t.Errorf("a 2047-octet frame: %v", err)
	}
	big.Info = append(big.Info, 0)
	if _, err := big.Encode(); err == nil {
		t.Error("a 2048-octet frame was encoded")
	}
	for _, n := range []int{0, 1, 4} {
		raw := []byte{Flag, 0xA0, byte(n), 0x21, 0x23, 0x93, 0x00, 0x00, Flag}
		if _, err := Decode(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("length %d: %v", n, err)
		}
	}
}

// 13239 4.7.1: address extension uses the first bit sent (the lowest
// order) of each octet, 0 when another octet follows and 1 on the last;
// 4.8.2 and 4.8.3: all ones is the all-station address and all zeros in
// the first octet the no-station address. IEC 62056-46 allows only 1, 2 and
// 4 octet fields, so 3 and 5 octet fields are refused (the 62056 profile
// narrows 13239's recursive extension).
//
// Covers: SIG-IPE-2705
func TestISO13239AddressExtension(t *testing.T) {
	for _, a := range []Address{ClientAddress(0x10), ServerAddress(0x12, 0x34, 2), ServerAddress(0x1234, 0x3FFF, 4)} {
		b, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		for i, o := range b {
			if last := i == len(b)-1; (o&1 == 1) != last {
				t.Errorf("%v octet %d % X: extension bit wrong", a, i, b)
			}
		}
	}
	if b, _ := ClientAddress(AllStation).Encode(); b[0] != 0xFF {
		t.Errorf("all-station % X, want FF", b)
	}
	if b, _ := ClientAddress(NoStation).Encode(); b[0]&0xFE != 0 {
		t.Errorf("no-station % X", b)
	}
	for _, b := range [][]byte{{0x02, 0x04, 0x07}, {0x02, 0x04, 0x06, 0x08, 0x0B}} {
		if _, _, err := DecodeAddress(b); err == nil {
			t.Errorf("% X: a %d-octet address was taken", b, len(b))
		}
	}
}

// 13239 5.3 and 5.5 Figures 15 and 17: the control fields we use, from the
// figures' bit strings (bit 1 first, P/F at bit 5): SNRM 1100P001, DISC
// 1100P010, UI 1100P000, UA 1100F110, DM 1111F000, FRMR 1110F001; RR 10 00
// P N(R), RNR 10 10 P N(R) (5.5.2); I 0 N(S) P N(R) with N(S) in bits 2-4
// and N(R) in bits 6-8, lowest bit first (5.3.1).
//
// Covers: SIG-IPE-2706
func TestISO13239ControlFields(t *testing.T) {
	for kind, bits := range map[Kind]string{
		KindSNRM: "11000001", KindDISC: "11000010", KindUI: "11000000",
		KindUA: "11000110", KindDM: "11110000", KindFRMR: "11100001",
	} {
		for _, pf := range []bool{false, true} {
			want := bitsLSB(bits)
			if pf {
				want |= 1 << 4
			}
			if got := (Control{Kind: kind, PF: pf}).Byte(); got != want {
				t.Errorf("%v P/F %v: %#02x, want %#02x", kind, pf, got, want)
			}
			if c := ParseControl(want); c.Kind != kind || c.PF != pf {
				t.Errorf("%#02x parsed %+v", want, c)
			}
		}
	}
	for nr := 0; nr < 8; nr++ {
		n := func(v int) string {
			return string(rune('0'+v&1)) + string(rune('0'+v>>1&1)) + string(rune('0'+v>>2&1))
		}
		if got := (Control{Kind: KindRR, NR: nr}).Byte(); got != bitsLSB("1000"+"0"+n(nr)) {
			t.Errorf("RR N(R) %d: %#02x", nr, got)
		}
		if got := (Control{Kind: KindRNR, NR: nr, PF: true}).Byte(); got != bitsLSB("1010"+"1"+n(nr)) {
			t.Errorf("RNR N(R) %d: %#02x", nr, got)
		}
		for ns := 0; ns < 8; ns++ {
			if got := ctlI(nr, ns, false); got != bitsLSB("0"+n(ns)+"0"+n(nr)) {
				t.Errorf("I N(S) %d N(R) %d: %#02x", ns, nr, got)
			}
		}
	}
}

// syncBuf is a log sink safe for the reader goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The client reads an FRMR's reason field (13239 5.5.3.4.2 Figure 18a),
// logs it and returns a link error naming it, which is still ErrRejected;
// the station fills in the rejected control field, its V(S) and V(R) and
// the reason bit.
//
// Covers: SIG-IPE-2707
func TestClientReportsFRMRReason(t *testing.T) {
	var events []string
	var emu sync.Mutex
	st := &Station{Upper: 1, Lower: 0x11, Size: 2,
		Handle: func(int, []byte, bool) []byte { return []byte{0xC4, 0x01} },
		Log:    func(e string) { emu.Lock(); events = append(events, e); emu.Unlock() }}
	c, _, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2)}, &wire{})
	logs := &syncBuf{}
	c.SetLogger(log.New(logs, "", 0))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.Send([]byte{0xC0, 1}); err != nil {
		t.Fatal(err)
	}
	<-dc
	// Too long for the station's 128 octets: Y.
	c.mu.Lock()
	c.params.MaxInfoTX = 200
	c.mu.Unlock()
	err := c.Send(pattern(190, 0))
	var rej *RejectError
	if !errors.As(err, &rej) || !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized frame: %v, want a RejectError", err)
	}
	// Our first I frame was N(S) 0 N(R) 0; the second (rejected) is
	// N(S) 1, N(R) 1, P 1; the station has sent one I frame and taken one.
	want := FrameReject{Modulo: 8, Control: uint16(ctlI(1, 1, true)), VS: 1, VR: 1, Y: true}
	if rej.FrameReject != want {
		t.Errorf("FRMR %+v, want %+v", rej.FrameReject, want)
	}
	if !strings.Contains(err.Error(), "information field too long") {
		t.Errorf("error %q does not name the reason", err)
	}
	if !strings.Contains(logs.String(), "FRMR from the server") || !strings.Contains(logs.String(), "information field too long") {
		t.Errorf("log %q does not report the FRMR reason", logs.String())
	}
	emu.Lock()
	defer emu.Unlock()
	if !strings.Contains(strings.Join(events, "\n"), "FRMR to client 0x10: information field too long") {
		t.Errorf("station events %q", events)
	}
	// An unreadable reason field still ends the link as ErrRejected.
	if err := rejectError([]byte{0x01}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("short FRMR field: %v", err)
	}
}
