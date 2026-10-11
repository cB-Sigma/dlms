package hdlc

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// ISO/IEC 13239 extended (modulo 128) control fields, from the bit strings
// in transmission order (bit 1 first): I is 0 N(S) in the first octet and
// P/F N(R) in the second; RR and RNR are 1 0 S S 0 0 0 0 then P/F N(R),
// with S 00 for RR and 10 for RNR; unnumbered frames keep one octet, and
// SNRME is 1111 P 011. A frame with a two-octet control field has its HCS
// over both octets. IEC 62056-46 (DLMS) uses modulo 8 only; this is for
// ISO/IEC 13239 peers.
//
// Covers: SIG-IPE-2706
func TestISO13239ExtendedControl(t *testing.T) {
	seven := func(v int) string {
		s := ""
		for i := 0; i < 7; i++ {
			s += string(rune('0' + v>>i&1))
		}
		return s
	}
	for _, pf := range []bool{false, true} {
		p := "0"
		if pf {
			p = "1"
		}
		for _, n := range [][2]int{{0, 0}, {1, 126}, {127, 5}, {64, 127}} {
			ns, nr := n[0], n[1]
			want := []byte{bitsLSB("0" + seven(ns)), bitsLSB(p + seven(nr))}
			c := cI(nr, ns, pf)
			if got := c.Encode(Modulo128); !bytes.Equal(got, want) {
				t.Errorf("I N(S) %d N(R) %d: % X, want % X", ns, nr, got, want)
			}
			if back := ParseControlModulo(want, Modulo128); back != c {
				t.Errorf("% X parsed %+v, want %+v", want, back, c)
			}
			for kind, s := range map[Kind]string{KindRR: "10000000", KindRNR: "10100000"} {
				c := Control{Kind: kind, NR: nr, PF: pf}
				want := []byte{bitsLSB(s), bitsLSB(p + seven(nr))}
				if got := c.Encode(Modulo128); !bytes.Equal(got, want) {
					t.Errorf("%v N(R) %d: % X, want % X", kind, nr, got, want)
				}
				if back := ParseControlModulo(want, Modulo128); back != c {
					t.Errorf("% X parsed %+v, want %+v", want, back, c)
				}
			}
		}
		want := bitsLSB("1111" + p + "011")
		if got := (Control{Kind: KindSNRME, PF: pf}).Encode(Modulo128); !bytes.Equal(got, []byte{want}) {
			t.Errorf("SNRME: % X, want %02X", got, want)
		}
		if c := ParseControl(want); c.Kind != KindSNRME || c.PF != pf {
			t.Errorf("%02X parsed %+v", want, c)
		}
		for _, k := range []Kind{KindSNRM, KindDISC, KindUA, KindDM, KindFRMR, KindUI} {
			if got := (Control{Kind: k, PF: pf}).Encode(Modulo128); len(got) != 1 || got[0] != (Control{Kind: k, PF: pf}).Byte() {
				t.Errorf("%v under modulo 128: % X", k, got)
			}
		}
	}
	if c := ParseControlModulo([]byte{0x02}, Modulo128); c.Kind != KindUnknown {
		t.Errorf("an I frame without its second octet parsed as %v", c.Kind)
	}
	if c := ParseControlModulo([]byte{0x09, 0x00}, Modulo128); c.Kind != KindUnknown {
		t.Errorf("REJ parsed as %v", c.Kind)
	}
	// Under modulo 8 the same calls give the one-octet field.
	if got := cI(3, 5, true).Encode(Modulo8); !bytes.Equal(got, []byte{ctlI(3, 5, true)}) {
		t.Errorf("modulo 8 I: % X", got)
	}

	// Frames: a two-octet control field, HCS over both octets.
	f := Frame{Dest: ServerAddress(1, 0x11, 2), Src: ClientAddress(0x10), Info: []byte{1, 2, 3}}
	cI(100, 120, true).set(&f, Modulo128)
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hdr := 2 + 2 + 1 + 2
	if b[1+2+3] != f.Control || b[1+2+3+1] != f.Control2 || FCS(b[1:1+hdr]) != uint16(b[1+hdr])|uint16(b[2+hdr])<<8 {
		t.Fatalf("frame % X: control or HCS misplaced", b)
	}
	g, err := DecodeModulo(b, Modulo128)
	if err != nil || !g.Extended || g.ControlField() != cI(100, 120, true) || !bytes.Equal(g.Info, f.Info) {
		t.Fatalf("decoded %+v %v", g, err)
	}
	if _, err := Decode(b); !errors.Is(err, ErrHCS) {
		t.Errorf("a modulo 128 I frame read as modulo 8: %v, want an HCS error", err)
	}
	// An unnumbered frame reads the same either way.
	u := Frame{Dest: ServerAddress(1, 0x11, 2), Src: ClientAddress(0x10), Control: ctl(KindSNRME, true)}
	b, _ = u.Encode()
	for _, m := range []int{Modulo8, Modulo128} {
		if g, err := DecodeModulo(b, m); err != nil || g.Extended || g.ControlField().Kind != KindSNRME {
			t.Errorf("modulo %d SNRME: %+v %v", m, g, err)
		}
	}
	// RR without information: two control octets and the FCS only.
	rr := Frame{Dest: ClientAddress(0x10), Src: ServerAddress(1, 0x11, 2)}
	cRR(77, true).set(&rr, Modulo128)
	b, _ = rr.Encode()
	if len(b) != 2+2+1+2+2+2 {
		t.Errorf("RR frame of %d octets", len(b))
	}
	if g, err := DecodeModulo(b, Modulo128); err != nil || g.ControlField() != cRR(77, true) {
		t.Errorf("RR decoded %+v %v", g, err)
	}

	// Parameters: windows above 7 need modulo 128.
	p := Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 127, WindowRX: 20}
	if p.Check() == nil || p.CheckModulo(Modulo128) != nil || (Params{MaxInfoTX: 1, MaxInfoRX: 1, WindowTX: 128, WindowRX: 1}).CheckModulo(Modulo128) == nil {
		t.Error("window limits per modulus")
	}
	if p.CheckModulo(16) == nil {
		t.Error("modulo 16 accepted")
	}
	if q, _, err := DecodeParams(p.Encode(nil)); err != nil || q != p {
		t.Errorf("windows of 127 and 20 round-trip as %+v %v", q, err)
	}
	if _, err := NewClient(&connTransport{}, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Propose: &p}); err == nil {
		t.Error("a window of 127 was accepted under modulo 8")
	}
	if _, err := NewClient(&connTransport{}, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Modulo: 64}); err == nil {
		t.Error("modulo 64 was accepted")
	}
}

// A modulo 128 link: SNRME and UA negotiate windows above 7, I and S frames
// carry two-octet control fields, an answer of 188 frames comes in a window
// of 127 and then one whose N(S) wraps past 127, a second exchange carries
// on the numbering, and an FRMR has the five-octet field of Figure 18b.
//
// Covers: SIG-IPE-1203, SIG-IPE-1204, SIG-IPE-2702
func TestModulo128Link(t *testing.T) {
	answer := pattern(3000, 5)
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Modulo128: true,
		Own:    Params{MaxInfoTX: 16, MaxInfoRX: 128, WindowTX: 127, WindowRX: 127},
		Handle: func(int, []byte, bool) []byte { return answer }}
	down := &wire{mod: Modulo128}
	c, up, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Modulo: Modulo128,
		Propose: &Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 20, WindowRX: 127}}, down)
	up.mod = Modulo128
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Modulo() != Modulo128 {
		t.Fatalf("modulo %d after SNRME", c.Modulo())
	}
	if p := c.Params(); p != (Params{MaxInfoTX: 128, MaxInfoRX: 16, WindowTX: 20, WindowRX: 127}) {
		t.Fatalf("negotiated %+v", p)
	}
	if k := up.kinds()[0].ControlField().Kind; k != KindSNRME {
		t.Fatalf("the link was set up with %v", k)
	}
	for round := 0; round < 2; round++ {
		if err := c.Send(pattern(300, byte(round))); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		select {
		case a := <-dc:
			if !bytes.Equal(a, answer) {
				t.Fatalf("round %d: answer of %d octets differs", round, len(a))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: no answer", round)
		}
	}
	// 3003 octets in 16-octet frames: 188 a round.
	var ans []Frame
	for _, f := range down.kinds() {
		if f.ControlField().Kind == KindI {
			ans = append(ans, f)
		}
	}
	if len(ans) != 2*188 {
		t.Fatalf("%d answer frames, want 376", len(ans))
	}
	for i, f := range ans {
		k := i % 188
		ctl := f.ControlField()
		wantF := k == 126 || k == 187
		if !f.Extended || ctl.NS != i%128 || ctl.PF != wantF || f.Segmented != (k < 187) {
			t.Fatalf("answer frame %d: %+v extended %v segmented %v", i, ctl, f.Extended, f.Segmented)
		}
	}
	// Our requests (303 octets, 3 frames, window 20) and polls are extended
	// too; N(S) carries on across rounds.
	var ns []int
	for _, f := range up.kinds() {
		ctl := f.ControlField()
		switch ctl.Kind {
		case KindI:
			ns = append(ns, ctl.NS)
			if !f.Extended {
				t.Errorf("I frame with a one-octet control field")
			}
		case KindRR:
			if !f.Extended {
				t.Errorf("RR with a one-octet control field")
			}
		}
	}
	if len(ns) != 6 || ns[3] != 3 || ns[5] != 5 {
		t.Errorf("our N(S) %v", ns)
	}
	// FRMR in the modulo 128 layout: an information field too long.
	c.mu.Lock()
	c.params.MaxInfoTX = 200
	c.mu.Unlock()
	err := c.Send(pattern(190, 0))
	var rej *RejectError
	if !errors.As(err, &rej) || rej.Modulo != Modulo128 || !rej.Y || len(rej.Raw) != 5 {
		t.Fatalf("oversized frame: %v (%+v)", err, rej)
	}
	if rej.Control&0xFF != 6<<1 || int(rej.Control>>9) != c.vr || rej.VR != 6 {
		t.Errorf("FRMR names control %#04x V(R) %d", rej.Control, rej.VR)
	}
}

// Modulo 128 negotiated: a station that does not take SNRME answers DM, and
// a client with ModuloFallback sets the link up with SNRM instead (windows
// brought down to 7); without the fallback the refusal is reported.
//
// Covers: SIG-IPE-1203
func TestModulo128Fallback(t *testing.T) {
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Own: Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 7, WindowRX: 7},
		Handle: func(int, []byte, bool) []byte { return []byte{0xC4, 0x01} }}
	c, up, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Modulo: Modulo128, ModuloFallback: true,
		Propose: &Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 30, WindowRX: 30}}, &wire{})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Modulo() != Modulo8 {
		t.Fatalf("modulo %d after the fallback", c.Modulo())
	}
	if p := c.Params(); p.WindowTX != 7 || p.WindowRX != 7 {
		t.Errorf("negotiated %+v", p)
	}
	fr := up.kinds()
	if len(fr) != 2 || fr[0].ControlField().Kind != KindSNRME || fr[1].ControlField().Kind != KindSNRM {
		t.Fatalf("set up with %v", fr)
	}
	if p, _, err := DecodeParams(fr[1].Info); err != nil || p.WindowTX != 7 || p.WindowRX != 7 {
		t.Errorf("the SNRM proposed %+v %v", p, err)
	}
	if err := c.Send([]byte{0xC0, 1}); err != nil {
		t.Fatal(err)
	}
	if a := <-dc; a[0] != 0xC4 {
		t.Errorf("answer % X", a)
	}

	st2 := &Station{Upper: 1, Lower: 0x11, Size: 2}
	c2, _, _ := pipeLink(t, st2, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Modulo: Modulo128}, &wire{})
	if err := c2.Connect(); !errors.Is(err, ErrRefused) {
		t.Errorf("SNRME without fallback: %v, want ErrRefused", err)
	}
}

// Sending segmented UI frames (opt-in, F-233): the client's unconfirmed
// APDU longer than the information field goes in UI frames with P 0, the
// segmentation bit on all but the last, and the station joins them; the
// station's queued event notification goes the same way to OnUI, with F
// only on its last frame.
//
// Covers: SIG-IPE-1210, SIG-IPE-1211
func TestSegmentedUISend(t *testing.T) {
	got := make(chan []byte, 2)
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, SegmentUI: true, Handle: func(_ int, apdu []byte, u bool) []byte {
		if u {
			got <- append([]byte(nil), apdu...)
			return nil
		}
		return []byte{0xC4, 0x01}
	}}
	events := make(chan []byte, 2)
	down := &wire{}
	c, up, _ := pipeLink(t, st, Config{Client: 0x30, Server: ServerAddress(1, 0x11, 2), SegmentUI: true,
		OnUI: func(_ Address, apdu []byte) { events <- apdu }}, down)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	long := pattern(300, 7)
	if err := c.SendBroadcast(long); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-got:
		if !bytes.Equal(a, long) {
			t.Fatalf("the station joined %d octets", len(a))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the segmented UI APDU did not arrive")
	}
	var ui []Frame
	for _, f := range up.kinds() {
		if f.ControlField().Kind == KindUI {
			ui = append(ui, f)
		}
	}
	if len(ui) != 3 { // 303 octets in 128-octet frames
		t.Fatalf("%d UI frames", len(ui))
	}
	for i, f := range ui {
		if f.ControlField().PF || f.Segmented != (i < 2) || len(f.Info) > 128 {
			t.Errorf("UI frame %d: P %v segmented %v, %d octets", i, f.ControlField().PF, f.Segmented, len(f.Info))
		}
	}
	// The station's side: a 400-octet notification after a trigger.
	ev := pattern(400, 1)
	st.Queue(ev)
	if err := c.Trigger(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if !bytes.Equal(e, ev) {
			t.Fatalf("event of %d octets differs", len(e))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no segmented event notification")
	}
	var sent []Frame
	for _, f := range down.kinds() {
		if f.ControlField().Kind == KindUI {
			sent = append(sent, f)
		}
	}
	if len(sent) != 4 { // 403 octets
		t.Fatalf("%d UI frames from the station", len(sent))
	}
	for i, f := range sent {
		if f.ControlField().PF != (i == 3) || f.Segmented != (i < 3) {
			t.Errorf("station UI frame %d: F %v segmented %v", i, f.ControlField().PF, f.Segmented)
		}
	}
}
