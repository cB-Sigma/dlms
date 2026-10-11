package hdlc

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// connTransport is a gosem transport over one end of a pipe.
type connTransport struct {
	c         net.Conn
	mu        sync.Mutex
	dc        gdlms.DataChannel
	connected bool
	started   bool
	tap       func(b []byte) // sees what we write
}

func (t *connTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = true
	if !t.started {
		t.started = true
		go func() {
			buf := make([]byte, 512)
			for {
				n, err := t.c.Read(buf)
				if n > 0 {
					t.mu.Lock()
					dc := t.dc
					t.mu.Unlock()
					if dc != nil {
						dc <- append([]byte(nil), buf[:n]...)
					}
				}
				if err != nil {
					t.mu.Lock()
					t.connected = false
					t.mu.Unlock()
					return
				}
			}
		}()
	}
	return nil
}
func (t *connTransport) Disconnect() error { return nil }
func (t *connTransport) Close() {
	_ = t.c.Close()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
		t.dc = nil
	}
}
func (t *connTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}
func (t *connTransport) SetAddress(int, int) {}
func (t *connTransport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dc = dc
}
func (t *connTransport) Send(b []byte) error {
	if t.tap != nil {
		t.tap(b)
	}
	_, err := t.c.Write(b)
	return err
}
func (t *connTransport) SetLogger(*log.Logger) {}

// wire records the frames written in one direction and may drop some.
type wire struct {
	mu     sync.Mutex
	w      io.Writer
	frames []Frame
	drop   func(n int, f Frame) bool
}

func (w *wire) Write(b []byte) (int, error) {
	f, err := Decode(b)
	w.mu.Lock()
	n := len(w.frames)
	if err == nil {
		w.frames = append(w.frames, f)
	}
	drop := w.drop != nil && err == nil && w.drop(n, f)
	w.mu.Unlock()
	if drop {
		return len(b), nil
	}
	return w.w.Write(b)
}

func (w *wire) kinds() []Frame {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Frame(nil), w.frames...)
}

// tapped is a connection whose writes go through a wire.
type tapped struct {
	net.Conn
	w io.Writer
}

func (t tapped) Write(b []byte) (int, error) { return t.w.Write(b) }

// pipeLink starts a station on one end of a pipe and a client on the other.
func pipeLink(t *testing.T, st *Station, cfg Config, down *wire) (*Client, *wire, chan []byte) {
	t.Helper()
	ours, theirs := net.Pipe()
	down.w = theirs
	go func() { _ = st.Serve(tapped{theirs, down}); _ = theirs.Close() }()
	up := &wire{}
	tr := &connTransport{c: ours}
	tr.tap = func(b []byte) { _, _ = up.Write(b) }
	up.w = io.Discard
	if cfg.ResponseTimeout == 0 {
		cfg.ResponseTimeout = time.Second
	}
	c, err := NewClient(tr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	dc := make(gdlms.DataChannel, 4)
	c.SetReception(dc)
	t.Cleanup(c.Close)
	return c, up, dc
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

// A request longer than the negotiated information field goes in
// segments, one window at a time, each window acknowledged by RR; the
// answer comes in windows of up to seven frames, the last of each with F
// and, while more follows, the segmentation bit, and we poll for the rest
// with RR (6.4.4.4.3.4 to 6.4.4.4.3.6, 6.4.4.5). Table 8's parameters are
// negotiated.
//
// Covers: SIG-IPE-1203, SIG-IPE-1204, SIG-IPE-1207, SIG-IPE-1209
func TestClientSegmentsAndWindows(t *testing.T) {
	var got [][]byte
	answer := pattern(2000, 3)
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Own: Params{MaxInfoTX: 128, MaxInfoRX: 64, WindowTX: 7, WindowRX: 7},
		Handle: func(client int, apdu []byte, unconfirmed bool) []byte {
			got = append(got, append([]byte(nil), apdu...))
			return answer
		}}
	down := &wire{}
	c, up, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2),
		Propose: &Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 1, WindowRX: 7}}, down)
	if err := c.Send([]byte{1}); !errors.Is(err, ErrNoLink) {
		t.Fatalf("send before SNRM: %v", err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if p := c.Params(); p != (Params{MaxInfoTX: 64, MaxInfoRX: 128, WindowTX: 1, WindowRX: 7}) {
		t.Fatalf("negotiated %+v", p)
	}
	req := pattern(300, 9)
	if err := c.Send(req); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-dc:
		if !bytes.Equal(a, answer) {
			t.Fatalf("answer of %d octets differs", len(a))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no answer delivered")
	}
	if len(got) != 1 || !bytes.Equal(got[0], req) {
		t.Fatalf("the station got %d requests", len(got))
	}
	// Our I frames: 303 octets (LLC E6 E6 00 first) in 64-octet
	// segments, each with P (window 1), all but the last segmented.
	var is []Frame
	for _, f := range up.kinds() {
		if ParseControl(f.Control).Kind == KindI {
			is = append(is, f)
		}
	}
	if len(is) != 5 || !bytes.Equal(is[0].Info[:3], LLCCommand) {
		t.Fatalf("%d I frames", len(is))
	}
	for i, f := range is {
		c := ParseControl(f.Control)
		if !c.PF || c.NS != i || f.Segmented != (i < 4) || len(f.Info) > 64 {
			t.Errorf("I frame %d: %+v segmented %v, %d octets", i, c, f.Segmented, len(f.Info))
		}
	}
	// Their answer: 2003 octets in 16 frames of up to 128, windows of 7:
	// F on frames 7, 14 and 16; the segmentation bit on all but the last.
	var ans []Frame
	for _, f := range down.kinds() {
		if ParseControl(f.Control).Kind == KindI {
			ans = append(ans, f)
		}
	}
	if len(ans) != 16 {
		t.Fatalf("%d answer frames", len(ans))
	}
	for i, f := range ans {
		c := ParseControl(f.Control)
		wantF := i == 6 || i == 13 || i == 15
		if c.PF != wantF || f.Segmented != (i < 15) || c.NS != i%8 || len(f.Info) > 128 {
			t.Errorf("answer frame %d: %+v segmented %v", i, c, f.Segmented)
		}
	}
	if !bytes.Equal(ans[0].Info[:3], LLCResponse) {
		t.Errorf("the answer starts % X", ans[0].Info[:3])
	}
	// A second exchange carries on the numbering.
	answer = []byte{0xC4, 0x01}
	if err := c.Send([]byte{0xC0, 0x01}); err != nil {
		t.Fatal(err)
	}
	if a := <-dc; !bytes.Equal(a, answer) {
		t.Fatalf("second answer % X", a)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if c.IsConnected() {
		t.Error("connected after DISC")
	}
	last := up.kinds()[len(up.kinds())-1]
	if ParseControl(last.Control).Kind != KindDISC {
		t.Errorf("the last frame sent is %v", ParseControl(last.Control).Kind)
	}
}

// 6.4.4.9: a lost answer frame is a sequence error recovered by the poll
// (go back to N(R)); a lost whole answer is a response time-out recovered
// with an RR poll, never by sending the I frame again; FRMR and DM end the
// link; the station drops the link after the inactivity time-out and
// answers DM, and the client connects again with SNRM.
//
// Covers: SIG-IPE-1205, SIG-IPE-1207
func TestClientRecovery(t *testing.T) {
	answer := pattern(500, 1)
	calls := 0
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Inactivity: 400 * time.Millisecond,
		Own:    Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 7, WindowRX: 1},
		Handle: func(int, []byte, bool) []byte { calls++; return answer }}
	dropped := 0
	down := &wire{drop: func(n int, f Frame) bool {
		c := ParseControl(f.Control)
		// The second answer frame of the first exchange, then the whole
		// first window of the second.
		if c.Kind == KindI && dropped == 0 && c.NS == 1 {
			dropped++
			return true
		}
		if c.Kind == KindI && dropped >= 1 && dropped < 5 && calls == 2 {
			dropped++
			return true
		}
		return false
	}}
	c, up, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), ResponseTimeout: 150 * time.Millisecond,
		Propose: &Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 1, WindowRX: 4}}, down)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		if err := c.Send([]byte{0xC0, byte(round)}); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if a := <-dc; !bytes.Equal(a, answer) {
			t.Fatalf("round %d: answer of %d octets differs", round, len(a))
		}
	}
	if calls != 2 {
		t.Errorf("the station handled %d requests, want 2 (an I frame was repeated)", calls)
	}
	var iFrames int
	for _, f := range up.kinds() {
		if ParseControl(f.Control).Kind == KindI {
			iFrames++
		}
	}
	if iFrames != 2 {
		t.Errorf("we sent %d I frames, want 2: recovery polls with RR", iFrames)
	}
	// Inactivity: the station falls back to NDM and answers DM.
	time.Sleep(600 * time.Millisecond)
	if err := c.Send([]byte{0xC0, 3}); !errors.Is(err, ErrLinkLost) {
		t.Fatalf("after the inactivity time-out: %v", err)
	}
	if c.IsConnected() {
		t.Error("still connected after DM")
	}
	if err := c.Connect(); err != nil {
		t.Fatalf("SNRM again: %v", err)
	}
	if err := c.Send([]byte{0xC0, 4}); err != nil {
		t.Fatal(err)
	}
	<-dc
	// An information field longer than the station takes: FRMR.
	c.mu.Lock()
	c.params.MaxInfoTX = 200
	c.mu.Unlock()
	if err := c.Send(pattern(190, 0)); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized frame: %v", err)
	}
	if c.IsConnected() {
		t.Error("still connected after FRMR (6.4.4.9.4: SNRM first)")
	}
}

// UI frames: an unconfirmed APDU goes in one UI frame with P 0 and is never
// answered (IEC 62056-7-6 9.1); the station keeps an event notification
// until it has the right to talk and sends it from the management logical
// device to the client management process just before its answer, or on
// an empty UI frame with P 1 (6.4.4.7, IEC 62056-7-6 9.4).
//
// Covers: SIG-IPE-1210, SIG-IPE-1211
func TestUIFrames(t *testing.T) {
	var unconfirmed [][]byte
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Handle: func(_ int, apdu []byte, u bool) []byte {
		if u {
			unconfirmed = append(unconfirmed, apdu)
			return nil
		}
		return []byte{0xC4, 0x01, 0x81, 0x00}
	}}
	events := make(chan []byte, 4)
	down := &wire{}
	c, up, dc := pipeLink(t, st, Config{Client: 0x30, Server: ServerAddress(1, 0x11, 2),
		OnUI: func(from Address, apdu []byte) {
			if from.Upper != ManagementDevice {
				t.Errorf("event from %v", from)
			}
			events <- apdu
		}}, down)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendBroadcast([]byte{0xC1, 0x01, 0x01}); err != nil {
		t.Fatal(err)
	}
	st.Queue([]byte{0xC2, 0x00, 0x01})
	if err := c.Send([]byte{0xC0, 0x01}); err != nil {
		t.Fatal(err)
	}
	if a := <-dc; a[0] != 0xC4 {
		t.Fatalf("answer % X", a)
	}
	select {
	case e := <-events:
		if !bytes.Equal(e, []byte{0xC2, 0x00, 0x01}) {
			t.Errorf("event % X", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event notification")
	}
	if len(unconfirmed) != 1 || unconfirmed[0][0] != 0xC1 {
		t.Errorf("unconfirmed requests %v", unconfirmed)
	}
	for _, f := range up.kinds() {
		if k := ParseControl(f.Control); k.Kind == KindUI && (k.PF || f.Segmented) {
			t.Errorf("our UI frame has P or the segmentation bit")
		}
	}
	var ui Frame
	for _, f := range down.kinds() {
		if ParseControl(f.Control).Kind == KindUI {
			ui = f
		}
	}
	if ui.Dest.Upper != ClientManagement || ui.Src.Upper != ManagementDevice || ParseControl(ui.Control).PF {
		t.Errorf("event UI frame %+v", ui)
	}
	// Right to talk from an empty UI with P 1: the last pending UI has F.
	st.Queue([]byte{0xC2, 0x00, 0x02})
	if err := c.Trigger(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e[2] != 0x02 {
			t.Errorf("event % X", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event after the trigger")
	}
	fr := down.kinds()
	if f := fr[len(fr)-1]; ParseControl(f.Control) != (Control{Kind: KindUI, PF: true}) {
		t.Errorf("the flushed UI frame is %+v", ParseControl(f.Control))
	}
	// Too long for one UI frame: refused (6.4.4.4.3.4).
	if err := c.SendBroadcast(make([]byte, 200)); err == nil {
		t.Error("an APDU longer than one UI frame was sent")
	}
}

// Table 5 and Table 10: which destination addresses a station takes, and
// that only UI frames with P 0 may be broadcast (6.4.2.4, 6.4.4.6).
//
// Covers: SIG-IPE-1208, SIG-IPE-1209
func TestStationAddressing(t *testing.T) {
	s4 := &Station{Upper: 0x21, Lower: 0x1234, Size: 4}
	s2 := &Station{Upper: 0x21, Lower: 0x22, Size: 2}
	s1 := &Station{Upper: 0x21, Size: 1}
	cases := []struct {
		s             *Station
		d             Address
		ok, broadcast bool
	}{
		{s4, ServerAddress(0x21, 0x1234, 4), true, false},
		{s4, ServerAddress(0x22, 0x1234, 4), false, false},
		{s4, ServerAddress(0x21, 0x3FFF, 4), true, true},   // Table 10: individual upper, all physical
		{s4, ServerAddress(0x3FFF, 0x1234, 4), true, true}, // all logical devices of this one
		{s4, ServerAddress(0x3FFF, 0x3FFF, 4), true, true}, // everybody
		{s4, ServerAddress(0x21, 0x3FFE, 4), false, false}, // CALLING, not calling
		{s4, ServerAddress(0x21, 0x7F, 2), true, true},     // Table 5: two octets taken as four
		{s4, ServerAddress(0x21, 0, 1), false, false},      // Table 5: one octet discarded
		{s2, ServerAddress(0x21, 0x22, 2), true, false},    //
		{s2, ServerAddress(0x21, 0x3FFF, 4), false, false}, // Table 5: all-station lower needs all-station upper
		{s2, ServerAddress(0x3FFF, 0x3FFF, 4), true, true}, //
		{s2, ServerAddress(0x01, 0x3FFE, 4), false, false}, // CALLING without CALLING DEVICE
		{s1, ServerAddress(0x21, 0, 1), true, false},       //
		{s1, ServerAddress(0x21, 0x7F, 2), true, true},     // Table 5: lower all-station only
		{s1, ServerAddress(0x21, 0x22, 2), false, false},   //
		{s1, ServerAddress(0x3FFF, 0x3FFF, 4), true, true}, //
		{s1, ServerAddress(0x21, 0x3FFF, 4), false, false}, //
		{s1, ServerAddress(0x7F, 0, 1), true, true},        // all-station
		{&Station{Upper: 1, Lower: 0x1234, Size: 4, Calling: true}, ServerAddress(1, 0x3FFE, 4), true, false},
		{&Station{Upper: 1, Lower: 0x22, Size: 2, Calling: true}, ServerAddress(1, 0x3FFE, 4), true, false},
	}
	for i, tc := range cases {
		ok, b := tc.s.accepts(tc.d)
		if ok != tc.ok || (ok && b != tc.broadcast) {
			t.Errorf("%d: station %d/%#x (%d) to %v: %v %v, want %v %v", i, tc.s.Upper, tc.s.Lower, tc.s.Size, tc.d, ok, b, tc.ok, tc.broadcast)
		}
	}
	// Broadcast: UI with P 0 is handled; UI with P 1, I and SNRM are not.
	var handled int
	st := &Station{Upper: 1, Lower: 0x22, Size: 2, Handle: func(int, []byte, bool) []byte { handled++; return nil }}
	var out bytes.Buffer
	info := append(append([]byte(nil), LLCCommand...), 0xC1)
	all := ServerAddress(AllStation, AllStation, 2)
	for _, f := range []Frame{
		{Dest: all, Src: ClientAddress(0x66), Control: ctl(KindUI, false), Info: info},
		{Dest: all, Src: ClientAddress(0x66), Control: ctl(KindUI, true), Info: info},
		{Dest: all, Src: ClientAddress(0x66), Control: ctlI(0, 0, false), Info: info},
		{Dest: all, Src: ClientAddress(0x66), Control: ctl(KindSNRM, true)},
		{Dest: ServerAddress(1, 0x22, 2), Src: ServerAddress(0x66, 1, 2), Control: ctl(KindSNRM, true)}, // two-octet source
	} {
		if err := st.frame(&out, f); err != nil {
			t.Fatal(err)
		}
	}
	if handled != 1 || out.Len() != 0 || st.linked {
		t.Errorf("broadcast handling: %d handled, %d octets answered, linked %v", handled, out.Len(), st.linked)
	}
	// An LLC header with the broadcast destination LSAP 0xFF is taken.
	if _, ok := splitLLC([]byte{0xFF, 0xE6, 0x00, 1}, false); !ok {
		t.Error("destination LSAP FF refused")
	}
	if _, ok := splitLLC([]byte{0xE6, 0xE7, 0x00, 1}, false); ok {
		t.Error("a response LLC header was taken as a command")
	}
	// In NDM, I and RR with P get DM.
	nd := &Station{Upper: 1, Lower: 0x22, Size: 2}
	out.Reset()
	_ = nd.frame(&out, Frame{Dest: ServerAddress(1, 0x22, 2), Src: ClientAddress(0x10), Control: ctlRR(0, true)})
	if f, err := Decode(out.Bytes()); err != nil || ParseControl(f.Control).Kind != KindDM {
		t.Errorf("RR in NDM answered %v %v", f, err)
	}
	// An SNRM with a parameter this profile does not have gets DM.
	out.Reset()
	_ = nd.frame(&out, Frame{Dest: ServerAddress(1, 0x22, 2), Src: ClientAddress(0x10), Control: ctl(KindSNRM, true), Info: []byte{0x81, 0x80, 0x03, 0x0A, 0x01, 0x01}})
	if f, err := Decode(out.Bytes()); err != nil || ParseControl(f.Control).Kind != KindDM {
		t.Errorf("SNRM with a foreign parameter answered %v %v", f, err)
	}
}
