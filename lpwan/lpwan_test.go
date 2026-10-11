package lpwan_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/dlms/wrapper"
)

func frame(src, dst uint16, apdu []byte) []byte {
	f := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(f[0:], 1)
	binary.BigEndian.PutUint16(f[2:], src)
	binary.BigEndian.PutUint16(f[4:], dst)
	binary.BigEndian.PutUint16(f[6:], uint16(len(apdu)))
	return append(f, apdu...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// A meter calling from behind NAT gets its own conn, answered at its
// source address only while the reply window is open; datagrams that are
// not whole wrapper frames are dropped.
// Covers: SIG-IPE-3770
func TestUDPListenerReplyWindow(t *testing.T) {
	clk := &clock{t: time.Now()}
	var discarded int
	var dmu sync.Mutex
	l, err := lpwan.ListenUDP("127.0.0.1:0", lpwan.UDPOptions{ReplyWindow: 30 * time.Second, Now: clk.now,
		OnDiscard: func(net.Addr, error) { dmu.Lock(); discarded++; dmu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	meter, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer meter.Close()
	_, _ = meter.WriteTo([]byte{0, 1, 0, 1}, l.Addr()) // not a wrapper frame
	push := frame(1, 102, []byte{0x0F, 0, 0, 0, 1, 0, 0x09, 0x01})
	_, _ = meter.WriteTo(push, l.Addr())
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	h, apdu, err := wrapper.ReadWPDU(c)
	if err != nil || h.Src != 1 || apdu[0] != 0x0F {
		t.Fatalf("read %v % x %v", h, apdu, err)
	}
	if c.RemoteAddr().String() != meter.LocalAddr().String() {
		t.Fatalf("remote %s", c.RemoteAddr())
	}
	req := frame(48, 1, []byte{0xC0, 0x01, 0xC1})
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	_ = meter.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := meter.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], req) {
		t.Fatalf("meter got % x, %v", buf[:n], err)
	}
	clk.add(31 * time.Second)
	if _, err := c.Write(req); !errors.Is(err, lpwan.ErrReplyWindowClosed) {
		t.Fatalf("write after the window: %v", err)
	}
	// The next datagram reopens it, on the same conn.
	_, _ = meter.WriteTo(push, l.Addr())
	if _, _, err := wrapper.ReadWPDU(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	dmu.Lock()
	defer dmu.Unlock()
	if discarded != 1 {
		t.Fatalf("%d discarded", discarded)
	}
}

// The command queue is bounded, expires, retries on later calls and keeps
// its state across a restart.
// Covers: SIG-IPE-3771
func TestQueue(t *testing.T) {
	clk := &clock{t: time.Now()}
	q := lpwan.NewQueue(lpwan.QueueOptions{Max: 2, TTL: time.Hour, Attempts: 2, Now: clk.now})
	cmd := json.RawMessage(`{"action":"disconnect"}`)
	if _, err := q.Enqueue("M1", "c1", cmd, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue("M1", "c2", cmd, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue("M1", "c3", cmd, 0); !errors.Is(err, lpwan.ErrQueueFull) {
		t.Fatalf("third: %v", err)
	}
	clk.add(11 * time.Minute)
	due := q.Due("M1")
	if len(due) != 1 || due[0].ID != "c1" || due[0].Status != lpwan.Sent {
		t.Fatalf("due %+v", due)
	}
	if it := q.List("M1"); it[0].ID != "c2" && it[1].Status != lpwan.Expired {
		t.Fatalf("list %+v", it)
	}
	if it, _ := q.Finish("M1", "c1", errors.New("time-out"), false); it.Status != lpwan.Queued {
		t.Fatalf("after one failure: %s", it.Status)
	}
	snap := q.Snapshot()
	q2 := lpwan.NewQueue(lpwan.QueueOptions{Max: 2, TTL: time.Hour, Attempts: 2, Now: clk.now})
	q2.Restore(snap)
	due = q2.Due("M1")
	if len(due) != 1 || due[0].Attempts != 2 {
		t.Fatalf("restored due %+v", due)
	}
	if it, _ := q2.Finish("M1", "c1", errors.New("time-out"), false); it.Status != lpwan.Failed {
		t.Fatalf("after its attempts: %s", it.Status)
	}
	_, _ = q2.Enqueue("M1", "c4", cmd, 0)
	q2.Due("M1")
	if it, _ := q2.Finish("M1", "c4", nil, false); it.Status != lpwan.Done {
		t.Fatalf("done: %s", it.Status)
	}
	if q2.Waiting("M1") != 0 {
		t.Fatal("still waiting")
	}
}

// Wake tracking: awake for the active time after each datagram, overdue
// after two periods of silence.
// Covers: SIG-IPE-3772
func TestWakes(t *testing.T) {
	clk := &clock{t: time.Now()}
	w := lpwan.NewWakes(clk.now)
	s := lpwan.Sleep{ActiveTime: lpwan.Duration(20 * time.Second), Period: lpwan.Duration(time.Hour)}
	if err := s.Defaults(); err != nil {
		t.Fatal(err)
	}
	w.Configure("M1", s)
	w.Heard("M1", true)
	if ok, left := w.Listening("M1"); !ok || left != 20*time.Second {
		t.Fatalf("listening %v %v", ok, left)
	}
	clk.add(21 * time.Second)
	if ok, _ := w.Listening("M1"); ok {
		t.Fatal("still awake")
	}
	clk.add(2 * time.Hour)
	if st := w.State("M1"); !st.Overdue || st.Calls != 1 {
		t.Fatalf("state %+v", st)
	}
}

// Region limits and air time.
// Covers: SIG-IPE-3773
func TestRegion(t *testing.T) {
	r, err := lpwan.LookupRegion("in865")
	if err != nil || r.Payload(0) != 51 || r.Payload(5) != 242 || r.DutyCycle != 0 {
		t.Fatalf("IN865 %+v %v", r, err)
	}
	eu, _ := lpwan.LookupRegion("EU868")
	// SF7/125 kHz, 13 bytes: about 46 ms; SF12: about 1.3 s.
	if a := eu.Airtime(5, 13); a < 40*time.Millisecond || a > 52*time.Millisecond {
		t.Fatalf("SF7 airtime %v", a)
	}
	if a := eu.Airtime(0, 13); a < 1100*time.Millisecond || a > 1400*time.Millisecond {
		t.Fatalf("SF12 airtime %v", a)
	}
	if _, err := lpwan.LookupRegion("XX1"); err == nil {
		t.Fatal("unknown region accepted")
	}
}

func loraSettings(t *testing.T, mut func(*lpwan.BridgeSettings)) lpwan.BridgeSettings {
	t.Helper()
	s := lpwan.BridgeSettings{}
	if mut != nil {
		mut(&s)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	return s
}

// Settings are checked, and the unverified profile is named.
// Covers: SIG-IPE-3775
func TestLoRaWANSettings(t *testing.T) {
	for _, bad := range []func(*lpwan.BridgeSettings){
		func(s *lpwan.BridgeSettings) { s.FPortUp, s.FPortDown = 30, 30 },
		func(s *lpwan.BridgeSettings) { s.FPortUp = 224 },
		func(s *lpwan.BridgeSettings) { s.Header = "udp" },
		func(s *lpwan.BridgeSettings) { s.Class = "D" },
		func(s *lpwan.BridgeSettings) { s.Region = "XX" },
		func(s *lpwan.BridgeSettings) {
			s.Rules = json.RawMessage(`{"rules":[{"ruleId":20,"kind":"no-compression"}]}`)
		},
	} {
		s := lpwan.BridgeSettings{}
		bad(&s)
		if err := s.Check(); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	s := loraSettings(t, nil)
	msg, detail := s.ProfileWarning()
	if msg == "" || !bytes.Contains([]byte(detail), []byte("fPortUp=20 fPortDown=21 fPortNoCompression=22 header=wrapper rules=built-in downlinkFragmentation=ack-always tileBytes=10")) {
		t.Fatalf("%s / %s", msg, detail)
	}
}
