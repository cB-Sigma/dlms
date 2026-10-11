package phy

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// 6.3.3.2: IDENTIFY.request is 0x20, or three octets with the multidrop
// device ID; 0x49 ('I') is accepted too; the response is four octets,
// success 0x00, protocol 0x04, version 0x01, revision 0x00 for this stack.
//
// Covers: SIG-IPE-1228
func TestIdentifyMessages(t *testing.T) {
	if !bytes.Equal(IdentifyRequest(nil), []byte{0x20}) {
		t.Error("request without device")
	}
	d := uint16(0x1234)
	if !bytes.Equal(IdentifyRequest(&d), []byte{0x20, 0x12, 0x34}) {
		t.Error("request with device")
	}
	for _, b := range [][]byte{{0x20}, {0x49}, {0x20, 0, 1}} {
		if _, err := ParseIdentifyRequest(b); err != nil {
			t.Errorf("% X refused", b)
		}
	}
	for _, b := range [][]byte{{0x21}, {0x20, 1}, {0x7E, 0xA0, 0x07, 0x03}, nil} {
		if _, err := ParseIdentifyRequest(b); err == nil {
			t.Errorf("% X taken", b)
		}
	}
	if !bytes.Equal(COSEM.Bytes(), []byte{0x00, 0x04, 0x01, 0x00}) {
		t.Errorf("COSEM identity % X", COSEM.Bytes())
	}
}

// 6.3.3.3 Figure 6: the server answers an identification request of up to
// three octets ended by a gap, stays in the identification stage, ignores
// a request for another device or one it cannot parse, and hands the
// octets on once more than three arrive; a client not using the service
// starts with a longer frame (NOTE 3).
//
// Covers: SIG-IPE-1228
func TestServerIdentify(t *testing.T) {
	ours, theirs := net.Pipe()
	defer ours.Close()
	dev := uint16(0x1001)
	type out struct {
		prefix []byte
		err    error
	}
	done := make(chan out, 1)
	go func() {
		p, err := ServerIdentify(theirs, COSEM, &dev, 30*time.Millisecond)
		done <- out{p, err}
	}()
	ask := func(req []byte) []byte {
		_ = ours.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := ours.Write(req); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8)
		n, _ := ours.Read(buf)
		return buf[:n]
	}
	if got := ask([]byte{0x20}); !bytes.Equal(got, COSEM.Bytes()) {
		t.Errorf("identify: % X", got)
	}
	if got := ask([]byte{0x20, 0x10, 0x02}); len(got) != 0 {
		t.Errorf("another device answered: % X", got)
	}
	if got := ask([]byte{0x20, 0x10, 0x01}); !bytes.Equal(got, COSEM.Bytes()) {
		t.Errorf("our device: % X", got)
	}
	if got := ask([]byte{0x55, 0x55}); len(got) != 0 {
		t.Errorf("garbage answered: % X", got)
	}
	frame := []byte{0x7E, 0xA0, 0x07, 0x03, 0x21, 0x93, 0x0F, 0x01, 0x7E}
	_ = ours.SetDeadline(time.Time{})
	if _, err := ours.Write(frame); err != nil {
		t.Fatal(err)
	}
	o := <-done
	if o.err != nil || !bytes.Equal(o.prefix, frame) {
		t.Errorf("data stage got % X %v", o.prefix, o.err)
	}
}

// echo is a far end that runs the identification stage and then echoes.
func echo(c net.Conn) {
	prefix, err := ServerIdentify(c, COSEM, nil, 20*time.Millisecond)
	if err != nil {
		return
	}
	_, _ = c.Write(prefix)
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:n])
	}
}

// Annex A over a simulated Hayes modem: PH-CONNECT.request dials (ATD),
// CONNECT confirms with its rate, the identification service runs, then
// PH-DATA carries the data link layer's octets; PH-ABORT.request escapes
// with guard times and "+++" and hangs up with ATH. A wrong number (NO
// CARRIER) and a busy line give a negative PH-CONNECT.confirm.
//
// Covers: SIG-IPE-1228, SIG-IPE-1229, SIG-CMD-232
func TestPortModem(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := &ModemSim{Number: "049515101188", Rate: 19200, Guard: 100 * time.Millisecond, Remote: echo}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = m.Serve(c); _ = c.Close() }()
		}
	}()
	open := func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }
	p, err := NewPort(Config{Open: open, Dial: "049515101188", Init: []string{"ATZ", "ATE0"}, Guard: 100 * time.Millisecond, Identify: true})
	if err != nil {
		t.Fatal(err)
	}
	dc := make(gdlms.DataChannel, 8)
	p.SetReception(dc)
	if err := p.Connect(); err != nil {
		t.Fatal(err)
	}
	if got := p.Connection(); got.Rate != 19200 || got.Identity == nil || *got.Identity != COSEM {
		t.Fatalf("connection %+v", got)
	}
	msg := []byte{0x7E, 0xA0, 0x07, 0x03, 0x21, 0x93, 0x0F, 0x01, 0x7E}
	if err := p.Send(msg); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for len(got) < len(msg) {
		select {
		case b := <-dc:
			got = append(got, b...)
		case <-time.After(2 * time.Second):
			t.Fatalf("echo %X", got)
		}
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo % X", got)
	}
	if err := p.Disconnect(); err != nil {
		t.Fatalf("hang up: %v", err)
	}
	if calls, hangups := m.Calls(); calls != 1 || hangups != 1 {
		t.Errorf("calls %d, hangups %d", calls, hangups)
	}
	cmds := strings.Join(m.Commands(), ",")
	if cmds != "ATZ,ATE0,ATD049515101188,ATH" {
		t.Errorf("commands %s", cmds)
	}
	for _, tc := range []struct {
		number string
		busy   bool
		want   string
	}{{"123", false, "NO CARRIER"}, {"049515101188", true, "BUSY"}} {
		m.Busy = tc.busy
		q, _ := NewPort(Config{Open: open, Dial: tc.number})
		err := q.Connect()
		if !errors.Is(err, ErrConnect) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.want, err)
		}
		if q.IsConnected() {
			t.Errorf("%s: connected", tc.want)
		}
	}
}

// A direct connection (a converter, no modem) with identification: a
// server answering another stack is refused; the far end going away is
// PH-ABORT.indication to the connection manager (6.3.5).
//
// Covers: SIG-IPE-1228, SIG-IPE-1229
func TestPortDirect(t *testing.T) {
	serve := func(id Identity, after func(net.Conn)) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			if _, err := ServerIdentify(c, id, nil, 20*time.Millisecond); err == nil || after != nil {
				if after != nil {
					after(c)
				}
			}
		}()
		return ln.Addr().String()
	}
	other := serve(Identity{0, 0x05, 1, 0}, nil)
	p, _ := NewPort(Config{Open: func() (net.Conn, error) { return net.Dial("tcp", other) }, Identify: true})
	if err := p.Connect(); err == nil || !strings.Contains(err.Error(), "not") {
		t.Errorf("another stack: %v", err)
	}
	// The server drops the line right after answering the identification.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4)
		_, _ = c.Read(buf)
		_, _ = c.Write(COSEM.Bytes())
		time.Sleep(100 * time.Millisecond)
		_ = c.Close()
	}()
	aborted := make(chan error, 1)
	p, _ = NewPort(Config{Open: func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }, Identify: true,
		OnAbort: func(err error) { aborted <- err }})
	if err := p.Connect(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-aborted:
	case <-time.After(2 * time.Second):
		t.Fatal("no PH-ABORT.indication")
	}
	if p.IsConnected() {
		t.Error("connected after the line went down")
	}
}

// Annex A.2.3: a called client answers RING with ATA and takes CONNECT as
// PH-CONNECT.indication, with the rate.
//
// Covers: SIG-IPE-1229
func TestAnswer(t *testing.T) {
	ours, theirs := net.Pipe()
	defer ours.Close()
	m := &ModemSim{Rate: 2400, Guard: 50 * time.Millisecond, Remote: func(c net.Conn) { _, _ = c.Write([]byte("hello")) }}
	go func() { _ = m.Call(theirs); _ = theirs.Close() }()
	rate, rest, err := Answer(ours, 2*time.Second)
	if err != nil || rate != 2400 {
		t.Fatalf("answer: %d %v", rate, err)
	}
	// The far end's first octets may come with CONNECT: none is lost.
	got := string(rest)
	buf := make([]byte, 5)
	_ = ours.SetReadDeadline(time.Now().Add(time.Second))
	for len(got) < 5 {
		n, err := ours.Read(buf)
		got += string(buf[:n])
		if err != nil {
			break
		}
	}
	if got != "hello" {
		t.Errorf("after CONNECT: %q", got)
	}
}
