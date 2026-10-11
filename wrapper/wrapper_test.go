package wrapper

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// 5.3.2 Figure 4: version 0x0001, source wPort, destination wPort,
// length, each 16 bits, most significant octet first.
//
// Covers: SIG-IPE-1214
func TestHeader(t *testing.T) {
	b, err := Encode(0x10, 0x01, []byte{0xC0, 0x01, 0xC1})
	if err != nil || !bytes.Equal(b, []byte{0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x03, 0xC0, 0x01, 0xC1}) {
		t.Fatalf("% X %v", b, err)
	}
	h, apdu, err := ParseDatagram(b)
	if err != nil || h != (Header{Version: 1, Src: 0x10, Dst: 1, Length: 3}) || !bytes.Equal(apdu, b[8:]) {
		t.Fatalf("%+v % X %v", h, apdu, err)
	}
	if _, err := Encode(1, 1, make([]byte, 0x10000)); err == nil {
		t.Error("an APDU past the 16-bit length was encoded")
	}
	// Another version, a short or long datagram: refused.
	v2 := append([]byte{0, 2}, b[2:]...)
	if _, _, err := ParseDatagram(v2); !errors.Is(err, ErrVersion) {
		t.Errorf("version 2: %v", err)
	}
	for _, d := range [][]byte{b[:5], b[:10], append(b, 0)} {
		if _, _, err := ParseDatagram(d); err == nil {
			t.Errorf("% X was taken", d)
		}
	}
	if Port != 4059 {
		t.Error("the DLMS/COSEM port is 4059")
	}
}

// Table 1: reserved client and server wPorts.
//
// Covers: SIG-IPE-1216
func TestReservedWPorts(t *testing.T) {
	for _, p := range []int{1, 2, 0x0F, 0x10, 0x11, 0x30, 0xFF} {
		if CheckClient(p) != nil {
			t.Errorf("client wPort %#x refused", p)
		}
	}
	for _, p := range []int{0, 0x100, -1} {
		if CheckClient(p) == nil {
			t.Errorf("client wPort %#x taken", p)
		}
	}
	for _, p := range []int{1, 0x10, 0x7E} {
		if CheckServer(p) != nil {
			t.Errorf("server wPort %#x refused", p)
		}
	}
	for _, p := range []int{0, 2, 0x0F, 0x7F, 0x80, 0x100} {
		if CheckServer(p) == nil {
			t.Errorf("server wPort %#x taken", p)
		}
	}
}

// chunks yields its data in the given pieces.
type chunks struct {
	data  []byte
	sizes []int
}

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(c.data)
	if len(c.sizes) > 0 {
		n, c.sizes = min(c.sizes[0], n), c.sizes[1:]
	}
	n = min(n, len(p))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

// short writes at most the next size each time.
type short struct {
	sizes []int
	got   []byte
	calls int
}

func (s *short) Write(p []byte) (int, error) {
	n := len(p)
	if s.calls < len(s.sizes) {
		n = min(n, s.sizes[s.calls])
	}
	s.calls++
	s.got = append(s.got, p[:n]...)
	return n, nil
}

// Annex A.4: a 992-octet APDU makes a 1 000-octet WPDU, sent in writes of
// 476, 302 and 222 octets (Figure A.5) and received in reads of 6, 470,
// 302 and 222 (Figure A.6); the receiver waits for the length the header
// gives.
//
// Covers: SIG-IPE-1215
func TestStreamAnnexA4(t *testing.T) {
	apdu := make([]byte, 992)
	for i := range apdu {
		apdu[i] = byte(i)
	}
	w, _ := Encode(0x10, 0x01, apdu)
	if len(w) != 1000 {
		t.Fatalf("WPDU of %d octets", len(w))
	}
	s := &short{sizes: []int{476, 302, 222}}
	if n, err := writeAll(s, w); n != 1000 || err != nil || s.calls != 3 || !bytes.Equal(s.got, w) {
		t.Fatalf("sent %d in %d writes: %v", n, s.calls, err)
	}
	r := &chunks{data: append(append([]byte(nil), w...), w...), sizes: []int{6, 470, 302, 222, 1000}}
	for i := range 2 {
		h, got, err := ReadWPDU(r)
		if err != nil || h.Length != 992 || !bytes.Equal(got, apdu) {
			t.Fatalf("WPDU %d: %+v %v", i+1, h, err)
		}
	}
	if _, _, err := ReadWPDU(&chunks{data: w[:500]}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a cut WPDU: %v", err)
	}
}

// The client transport over TCP: a WPDU split over several TCP packets is
// delivered whole; WPDUs for another wPort, from another logical device or
// of another version are discarded without losing what follows (5.3.5,
// 6.2.5.2, 6.3.5.4). Over UDP a WPDU fills one datagram.
//
// Covers: SIG-IPE-1214, SIG-IPE-1215, SIG-IPE-1216, SIG-IPE-1217
func TestTransport(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	answer := bytes.Repeat([]byte{0xAB}, 3000)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		h, req, err := ReadWPDU(c)
		if err != nil || h.Src != 0x30 || h.Dst != 1 || req[0] != 0xC0 {
			return
		}
		other, _ := Encode(1, 0x31, []byte{1})
		foreign, _ := Encode(0x20, 0x30, []byte{2})
		v2, _ := Encode(1, 0x30, []byte{3})
		v2[1] = 2
		good, _ := Encode(1, 0x30, answer)
		stream := append(append(append(other, foreign...), v2...), good...)
		for len(stream) > 0 {
			n := min(len(stream), 700)
			_, _ = c.Write(stream[:n])
			stream = stream[n:]
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}()
	tr, err := New("tcp", ln.Addr().String(), 0x30, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dc := make(gdlms.DataChannel, 4)
	tr.SetReception(dc)
	if err := tr.Connect(); err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if err := tr.Send([]byte{0xC0, 0x01}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dc:
		if !bytes.Equal(got, answer) {
			t.Fatalf("got %d octets", len(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no APDU")
	}
	if n := tr.Discarded(); n != 3 {
		t.Errorf("%d WPDUs discarded, want 3", n)
	}

	// UDP.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 65536)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		h, req, err := ParseDatagram(buf[:n])
		if err != nil {
			return
		}
		bad, _ := Encode(h.Dst, h.Src, []byte{9})
		_, _ = pc.WriteTo(append(bad, 0), from) // length does not match
		good, _ := Encode(h.Dst, h.Src, append([]byte{0xC4}, req...))
		_, _ = pc.WriteTo(good, from)
	}()
	u, err := New("udp", pc.LocalAddr().String(), 0x30, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	udc := make(gdlms.DataChannel, 4)
	u.SetReception(udc)
	if err := u.Connect(); err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if err := u.Send([]byte{0xC0, 0x02}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-udc:
		if !bytes.Equal(got, []byte{0xC4, 0xC0, 0x02}) {
			t.Fatalf("UDP answer % X", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no UDP answer")
	}
	if u.Discarded() != 1 {
		t.Errorf("UDP discarded %d, want 1", u.Discarded())
	}
	if err := u.Send(make([]byte, MaxUDPAPDU+1)); err == nil {
		t.Error("an APDU past one datagram was sent")
	}
	if _, err := New("sctp", "h:1", 1, 1, 0); err == nil {
		t.Error("network sctp taken")
	}
}
