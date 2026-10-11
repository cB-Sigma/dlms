package hdlc

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// RNR (6.4.3.5, 6.4.4.9.5): a busy station answers our I frame, and then
// our polls, with RNR and takes nothing; we wait and poll with RR, and when
// the busy condition ends we send the frames it did not acknowledge again,
// without the station seeing any of them twice.
//
// Covers: SIG-IPE-1220
func TestClientRNR(t *testing.T) {
	var got [][]byte
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Own: Params{MaxInfoTX: 128, MaxInfoRX: 32, WindowTX: 1, WindowRX: 3},
		Handle: func(_ int, apdu []byte, _ bool) []byte {
			got = append(got, append([]byte(nil), apdu...))
			return []byte{0xC4, 0x01, 0x81, 0x00}
		}}
	down := &wire{}
	c, up, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), ResponseTimeout: 400 * time.Millisecond,
		Propose: &Params{MaxInfoTX: 128, MaxInfoRX: 128, WindowTX: 3, WindowRX: 1}}, down)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	// Busy at the first segment, and busy again in the middle.
	for round, busy := range []int{3, 1} {
		st.SetBusy(busy)
		req := pattern(100, byte(round))
		if err := c.Send(req); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if a := <-dc; a[0] != 0xC4 {
			t.Fatalf("answer % X", a)
		}
		if len(got) != round+1 || !bytes.Equal(got[round], req) {
			t.Fatalf("round %d: the station got %d requests", round, len(got))
		}
	}
	if st.RNRs() != 4 {
		t.Errorf("the station sent %d RNR, want 4", st.RNRs())
	}
	var polls int
	for _, f := range up.kinds() {
		if k := ParseControl(f.Control); k.Kind == KindRR && k.PF {
			polls++
		}
	}
	if polls < 4 {
		t.Errorf("%d RR polls, want one after each RNR", polls)
	}
}

// The server's inactivity time-out (6.4.4.10.3): the client knows it, so
// after a silence that long it takes the link as gone (IsConnected false)
// and refuses to send into it; SNRM sets it up again, and the station,
// which fell back to disconnected mode meanwhile, is never sent an I frame
// that it would answer with DM.
//
// Covers: SIG-IPE-1221
func TestClientInactivity(t *testing.T) {
	st := &Station{Upper: 1, Lower: 0x11, Size: 2, Inactivity: 500 * time.Millisecond,
		Handle: func(int, []byte, bool) []byte { return []byte{0xC4} }}
	down := &wire{}
	c, _, dc := pipeLink(t, st, Config{Client: 0x10, Server: ServerAddress(1, 0x11, 2), Inactivity: 500 * time.Millisecond}, down)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	for range 3 { // activity keeps the link
		time.Sleep(250 * time.Millisecond)
		if err := c.Send([]byte{0xC0}); err != nil {
			t.Fatal(err)
		}
		<-dc
	}
	time.Sleep(600 * time.Millisecond)
	if c.IsConnected() {
		t.Fatal("connected after the inactivity time-out")
	}
	if err := c.Send([]byte{0xC0}); !errors.Is(err, ErrNoLink) {
		t.Fatalf("send after the time-out: %v", err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.Send([]byte{0xC0}); err != nil {
		t.Fatal(err)
	}
	<-dc
	for _, f := range down.kinds() {
		if ParseControl(f.Control).Kind == KindDM {
			t.Error("the station answered DM: we sent into a dead link")
		}
	}
	if c.Expired() != 1 {
		t.Errorf("expired %d", c.Expired())
	}
}

// Multi-drop (IEC 62056-7-6 9.6, IEC 62056-46 6.4.2.2): two meters with
// their own physical addresses on one line behind one connection; several
// clients share it through a Bus, each keeps only the frames of its own
// server, and exchanges never overlap (no poll while another station has
// the right to talk), however hard they are driven in parallel.
//
// Covers: SIG-IPE-1222
func TestMultiDrop(t *testing.T) {
	mk := func(lower int) *Station {
		return &Station{Upper: 1, Lower: lower, Size: 4, Own: Params{MaxInfoTX: 64, MaxInfoRX: 64, WindowTX: 2, WindowRX: 2},
			Handle: func(client int, apdu []byte, _ bool) []byte {
				return append([]byte(fmt.Sprintf("%04X/%02X:", lower, client)), bytes.Repeat(apdu, 20)...)
			}}
	}
	line := &Line{Stations: []*Station{mk(0x1001), mk(0x1002)}}
	ours, theirs := net.Pipe()
	go func() { _ = line.Serve(theirs); _ = theirs.Close() }()
	bus := NewBus(&connTransport{c: ours})
	type cl struct {
		c     *Client
		dc    gdlms.DataChannel
		lower int
	}
	var clients []cl
	for _, a := range []struct{ client, lower int }{{0x10, 0x1001}, {0x10, 0x1002}, {0x30, 0x1001}} {
		c, err := NewClient(bus.Port(), Config{Client: a.client, Server: ServerAddress(1, a.lower, 4), Bus: bus,
			Propose: &Params{MaxInfoTX: 64, MaxInfoRX: 64, WindowTX: 2, WindowRX: 2}})
		if err != nil {
			t.Fatal(err)
		}
		dc := make(gdlms.DataChannel, 4)
		c.SetReception(dc)
		t.Cleanup(c.Close)
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, cl{c, dc, a.lower})
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i, x := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range 10 {
				req := []byte{0xC0, byte(i), byte(n)}
				if err := x.c.Send(req); err != nil {
					errs <- err
					return
				}
				a := <-x.dc
				want := append([]byte(fmt.Sprintf("%04X/%02X:", x.lower, x.c.cfg.Client)), bytes.Repeat(req, 20)...)
				if !bytes.Equal(a, want) {
					errs <- fmt.Errorf("client %d got %q", i, a[:12])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if v := line.Violations(); v != 0 {
		t.Errorf("%d polls while another meter had the right to talk", v)
	}
	// The line stays up while any client uses it.
	_ = clients[0].c.Disconnect()
	if !clients[1].c.IsConnected() {
		t.Error("one client's DISC closed the shared line")
	}
	if err := clients[1].c.Send([]byte{0xC0, 9}); err != nil {
		t.Fatal(err)
	}
	<-clients[1].dc
}
