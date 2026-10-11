package hdlc

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Station is a secondary station (a meter's data link layer) for the
// simulator and tests: it answers SNRM with UA and the negotiation result,
// takes windowed and segmented I frames, answers in windows and segments
// that respect the client's parameters, keeps pending UI frames until it
// has the right to talk (6.4.4.7), rejects what it cannot take with FRMR,
// answers DM while disconnected, and falls back to disconnected mode after
// the inactivity time-out (6.4.4.10.3).
type Station struct {
	// Upper and Lower are our logical and physical device addresses in an
	// address scheme of Size octets (1, 2 or 4).
	Upper, Lower, Size int
	// Own are our capabilities for negotiation; zero means the defaults.
	Own Params
	// Inactivity drops the link after this long without an octet; 0 never.
	Inactivity time.Duration
	// InterOctet is the inter-octet time-out; 0 turns it off.
	InterOctet time.Duration
	// Calling is the CALLING DEVICE layer parameter (6.4.4.8): set while
	// we have called the client, it makes us answer the CALLING address.
	Calling bool
	// Handle takes an APDU (LLC removed) from a client and returns the
	// answer, or nil for none. unconfirmed is true for a UI frame, whose
	// answer is never sent.
	Handle func(client int, apdu []byte, unconfirmed bool) []byte
	// Log, when set, reports frames refused and events.
	Log func(event string)
	// OnLink, when set, learns of each link set up (SNRM accepted) or
	// ended (DISC, FRMR, inactivity).
	OnLink func(client int, up bool)
	// UserData, when set, goes in the user data subfield of our UA to an
	// SNRM (IEC 62056-7-6 9.3; ISO/IEC 13239 5.5.3.2.3).
	UserData []byte
	// OnUserData, when set, receives the user data subfield of an SNRM or
	// DISC from a client (kind KindSNRM or KindDISC).
	OnUserData func(client int, kind Kind, data []byte)
	// StopAfterDISC makes Serve return after answering a DISC: the session
	// was handed over for one link (IEC 62056-21 mode E).
	StopAfterDISC bool
	// Modulo128 makes the station take SNRME (ISO/IEC 13239 extended
	// numbering, windows up to 127 as Own allows); without it SNRME is
	// answered with DM and the client falls back to SNRM. IEC 62056-46
	// uses modulo 8 only.
	Modulo128 bool
	// SegmentUI sends a pending UI APDU longer than the information field
	// as several UI frames, the segmentation bit on all but the last (F-233:
	// off by default, as IEC 62056-46 keeps UI data to one frame).
	SegmentUI bool

	mu      sync.Mutex
	pending [][]byte // UI information fields waiting for the right to talk
	busy    int      // polls still to answer with RNR (SetBusy)
	rnrs    int

	// Link state, one per client address (each client-server pair is its
	// own data link connection); link is the one of the frame at hand.
	links map[int]*link
	*link
	uiRx []byte
	stop bool
}

// link is the state of one data link connection (owned by Serve).
type link struct {
	linked      bool
	mod         int    // numbering set by the last SNRM (8) or SNRME (128); 0 is 8
	params      Params // negotiated, our point of view
	vs, vr      int
	rx          []byte   // I segments received so far
	rxComplete  bool     // rx is a whole MSDU waiting for a poll
	tx          [][]byte // answer segments not yet acknowledged
	txBase      int      // N(S) of tx[0]
	txNext      int      // index of the next tx segment to send
	client      int
	lastAddress Address // the destination the client used (echoed as our source)
	// held is a response owed to a command received with P 0: in normal
	// response mode we may only send when polled, so it goes out, with
	// F 1, on the next command with P 1 (ISO/IEC 13239 5.4.3.1.2,
	// 5.4.3.2.2, 5.5.3.3 a and b). heldFRMR tells an FRMR (cleared by a
	// mode-setting command) from a UA or DM owed to SNRM or DISC.
	held     *Frame
	heldFRMR bool
	heldStop bool // the held frame answers a DISC with StopAfterDISC
}

// use selects the link of a client.
func (s *Station) use(client int) {
	if s.links == nil {
		s.links = map[int]*link{}
	}
	l := s.links[client]
	if l == nil {
		l = &link{client: client}
		s.links[client] = l
	}
	s.link = l
}

// modulo is the numbering of the link at hand.
func (l *link) modulo() int {
	if l.mod == Modulo128 {
		return Modulo128
	}
	return Modulo8
}

func (l *link) mask() int { return l.modulo() - 1 }

// decode reads a frame in the numbering of the link of its source.
func (s *Station) decode(raw []byte) (Frame, error) {
	mod := Modulo8
	if len(raw) > 4 {
		if _, n, err := DecodeAddress(raw[3 : len(raw)-1]); err == nil && 3+n < len(raw)-1 {
			if src, _, err := DecodeAddress(raw[3+n : len(raw)-1]); err == nil && src.Size == 1 {
				if l := s.links[src.Upper]; l != nil {
					mod = l.modulo()
				}
			}
		}
	}
	return DecodeModulo(raw, mod)
}

func (s *Station) setLinked(up bool) {
	was := s.linked
	s.linked = up
	if s.OnLink != nil && (was != up || up) {
		s.OnLink(s.client, up)
	}
}

// SetBusy makes the station busy for the next n polls: each is answered
// with RNR and no I frame is accepted (6.4.3.5); the busy condition ends
// with the RR that answers the poll after them.
func (s *Station) SetBusy(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy = n
}

// RNRs is how many RNR frames the station has sent.
func (s *Station) RNRs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rnrs
}

func (s *Station) isBusy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy > 0
}

func (s *Station) takeBusy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy--
	s.rnrs++
}

// Queue adds an APDU to be sent in a UI frame from the management logical
// device at the next opportunity (IEC 62056-7-6 9.4).
func (s *Station) Queue(apdu []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, append(append([]byte(nil), LLCResponse...), apdu...))
}

// Pending is the number of UI frames waiting.
func (s *Station) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

func (s *Station) logf(event string) {
	if s.Log != nil {
		s.Log(event)
	}
}

func (s *Station) own() Params {
	p := s.Own
	if p.MaxInfoTX == 0 {
		p = Defaults()
	}
	return p
}

// deadlineReader is a reader whose reads can time out.
type deadlineReader interface {
	SetReadDeadline(time.Time) error
}

// Serve runs the station on rw until the stream ends. With a read deadline
// available (a net.Conn) the inactivity time-out is applied.
func (s *Station) Serve(rw io.ReadWriter) error {
	sc := Scanner{InterOctet: s.InterOctet}
	dl, _ := rw.(deadlineReader)
	buf := make([]byte, 4096)
	for {
		if dl != nil && s.Inactivity > 0 {
			_ = dl.SetReadDeadline(time.Now().Add(s.Inactivity))
		}
		n, err := rw.Read(buf)
		if err != nil {
			var te interface{ Timeout() bool }
			if dl != nil && s.Inactivity > 0 && errors.As(err, &te) && te.Timeout() {
				// Inactivity: the data link is disconnected (6.4.4.10.3),
				// the physical link stays.
				for c := range s.links {
					s.use(c)
					if s.linked {
						s.logf("inactivity time-out: link disconnected")
					}
					s.setLinked(false)
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		for _, raw := range sc.Feed(buf[:n], time.Now()) {
			f, err := s.decode(raw)
			if errors.Is(err, ErrHCS) {
				sc.Reset()
				break
			}
			if err != nil {
				s.logf("frame ignored: " + err.Error())
				continue
			}
			if err := s.frame(rw, f); err != nil {
				return err
			}
			if s.stop {
				return nil
			}
		}
	}
}

// accepts applies 6.4.2.4, 6.4.2.5 (Table 5) and Table 10 to a
// destination address; broadcast is true for an all-station part.
func (s *Station) accepts(d Address) (ok, broadcast bool) {
	allU := d.UpperAllStation()
	switch {
	case d.Size == s.Size:
	case d.Size == 1 && s.Size > 1:
		return false, false // Table 5: discarded
	case d.Size == 2 && s.Size == 1:
		if !d.LowerAllStation() {
			return false, false
		}
		d = Address{Upper: d.Upper, Size: 1}
		allU = d.UpperAllStation()
		return allU || d.Upper == s.Upper, true
	case d.Size == 2 && s.Size == 4:
		// Taken as if sent in four octets (Table 5).
		lower := d.Lower
		if d.LowerAllStation() {
			lower = AllStation2
		} else if lower == Calling {
			lower = Calling2
		}
		upper := d.Upper
		if allU {
			upper = AllStation2
		}
		d = Address{Upper: upper, Lower: lower, Size: 4}
		allU = d.UpperAllStation()
	case d.Size == 4 && s.Size == 1:
		ok := d.UpperAllStation() && d.LowerAllStation()
		return ok, ok
	case d.Size == 4 && s.Size == 2:
		if d.LowerAllStation() {
			return d.UpperAllStation(), true
		}
		if d.Lower == Calling2 {
			return d.Upper == ManagementDevice && s.Calling, false
		}
		return false, false
	default:
		return false, false
	}
	allL := d.LowerAllStation()
	upperOK := allU || d.Upper == s.Upper
	lowerOK := d.Size == 1 || allL || d.Lower == s.Lower || (d.Lower == CallingFor(d.Size) && s.Calling)
	return upperOK && lowerOK, allU || allL
}

func (s *Station) send(w io.Writer, f Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// reply builds a frame to the client from the address it used; with the
// CALLING address our own lower address goes back (6.4.4.8).
func (s *Station) reply(control Control, info []byte, segmented bool) Frame {
	src := s.lastAddress
	if src.Size == 0 || src.Broadcast() {
		src = ServerAddress(s.Upper, s.Lower, s.Size)
	}
	if src.Size > 1 && src.Lower == CallingFor(src.Size) {
		src.Lower = s.Lower
	}
	f := Frame{Dest: ClientAddress(s.client), Src: src, Info: info, Segmented: segmented}
	control.set(&f, s.modulo())
	return f
}

// flushUI sends the pending UI frames with F 0, the last with F final.
// With SegmentUI an APDU longer than the information field goes in
// segments (the segmentation bit on all but its last).
func (s *Station) flushUI(w io.Writer, final bool) (sent bool, err error) {
	s.mu.Lock()
	p := s.pending
	s.pending = nil
	s.mu.Unlock()
	mx := DefaultMaxInfo
	if s.link != nil && s.linked {
		mx = s.params.MaxInfoTX
	}
	for i, info := range p {
		segs := []segment{{info, false}}
		if s.SegmentUI {
			segs = segmentsOf(info, mx)
		}
		for j, seg := range segs {
			src := ServerAddress(ManagementDevice, s.Lower, s.Size)
			last := i == len(p)-1 && j == len(segs)-1
			f := Frame{Dest: ClientAddress(s.clientFor()), Src: src, Control: ctl(KindUI, final && last), Info: seg.data, Segmented: seg.more}
			if err := s.send(w, f); err != nil {
				return true, err
			}
		}
	}
	return len(p) > 0, nil
}

// clientFor is where UI frames go: event notifications go to the client
// management process (IEC 62056-7-6 9.4).
func (s *Station) clientFor() int { return ClientManagement }

func (s *Station) frame(w io.Writer, f Frame) error {
	ok, broadcast := s.accepts(f.Dest)
	if !ok {
		return nil
	}
	// Client addresses are one octet (6.4.2.5).
	if f.Src.Size != 1 {
		return nil
	}
	c := f.ControlField()
	s.use(f.Src.Upper)
	if broadcast {
		// Only UI (and DISC) may be broadcast, with P 0 (6.4.2.4, 6.4.4.6).
		switch {
		case c.Kind == KindUI && !c.PF:
			return s.ui(w, f, true)
		case c.Kind == KindDISC:
			s.setLinked(false) // no answer to a broadcast DISC
		}
		return nil
	}
	s.lastAddress = f.Dest
	if s.held != nil {
		modeSetting := c.Kind == KindSNRM || c.Kind == KindSNRME || c.Kind == KindDISC
		switch {
		case s.heldFRMR && modeSetting:
			// A mode-setting command ends the frame reject condition.
			s.held, s.heldFRMR, s.heldStop = nil, false, false
		case c.PF:
			// The first poll gets the response owed, F 1; the poll
			// itself is not acted on (13239 5.5.3.3: after a mode-setting
			// command the secondary may ignore frames until it has
			// answered, and answers the first such command).
			h := *s.held
			s.stop = s.heldStop
			s.held, s.heldFRMR, s.heldStop = nil, false, false
			return s.send(w, h)
		default:
			return nil // no respond opportunity yet
		}
	}
	switch c.Kind {
	case KindSNRM, KindSNRME:
		mod := Modulo8
		if c.Kind == KindSNRME {
			if !s.Modulo128 {
				// Extended numbering is not taken: DM says the mode
				// cannot be set (ISO/IEC 13239), and the client may fall
				// back to SNRM.
				s.setLinked(false)
				return s.respond(w, c.PF, s.reply(cU(KindDM, true), nil, false))
			}
			mod = Modulo128
		}
		proposed, user, err := DecodeParams(f.Info)
		if err != nil {
			s.setLinked(false)
			return s.respond(w, c.PF, s.reply(cU(KindDM, true), nil, false))
		}
		s.userData(KindSNRM, user)
		s.mod = mod
		s.params = Negotiate(proposed, s.own()).capWindows(mod)
		s.vs, s.vr, s.rx, s.rxComplete = 0, 0, nil, false
		s.setLinked(true)
		s.tx, s.txBase, s.txNext = nil, 0, 0
		ua := s.params.Encode(s.UserData)
		return s.respond(w, c.PF, s.reply(cU(KindUA, true), ua, false))
	case KindDISC:
		// A DISC may carry the format identifier and user data only
		// (13239 Table 9); anything else in it is ignored.
		if _, user, err := DecodeParams(f.Info); err == nil {
			s.userData(KindDISC, user)
		}
		k := KindDM
		stop := false
		if s.linked {
			k = KindUA
			stop = s.StopAfterDISC
		}
		s.setLinked(false)
		if !c.PF && s.held == nil {
			s.heldStop = stop // stop once the held UA is sent
		} else if c.PF {
			s.stop = stop
		}
		return s.respond(w, c.PF, s.reply(cU(k, true), nil, false))
	case KindUI:
		return s.ui(w, f, false)
	case KindUnknown, KindUA, KindDM, KindFRMR:
		if !s.linked {
			return nil
		}
		return s.reject(w, c, f, FrameReject{W: true})
	}
	if !s.linked {
		// I, RR, RNR in NDM: ask for a mode setting command (6.4.3.9).
		if c.PF {
			return s.send(w, s.reply(cU(KindDM, true), nil, false))
		}
		return nil
	}
	// RR and RNR carry no information field: W and X (13239 5.5.3.4.2).
	if (c.Kind == KindRR || c.Kind == KindRNR) && len(f.Info) > 0 {
		return s.reject(w, c, f, FrameReject{W: true, X: true})
	}
	// N(R) acknowledges our answer frames.
	acked := (c.NR - s.txBase) & s.mask()
	if acked > s.txNext {
		return s.reject(w, c, f, FrameReject{Z: true})
	}
	s.tx = s.tx[acked:]
	s.txNext -= acked
	s.txBase = (s.txBase + acked) & s.mask()
	switch c.Kind {
	case KindI:
		if len(f.Info) > s.params.MaxInfoRX {
			return s.reject(w, c, f, FrameReject{Y: true})
		}
		if s.isBusy() {
			// Busy (6.4.3.5): the frame is not accepted; RNR says what
			// was, and the primary sends it again after the busy ends.
			if c.PF {
				s.takeBusy()
				return s.send(w, s.reply(cRNR(s.vr), nil, false))
			}
			return nil
		}
		if c.NS == s.vr {
			s.vr = (s.vr + 1) & s.mask()
			s.rx = append(s.rx, f.Info...)
			if !f.Segmented {
				msdu := s.rx
				s.rx = nil
				if c.PF {
					return s.answer(w, msdu)
				}
				// A complete MSDU without P: answer at the next poll.
				s.rx = msdu
				s.rxComplete = true
				return nil
			}
		}
		if !c.PF {
			return nil
		}
		if s.rxComplete {
			msdu := s.rx
			s.rx, s.rxComplete = nil, false
			return s.answer(w, msdu)
		}
		return s.send(w, s.reply(cRR(s.vr, true), nil, false))
	case KindRR, KindRNR:
		if !c.PF {
			return nil
		}
		if s.isBusy() {
			s.takeBusy()
			return s.send(w, s.reply(cRNR(s.vr), nil, false))
		}
		if c.Kind == KindRR && len(s.tx) > 0 {
			return s.sendWindow(w)
		}
		if _, err := s.flushUI(w, false); err != nil {
			return err
		}
		return s.send(w, s.reply(cRR(s.vr, true), nil, false))
	}
	return nil
}

// ui handles a UI frame: an unconfirmed APDU, or with P 1 and no
// information the permission to send pending UI frames (6.4.4.7 a).
func (s *Station) ui(w io.Writer, f Frame, broadcast bool) error {
	c := f.ControlField()
	if len(f.Info) == 0 {
		if c.PF && !broadcast {
			_, err := s.flushUI(w, true)
			return err
		}
		return nil
	}
	s.uiRx = append(s.uiRx, f.Info...)
	if f.Segmented {
		// Not allowed for UI (6.4.4.4.3.4); taken anyway (F-233).
		if len(s.uiRx) > maxMSDU {
			s.uiRx = nil
		}
		return nil
	}
	msdu := s.uiRx
	s.uiRx = nil
	if apdu, ok := splitLLC(msdu, false); ok && s.Handle != nil {
		s.Handle(f.Src.Upper, apdu, true)
	}
	if c.PF && !broadcast {
		_, err := s.flushUI(w, true)
		return err
	}
	return nil
}

// answer hands a whole MSDU to the application and sends its answer.
func (s *Station) answer(w io.Writer, msdu []byte) error {
	var resp []byte
	if apdu, ok := splitLLC(msdu, false); ok && s.Handle != nil {
		resp = s.Handle(s.client, apdu, false)
	}
	if resp == nil {
		if _, err := s.flushUI(w, false); err != nil {
			return err
		}
		return s.send(w, s.reply(cRR(s.vr, true), nil, false))
	}
	info := append(append([]byte(nil), LLCResponse...), resp...)
	s.tx, s.txNext, s.txBase = nil, 0, s.vs
	for len(info) > 0 {
		n := min(len(info), s.params.MaxInfoTX)
		s.tx = append(s.tx, info[:n])
		info = info[n:]
	}
	return s.sendWindow(w)
}

// sendWindow sends the unacknowledged answer segments, at most a window,
// the last with F 1; pending UI frames go just before the window that
// carries the final bit (6.4.4.7).
func (s *Station) sendWindow(w io.Writer) error {
	s.txNext = 0
	end := min(len(s.tx), s.params.WindowTX)
	if _, err := s.flushUI(w, false); err != nil {
		return err
	}
	for k := 0; k < end; k++ {
		ns := (s.txBase + k) & s.mask()
		f := s.reply(cI(s.vr, ns, k == end-1), s.tx[k], k < len(s.tx)-1)
		if err := s.send(w, f); err != nil {
			return err
		}
	}
	s.txNext = end
	s.vs = (s.txBase + end) & s.mask()
	return nil
}

// respond sends a response to a command with P 1 now, with F 1; to a
// command with P 0 it is held for the next poll (13239 5.4.3.1.2, 5.5.3.3):
// the F bit of what we send always answers a P 1. The first response owed
// wins (5.5.3.3).
func (s *Station) respond(w io.Writer, poll bool, f Frame) error {
	if poll {
		return s.send(w, f)
	}
	if s.held == nil {
		s.held, s.heldFRMR = &f, false
	}
	return nil
}

// reject sends FRMR with the information field of ISO/IEC 13239 5.5.3.4.2
// in the link's numbering (Figure 18a modulo 8, 18b modulo 128): the
// rejected control field, our V(S), C/R 0 (a secondary station only
// rejects commands), our V(R), and the reason bits set in r. A frame
// rejected without P gets its FRMR at the next poll.
func (s *Station) reject(w io.Writer, c Control, rejected Frame, r FrameReject) error {
	r.Modulo, r.Control, r.VS, r.VR, r.Response = s.modulo(), rejected.rejectedControl(), s.vs, s.vr, false
	info := r.Encode()
	s.logf(fmt.Sprintf("FRMR to client %#x: %s", s.client, r))
	s.setLinked(false)
	f := s.reply(cU(KindFRMR, true), info, false)
	if c.PF {
		return s.send(w, f)
	}
	s.held, s.heldFRMR = &f, true
	return nil
}

// userData hands a client's user data subfield to OnUserData.
func (s *Station) userData(kind Kind, data []byte) {
	if len(data) > 0 && s.OnUserData != nil {
		s.OnUserData(s.client, kind, data)
	}
}
