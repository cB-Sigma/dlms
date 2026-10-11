package hdlc

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Config sets up a Client, the primary station.
type Config struct {
	// Client is our one-octet client address (6.4.2.2).
	Client int
	// Server is the destination: upper (logical device) and lower
	// (physical device) address in a 1, 2 or 4 octet field.
	Server Address
	// Propose, when set, is sent in the SNRM for negotiation; without it
	// the SNRM has no information field and the defaults apply.
	Propose *Params
	// UserData goes in the SNRM's user data subfield (IEC 62056-7-6 9.3;
	// ISO/IEC 13239 5.5.3.2.3).
	UserData []byte
	// DISCUserData goes in the DISC's user data subfield (IEC 62056-7-6
	// 9.3; ISO/IEC 13239 Table 9).
	DISCUserData []byte
	// ResponseTimeout is TO_WAIT_RESP (6.4.4.10.1), default 3 s.
	ResponseTimeout time.Duration
	// Retries is MAX_NB_OF_RETRIES (6.4.4.10.2), default 3.
	Retries int
	// InterOctet is the inter-octet time-out (6.4.4.10.4), default 100 ms
	// (the medium here is TCP through a converter or a serial port).
	InterOctet time.Duration
	// Bus, when set, is the multi-drop line this client shares (lower must
	// be one of its ports): every exchange holds the bus.
	Bus *Bus
	// Inactivity is the server's inactivity time-out (6.4.4.10.3; the
	// inactivity_time_out of its HDLC setup object). The server drops the
	// link after that long without an octet, so we take the link as gone a
	// little before (a tenth, at most 2 s) and set it up again instead of
	// sending into a dead link and waiting for DM. 0: not tracked.
	Inactivity time.Duration
	// OnUI receives the APDU of every UI frame the server sends (event
	// notifications, IEC 62056-7-6 9.4), LLC header removed. It runs on the
	// reading goroutine and must not block.
	OnUI func(from Address, apdu []byte)
}

// Errors a Client returns.
var (
	ErrNoLink   = errors.New("no HDLC link (send SNRM first)")
	ErrRefused  = errors.New("the server answered DM: it cannot enter normal response mode")
	ErrLinkLost = errors.New("the HDLC link was lost")
	ErrRejected = errors.New("the server rejected a frame (FRMR)")
	ErrTimeout  = errors.New("no HDLC response after the retries")
)

// maxMSDU bounds a reassembled MSDU.
const maxMSDU = 1 << 20

// Client is the primary station of an unbalanced connection-mode link
// (6.1) over a lower transport that carries octets (TCP to a converter, a
// serial port). It is a gosem Transport: Connect sends SNRM, Send moves
// one APDU in I frames and delivers the whole answer, Disconnect sends
// DISC. SendBroadcast sends an unconfirmed APDU in a UI frame
// (IEC 62056-7-6 9.1).
type Client struct {
	cfg   Config
	lower gdlms.Transport

	mu      sync.Mutex // one exchange at a time
	linked  bool
	params  Params // negotiated, our point of view
	vs, vr  int
	peer    []byte // user data the server put in its UA or DM
	expired int

	dmu    sync.Mutex
	dc     gdlms.DataChannel
	logger *log.Logger

	amu     sync.Mutex // guards cfg.Client and cfg.Server for the reader
	in      gdlms.DataChannel
	frames  chan Frame
	stop    chan struct{}
	stopped sync.Once
	gone    chan struct{} // closed when the lower transport stops delivering
	last    atomic.Int64  // UnixNano of the last octet sent or received
	ui      []byte        // UI segments so far (lenient receive, see F-233)
}

// NewClient builds a client over lower, which it owns.
func NewClient(lower gdlms.Transport, cfg Config) (*Client, error) {
	if cfg.Client < 1 || cfg.Client > 0x7E {
		return nil, fmt.Errorf("client address %d is not 1 to 126 (0 is no-station, 127 all-station)", cfg.Client)
	}
	if err := cfg.Server.Check(); err != nil {
		return nil, err
	}
	if cfg.Propose != nil {
		if err := cfg.Propose.Check(); err != nil {
			return nil, err
		}
	}
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = 3 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.InterOctet <= 0 {
		cfg.InterOctet = 100 * time.Millisecond
	}
	c := &Client{cfg: cfg, lower: lower, params: Defaults(), in: make(gdlms.DataChannel, 16),
		frames: make(chan Frame, 64), stop: make(chan struct{}), gone: make(chan struct{})}
	lower.SetReception(c.in)
	go c.read()
	return c, nil
}

// PeerUserData is the user data subfield of the server's last UA to our
// SNRM (ISO/IEC 13239 5.5.3.2.3), nil when it sent none.
func (c *Client) PeerUserData() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.peer...)
}

// rejected reads the reason of an FRMR (ISO/IEC 13239 5.5.3.4.2, modulo 8),
// logs it and returns the link error that names it.
func (c *Client) rejected(info []byte) error {
	err := rejectError(info)
	if c.logger != nil {
		c.logger.Printf("HDLC FRMR from the server: %v", err)
	}
	return err
}

// SetInactivity sets the server's inactivity time-out (0: not tracked),
// for instance once read from its HDLC setup object.
func (c *Client) SetInactivity(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.Inactivity = d
}

// Params are the negotiated parameters, from our point of view.
func (c *Client) Params() Params {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.params
}

// read turns octets into frames addressed to us.
func (c *Client) read() {
	s := Scanner{InterOctet: c.cfg.InterOctet}
	for {
		var chunk []byte
		var ok bool
		select {
		case chunk, ok = <-c.in:
		case <-c.stop:
			return
		}
		if !ok {
			close(c.gone)
			return
		}
		c.last.Store(time.Now().UnixNano())
		for _, raw := range s.Feed(chunk, time.Now()) {
			f, err := Decode(raw)
			if errors.Is(err, ErrHCS) {
				s.Reset()
				break
			}
			if err != nil || !c.ours(f) {
				continue
			}
			if ParseControl(f.Control).Kind == KindUI {
				c.gotUI(f)
				continue
			}
			select {
			case c.frames <- f:
			case <-c.stop:
				return
			}
		}
	}
}

// ours reports a frame from our server to us. Servers never send to a
// broadcast address (6.4.4.6). With the CALLING physical address the
// answer carries the server's own lower address (6.4.4.8).
func (c *Client) ours(f Frame) bool {
	c.amu.Lock()
	client, server := c.cfg.Client, c.cfg.Server
	c.amu.Unlock()
	ui := ParseControl(f.Control).Kind == KindUI
	if f.Dest.Size != 1 || (f.Dest.Upper != client && !(ui && f.Dest.Upper == ClientManagement)) {
		return false
	}
	// Event notifications come from the management logical device to the
	// client management process (IEC 62056-7-6 9.4), which we host too.
	if f.Src.Upper != server.Upper && !(ui && f.Src.Upper == ManagementDevice) {
		return false
	}
	if server.Size > 1 && f.Src.Size > 1 && f.Src.Lower != server.Lower && server.Lower != CallingFor(server.Size) {
		return false
	}
	return true
}

func (c *Client) gotUI(f Frame) {
	c.ui = append(c.ui, f.Info...)
	if f.Segmented && len(c.ui) < maxMSDU {
		return
	}
	msdu := c.ui
	c.ui = nil
	if apdu, ok := splitLLC(msdu, true); ok && len(apdu) > 0 && c.cfg.OnUI != nil {
		c.cfg.OnUI(f.Src, apdu)
	}
}

func (c *Client) write(f Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	if c.logger != nil {
		c.logger.Printf("HDLC TX % X", b)
	}
	err = c.lower.Send(b)
	c.last.Store(time.Now().UnixNano())
	return err
}

func (c *Client) frame(control byte, info []byte, segmented bool) Frame {
	return Frame{Dest: c.cfg.Server, Src: ClientAddress(c.cfg.Client), Control: control, Info: info, Segmented: segmented}
}

// await returns the next frame, or ok false after the response time-out.
func (c *Client) await() (Frame, bool, error) {
	t := time.NewTimer(c.cfg.ResponseTimeout)
	defer t.Stop()
	select {
	case f := <-c.frames:
		return f, true, nil
	case <-t.C:
		if !c.lower.IsConnected() {
			return Frame{}, false, ErrLinkLost
		}
		return Frame{}, false, nil
	case <-c.stop:
		return Frame{}, false, ErrLinkLost
	case <-c.gone:
		return Frame{}, false, ErrLinkLost
	}
}

// drain drops frames left from an earlier exchange.
func (c *Client) drain() {
	for {
		select {
		case <-c.frames:
		default:
			return
		}
	}
}

// Connect opens the lower transport and sets up the link: SNRM, then UA
// with the negotiation result or DM (6.4.4.4.3.1). SNRM is repeated after
// each response time-out, up to the retries.
func (c *Client) Connect() error {
	defer c.hold()()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.lower.Connect(); err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	c.linked = false
	c.drain()
	var info []byte
	proposed := Defaults()
	if c.cfg.Propose != nil {
		proposed = *c.cfg.Propose
		info = proposed.Encode(c.cfg.UserData)
	} else if len(c.cfg.UserData) > 0 {
		info = Defaults().Encode(c.cfg.UserData)
	}
	snrm := c.frame(ctl(KindSNRM, true), info, false)
	for try := 0; try <= c.cfg.Retries; try++ {
		if err := c.write(snrm); err != nil {
			return err
		}
		for {
			f, ok, err := c.await()
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			switch ParseControl(f.Control).Kind {
			case KindUA:
				got, user, err := DecodeParams(f.Info)
				if err != nil {
					return fmt.Errorf("the UA: %w", err)
				}
				c.params = bounded(got.Mirror(), proposed)
				c.peer = user
				c.vs, c.vr, c.linked = 0, 0, true
				return nil
			case KindDM:
				return ErrRefused
			}
		}
	}
	return fmt.Errorf("SNRM: %w", ErrTimeout)
}

// Disconnect sends DISC and waits for UA or DM (6.4.4.4.3.3), then closes
// the lower transport.
func (c *Client) Disconnect() error {
	defer c.hold()()
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { _ = c.lower.Disconnect() }()
	c.checkInactivity()
	if !c.linked || !c.lower.IsConnected() {
		c.linked = false
		return nil
	}
	c.linked = false
	c.drain()
	disc := c.frame(ctl(KindDISC, true), EncodeUserData(c.cfg.DISCUserData), false)
	for try := 0; try <= c.cfg.Retries; try++ {
		if err := c.write(disc); err != nil {
			return err
		}
		for {
			f, ok, err := c.await()
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			if k := ParseControl(f.Control).Kind; k == KindUA || k == KindDM {
				return nil
			}
		}
	}
	return fmt.Errorf("DISC: %w", ErrTimeout)
}

// IsConnected reports a link in normal response mode on a connected lower
// transport, not past the server's inactivity time-out.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkInactivity()
	return c.linked && c.lower.IsConnected()
}

// inactive reports that the server has dropped the link by now.
func (c *Client) inactive() bool {
	t := c.cfg.Inactivity
	if t <= 0 {
		return false
	}
	margin := min(t/10, 2*time.Second)
	return time.Since(time.Unix(0, c.last.Load())) >= t-margin
}

// checkInactivity ends the link when the server's inactivity time-out has
// run: the server is in disconnected mode (6.4.4.10.3).
func (c *Client) checkInactivity() {
	if c.linked && c.inactive() {
		c.linked = false
		c.expired++
	}
}

// Expired counts links ended by the inactivity time-out.
func (c *Client) Expired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expired
}

// SetAddress changes the client and logical device (upper) addresses.
func (c *Client) SetAddress(client, server int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.amu.Lock()
	defer c.amu.Unlock()
	c.cfg.Client, c.cfg.Server.Upper = client, server
}

// SetReception sets where whole APDUs go.
func (c *Client) SetReception(dc gdlms.DataChannel) {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.dc != nil {
		close(c.dc)
	}
	c.dc = dc
}

// SetLogger logs frames.
func (c *Client) SetLogger(l *log.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = l
	c.lower.SetLogger(l)
}

// Close stops the client and closes the lower transport.
func (c *Client) Close() {
	c.stopped.Do(func() { close(c.stop) })
	c.mu.Lock()
	c.linked = false
	c.mu.Unlock()
	c.lower.Close()
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.dc != nil {
		close(c.dc)
		c.dc = nil
	}
}

func (c *Client) deliver(apdu []byte) {
	c.dmu.Lock()
	dc := c.dc
	c.dmu.Unlock()
	if dc != nil {
		select {
		case dc <- apdu:
		case <-c.stop:
		}
	}
}

// SendBroadcast sends an unconfirmed APDU in one UI frame with P 0 to the
// server address (IEC 62056-7-6 9.1). The UI frame needs no link; its data
// must fit one frame (6.4.4.4.3.4).
func (c *Client) SendBroadcast(apdu []byte) error {
	defer c.hold()()
	c.mu.Lock()
	defer c.mu.Unlock()
	info := append(append([]byte(nil), LLCCommand...), apdu...)
	if mx := c.params.MaxInfoTX; len(info) > mx {
		return fmt.Errorf("an unconfirmed APDU of %d octets does not fit one UI frame of %d", len(apdu), mx)
	}
	return c.write(c.frame(ctl(KindUI, false), info, false))
}

// Trigger sends an empty UI frame with P 1, which gives the server the
// right to send its pending UI frames (6.4.4.7, IEC 62056-7-6 9.4); they
// reach OnUI.
func (c *Client) Trigger() error {
	defer c.hold()()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.write(c.frame(ctl(KindUI, true), nil, false))
}

// Send moves one APDU to the server in I frames and waits for its answer,
// which it delivers whole to the reception channel. Segments are sent
// windowed (6.4.4.4.3.4 to 6.4.4.4.3.6); every window ends with P 1 and
// the server's RR acknowledges it. The answer arrives in windows ending
// with F 1; while its last frame has the segmentation bit set we poll for
// more with RR (this also covers the long MSDU transfer of 6.4.4.5). A
// response time-out after an I frame is recovered with an RR poll, never by
// repeating the I frame (6.4.4.9.1).
func (c *Client) Send(apdu []byte) error {
	defer c.hold()()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkInactivity()
	if !c.linked {
		return ErrNoLink
	}
	msdu := append(append([]byte(nil), LLCCommand...), apdu...)
	resp, err := c.transfer(msdu)
	if err != nil {
		if errors.Is(err, ErrLinkLost) || errors.Is(err, ErrRejected) || errors.Is(err, ErrTimeout) {
			c.linked = false
		}
		return err
	}
	if resp != nil {
		c.deliver(resp)
	}
	return nil
}

// transfer runs one exchange and returns the answer's APDU, or nil when
// the server had nothing to send.
func (c *Client) transfer(msdu []byte) ([]byte, error) {
	c.drain()
	mx := c.params.MaxInfoTX
	var segs [][]byte
	for len(msdu) > 0 {
		n := min(len(msdu), mx)
		segs = append(segs, msdu[:n])
		msdu = msdu[n:]
	}
	base := c.vs // N(S) of segs[0]
	una, next := 0, 0
	retries := 0
	awaiting := false
	var first *Frame
	for first == nil {
		if !awaiting {
			if una == len(segs) {
				return nil, nil // all acknowledged by an RR F 1: no answer
			}
			end := min(una+c.params.WindowTX, len(segs))
			for k := next; k < end; k++ {
				f := c.frame(ctlI(c.vr, (base+k)&7, k == end-1), segs[k], k < len(segs)-1)
				if err := c.write(f); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrLinkLost, err)
				}
			}
			next = end
			c.vs = (base + next) & 7
			awaiting = true
		}
		f, ok, err := c.await()
		if err != nil {
			return nil, err
		}
		if !ok {
			if retries++; retries > c.cfg.Retries {
				return nil, ErrTimeout
			}
			if err := c.write(c.frame(ctlRR(c.vr, true), nil, false)); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrLinkLost, err)
			}
			continue
		}
		ctl := ParseControl(f.Control)
		switch ctl.Kind {
		case KindRR, KindRNR, KindI:
			n := (ctl.NR - (base + una)) & 7
			if n > next-una {
				return nil, fmt.Errorf("%w: N(R) %d acknowledges frames not sent", ErrRejected, ctl.NR)
			}
			una += n
			if ctl.Kind == KindI {
				if una < len(segs) {
					return nil, fmt.Errorf("%w: an I frame before our MSDU was complete", ErrRejected)
				}
				first = &f
				break
			}
			if !ctl.PF {
				continue
			}
			retries = 0
			awaiting = false
			if ctl.Kind == KindRNR {
				// Busy (6.4.3.5): wait, then poll.
				time.Sleep(min(c.cfg.ResponseTimeout/4, 500*time.Millisecond))
				if err := c.write(c.frame(ctlRR(c.vr, true), nil, false)); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrLinkLost, err)
				}
				awaiting = true
				continue
			}
			if una < next {
				next = una // lost frames: send again from N(R)
			}
		case KindDM:
			return nil, fmt.Errorf("%w: the server is in disconnected mode (DM)", ErrLinkLost)
		case KindFRMR:
			return nil, c.rejected(f.Info)
		}
	}
	return c.receive(*first)
}

// receive gathers the answer, starting with its first I frame.
func (c *Client) receive(f Frame) ([]byte, error) {
	var buf []byte
	complete := false
	retries := 0
	have := true
	for {
		if !have {
			var ok bool
			var err error
			if f, ok, err = c.await(); err != nil {
				return nil, err
			} else if !ok {
				if retries++; retries > c.cfg.Retries {
					return nil, ErrTimeout
				}
				if err := c.write(c.frame(ctlRR(c.vr, true), nil, false)); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrLinkLost, err)
				}
				continue
			}
		}
		have = false
		ctl := ParseControl(f.Control)
		switch ctl.Kind {
		case KindI:
			if ctl.NS == c.vr && !complete {
				c.vr = (c.vr + 1) & 7
				buf = append(buf, f.Info...)
				complete = !f.Segmented
				if len(buf) > maxMSDU {
					return nil, fmt.Errorf("%w: an answer longer than %d octets", ErrRejected, maxMSDU)
				}
			} // else a sequence error: dropped, recovered by the poll below
		case KindRR, KindRNR:
			if !ctl.PF {
				continue
			}
			if !complete && len(buf) == 0 {
				return nil, nil
			}
		case KindDM:
			return nil, fmt.Errorf("%w: the server is in disconnected mode (DM)", ErrLinkLost)
		case KindFRMR:
			return nil, c.rejected(f.Info)
		default:
			continue
		}
		if !ctl.PF {
			continue
		}
		retries = 0
		if complete {
			apdu, ok := splitLLC(buf, true)
			if !ok {
				return nil, errors.New("the answer has no LLC response header (E6 E7 00)")
			}
			return apdu, nil
		}
		// More to come (segmentation bit on the window's last frame) or a
		// sequence error: acknowledge what we have and poll.
		if err := c.write(c.frame(ctlRR(c.vr, true), nil, false)); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLinkLost, err)
		}
	}
}
