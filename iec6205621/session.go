package iec6205621

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// partial: the command sends or takes partial blocks (mode C only).
func partial(cmd string) bool { return cmd == "R3" || cmd == "R4" || cmd == "W3" || cmd == "W4" }

// SessionConfig is how a session with a meter runs: its line, the device
// address of the sign-on, wake-up (annex B.1) or fast wake-up (annex B.2,
// sessions end with B1), the highest rate accepted in mode B or C and
// whether to follow the meter's rate at all (on a converter the rate is
// fixed), the character wait, the read and write commands of programming
// mode (R1 to R6, W1 to W5) with the value length of W3/W4 partial
// blocks, and a callback for the meter's identification.
type SessionConfig struct {
	Line             Line
	MeterAddress     string
	WakeUp           bool
	FastWakeUp       bool
	MaxBaud          int
	BaudSwitch       bool
	Timeout          time.Duration
	ReadCommand      string
	WriteCommand     string
	PartialBlockSize int
	Identified       func(Identification)
}

// Session is one session with a meter, from its sign-on to its close.
type Session struct {
	cfg     *SessionConfig
	c       *conn
	id      Identification
	z       byte // the baud character agreed in the option select
	binary  bool // mode E: the port carries HDLC now
	program bool // in programming mode: close with B0
	signOn  bool // woken with the fast wake-up: close with B1 (annex B.2)
}

func (s *Session) timeout() time.Duration { return s.cfg.Timeout }

// reaction is the pause before we answer the meter: tr is more than
// 200 ms, or 20 ms for a meter with a lower-case third manufacturer
// letter (item 12, 6.4.1.5).
func (s *Session) reaction() time.Duration {
	if s.id.FastReaction {
		return 20 * time.Millisecond
	}
	return 200 * time.Millisecond
}

func (s *Session) send(b []byte) error {
	time.Sleep(s.reaction())
	return s.c.write(b)
}

func (s *Session) readMessage(bcc bool) (Message, error) {
	s.c.setDeadline(s.timeout())
	m, err := ReadMessage(s.c, bcc)
	if errors.Is(err, errTimeout) {
		return m, errors.New("the meter did not answer")
	}
	return m, err
}

// maxTries is how often a message is sent before the HHU gives up and
// sends the break message (Figure 23: after three tries).
const maxTries = 3

var errBreak = errors.New("the meter ended the session (B0)")

// exchange sends b and returns the meter's answer. A NAK from the meter
// asks for b again; an answer with a wrong BCC is answered with NAK so
// the meter repeats it (annex A, note 3). After maxTries the session is
// broken off with B0. A B0 from the meter is errBreak.
func (s *Session) exchange(b []byte) (Message, error) {
	out := b
	for try := 1; ; try++ {
		if try > maxTries {
			s.abort()
			return Message{}, fmt.Errorf("no valid exchange after %d tries: the session was broken off", maxTries)
		}
		if err := s.send(out); err != nil {
			return Message{}, err
		}
		msg, err := s.readMessage(true)
		switch {
		case errors.Is(err, ErrBCC):
			out = []byte{NAK}
			continue
		case err != nil:
			return msg, err
		case msg.Kind == NAK:
			out = b
			continue
		case msg.Kind == SOH && msg.Command == "B0":
			s.program, s.signOn = false, false
			return msg, errBreak
		}
		return msg, nil
	}
}

// abort sends the break message and leaves programming mode. A meter
// woken with the fast wake-up gets B1 instead, in every mode, and
// acknowledges it (annex B.2).
func (s *Session) abort() {
	if s.signOn {
		_ = s.signOff()
		return
	}
	if s.program {
		_ = s.send(Block("B0", "", false, ETX))
		s.program = false
	}
}

// signOff sends B1 and waits for the meter's ACK (annex B.2).
func (s *Session) signOff() error {
	s.signOn, s.program = false, false
	if err := s.send(Block("B1", "", false, ETX)); err != nil {
		return err
	}
	m, err := s.readMessage(true)
	if err != nil {
		return fmt.Errorf("sign-off B1: %w", err)
	}
	if m.Kind != ACK {
		return fmt.Errorf("sign-off B1 answered with %q, not ACK", m.Kind)
	}
	return nil
}

// fastWakeUp is the annex B.2 fast wake-up: NUL strings of 0.55 s
// (Tn 500 ms to 600 ms), each followed by a wait for the meter's ACK
// (Td: 20 ms and two characters, plus 20 ms, plus a margin for a
// converter), for at least the recommended 4.5 s; after the ACK the
// request follows 200 ms to 1500 ms later.
func (c *conn) fastWakeUp(ctx context.Context) error {
	n := c.baud * 55 / 1000
	charTime := 10 * time.Second / time.Duration(c.baud)
	td := 40*time.Millisecond + 2*charTime + 100*time.Millisecond
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		if err := c.write(make([]byte, n)); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(n) * charTime):
		}
		c.setDeadline(td)
		for {
			b, err := c.ReadByte()
			if errors.Is(err, errTimeout) {
				break
			}
			if err != nil && !errors.Is(err, ErrParity) {
				return err
			}
			if err == nil && b == ACK {
				time.Sleep(300 * time.Millisecond)
				c.p.drain()
				return nil
			}
		}
	}
	return errors.New("fast wake-up: the meter did not acknowledge the NUL strings (annex B.2)")
}

// wakeUp sends the annex B.1 wake-up message for battery-operated
// meters: NUL characters for 2.2 s at the current rate, then a 1.6 s
// pause before the request.
func (c *conn) wakeUp(ctx context.Context) error {
	n := WakeUpNULs(c.baud)
	if err := c.write(make([]byte, n)); err != nil {
		return err
	}
	d := time.Duration(n*10)*time.Second/time.Duration(c.baud) + 1600*time.Millisecond
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
	}
	c.p.drain()
	return nil
}

// txTime is how long n characters take on the line at the current rate
// (ten bits each), plus a small margin, before the rate may change: the
// meter answers tr (at least 20 ms) after the last character.
func (c *conn) txTime(n int) time.Duration {
	return time.Duration(n*10)*time.Second/time.Duration(c.baud) + 5*time.Millisecond
}

// OpenSession signs on and reads the identification. y is '0' for a readout,
// '1' for programming. With handOver, a mode E meter is switched to its
// binary (HDLC) phase instead and the session is marked binary. For a
// readout the data message is left for the caller. For programming, a
// mode C or E meter's opening operand (P0) is returned; modes A and B
// have none: their data message is read and dropped and the session
// continues at 300 baud (6.4.1.3, 6.4.2.3).
func OpenSession(ctx context.Context, cfg *SessionConfig, y byte, handOver bool) (*Session, *Message, error) {
	c, err := dial(ctx, cfg.Line, 300)
	if err != nil {
		return nil, nil, err
	}
	s := &Session{cfg: cfg, c: c, z: '0'}
	fail := func(err error) (*Session, *Message, error) { c.Close(); return nil, nil, err }
	if cfg.WakeUp {
		if err := c.wakeUp(ctx); err != nil {
			return fail(err)
		}
	}
	if cfg.FastWakeUp {
		if err := c.fastWakeUp(ctx); err != nil {
			return fail(err)
		}
		s.signOn = true
	}
	if err := c.write(SignOn(cfg.MeterAddress)); err != nil {
		return fail(err)
	}
	c.setDeadline(s.timeout())
	line, err := readLine(c, 64)
	if errors.Is(err, errTimeout) {
		return fail(errors.New("no identification: the meter did not answer the sign-on"))
	}
	if err != nil {
		return fail(fmt.Errorf("reading the identification: %w", err))
	}
	// Echoes of our own request (half-duplex probes) are skipped.
	if strings.HasPrefix(line, "/?") {
		c.setDeadline(s.timeout())
		if line, err = readLine(c, 64); err != nil {
			return fail(fmt.Errorf("reading the identification: %w", err))
		}
	}
	id, err := ParseIdentification(line)
	if err != nil {
		return fail(err)
	}
	s.id = id
	if cfg.Identified != nil {
		cfg.Identified(id)
	}
	if y == '1' && (partial(cfg.ReadCommand) || partial(cfg.WriteCommand)) && id.Mode != ModeC && id.Mode != ModeE {
		return fail(fmt.Errorf("partial blocks (R3, R4, W3, W4) are for mode C meters; this meter is mode %c", id.Mode))
	}
	switch id.Mode {
	case ModeA, ModeB:
		if id.Mode == ModeB {
			if id.Baud > cfg.MaxBaud || !cfg.BaudSwitch {
				return fail(fmt.Errorf("the mode B meter switches to %d baud on its own, which this port cannot follow", id.Baud))
			}
			if err := c.setBaud(id.Baud); err != nil {
				return fail(err)
			}
		}
		if y == '0' {
			return s, nil, nil
		}
		// Programming follows the data readout, at 300 baud.
		c.setDeadline(s.timeout())
		if _, err := ReadDataMessage(c); err != nil {
			return fail(fmt.Errorf("reading the data message before programming mode: %w", err))
		}
		if err := c.setBaud(300); err != nil {
			return fail(err)
		}
		s.program = true
		return s, nil, nil
	case ModeC, ModeE:
		// The meter changes rate only when our Z equals its own; any
		// other Z keeps both ends at 300 baud (6.4.3.2), so we either
		// accept its rate or ask for 300.
		baud := 300
		if cfg.BaudSwitch && id.Baud <= cfg.MaxBaud {
			baud, s.z = id.Baud, id.BaudChar
		}
		if id.Mode == ModeE && handOver && y == '0' {
			// Annex E: V '2' (HDLC protocol procedure), Y '2' (binary
			// mode). The meter confirms with ACK 2 Z 2 CR LF at the new
			// rate, still 7E1, then both ends use 8N1. A 7E1 character
			// and an 8N1 byte take the same time on the line, so the port
			// goes to 8N1 at once and the confirm is read with its parity
			// bits (Figure E.4); readDLMS checks it.
			if err := s.send(OptionSelect('2', s.z, '2')); err != nil {
				return fail(err)
			}
			time.Sleep(c.txTime(6))
			if err := c.setBinary(baud); err != nil {
				return fail(err)
			}
			s.binary = true
			return s, nil, nil
		}
		// Mode E meters also accept a mode C option select (V = '0').
		if err := s.send(OptionSelect('0', s.z, y)); err != nil {
			return fail(err)
		}
		// The rate changes once the acknowledgement is out.
		time.Sleep(c.txTime(6))
		if err := c.setBaud(baud); err != nil {
			return fail(err)
		}
	}
	if y == '1' {
		// The meter opens programming mode with an operand message P0.
		s.program = true
		m, err := s.readMessage(true)
		for try := 1; errors.Is(err, ErrBCC) && try < maxTries; try++ {
			if err = s.send([]byte{NAK}); err == nil {
				m, err = s.readMessage(true)
			}
		}
		if err != nil {
			s.abort()
			return fail(fmt.Errorf("entering programming mode: %w", err))
		}
		return s, &m, nil
	}
	return s, nil, nil
}

// ConfirmModeE reads the meter's switch confirm after a binary option
// select: ACK 2 Z 2 CR LF with even parity in bit 7. Anything else means
// the meter did not enter mode E (annex E.5).
func (s *Session) ConfirmModeE() error {
	want := WithParity(ModeEConfirm(s.z))
	got := make([]byte, 0, len(want))
	s.c.p.SetDeadline(time.Now().Add(s.timeout()))
	for len(got) < len(want) {
		b, err := s.c.p.ReadByte()
		if errors.Is(err, errTimeout) {
			return fmt.Errorf("mode E: no switch confirm (got % X)", got)
		}
		if err != nil {
			return fmt.Errorf("mode E: reading the switch confirm: %w", err)
		}
		got = append(got, b)
		if b != want[len(got)-1] {
			return fmt.Errorf("mode E: the meter answered % X, not the switch confirm % X", got, want)
		}
	}
	s.c.p.SetDeadline(time.Time{})
	return nil
}

// Close ends the session (B0 in programming mode, B1 after a fast
// wake-up) and closes the line.
func (s *Session) Close() {
	s.abort()
	time.Sleep(50 * time.Millisecond)
	s.c.Close()
}

// ReadData reads and parses the data message of a readout.
func (s *Session) ReadData() ([]DataSet, error) {
	s.c.setDeadline(s.timeout())
	msg, err := ReadDataMessage(s.c)
	if errors.Is(err, errTimeout) {
		return nil, errors.New("reading the data message: the meter did not answer")
	}
	if err != nil {
		return nil, fmt.Errorf("reading the data message: %w", err)
	}
	if msg.Partial {
		return nil, errors.New("the data message ended with EOT; partial blocks belong to programming mode")
	}
	return ParseDataSets(msg.Data)
}

// EndReadout ends a readout: a meter woken with the fast wake-up gets B1
// and acknowledges it (annex B.2); others need nothing.
func (s *Session) EndReadout() error {
	if s.signOn {
		return s.signOff()
	}
	return nil
}

// OpenProgramming signs on in programming mode and gives the password:
// access level 1 (annex D) needs none, and with an empty password the
// commands follow the operand directly; with one, it goes in a P1
// command, which the meter accepts with ACK and refuses with B0 (annex A)
// or an error message.
func OpenProgramming(ctx context.Context, cfg *SessionConfig, password string) (*Session, error) {
	s, op, err := OpenSession(ctx, cfg, '1', false)
	if err != nil {
		return nil, err
	}
	if err := s.login(op, password); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) login(op *Message, password string) error {
	if op != nil {
		switch {
		case op.Kind == SOH && op.Command == "B0":
			s.program = false
			return errors.New("the meter refused programming mode (B0)")
		case op.Kind == SOH && op.Command == "P0":
		default:
			return fmt.Errorf("unexpected programming mode opening %q %s", op.Kind, op.Command)
		}
	}
	if password != "" {
		ans, err := s.exchange(Block("P1", "("+password+")", true, ETX))
		if errors.Is(err, errBreak) {
			return errors.New("the meter refused the password and ended the session (B0)")
		}
		if err != nil {
			return fmt.Errorf("password: %w", err)
		}
		if ans.Kind != ACK {
			if ds, err := ParseDataSets(ans.Data); err == nil {
				if e, ok := ErrorValue(ds); ok {
					return fmt.Errorf("the meter refused the password with error %s", e)
				}
			}
			return errors.New("the meter refused the password")
		}
	}
	return nil
}

// Read sends a read command and returns the answer's data sets; partial
// blocks are acknowledged and joined.
func (s *Session) Read(addr string) ([]DataSet, error) {
	return s.ReadWith(s.cfg.ReadCommand, addr)
}

// ReadWith sends a read command. The answer is a data message, NAK
// (repeat, handled by exchange) or an error message; partial blocks
// (EOT) are acknowledged with ACK and a faulty one with NAK (6.4.7,
// Figure 21).
func (s *Session) ReadWith(cmd, addr string) ([]DataSet, error) {
	msg, err := s.exchange(Block(cmd, addr, true, ETX))
	var data strings.Builder
	for {
		if err != nil {
			return nil, err
		}
		if msg.Kind != STX {
			return nil, fmt.Errorf("unexpected answer %q", msg.Kind)
		}
		data.WriteString(msg.Data)
		if !msg.Partial {
			break
		}
		msg, err = s.exchange([]byte{ACK})
	}
	ds, err := ParseDataSets(data.String())
	if err != nil {
		return nil, err
	}
	if e, ok := ErrorValue(ds); ok {
		return nil, fmt.Errorf("the meter answered with error %s", e)
	}
	return ds, nil
}

// WriteValue sends a write command and waits for ACK. With W3 or W4 a
// value longer than one block goes in partial blocks: the address only
// in the first, each block acknowledged, the last ending with ETX
// (6.4.7, Figure 22). With W2 or W4 the address is an annex C code; an
// empty value resets the record, and in the season, group and load
// profile categories the write erases (C.3).
func (s *Session) WriteValue(addr, value string) error {
	cmd := s.cfg.WriteCommand
	var blocks []string
	chunk := s.cfg.PartialBlockSize
	if (cmd == "W3" || cmd == "W4") && len(value) > chunk {
		for i := 0; i < len(value); i += chunk {
			j := min(i+chunk, len(value))
			b := "(" + value[i:j] + ")"
			if i == 0 {
				b = addr + b
			}
			blocks = append(blocks, b)
		}
	} else {
		blocks = []string{addr + "(" + value + ")"}
	}
	for i, b := range blocks {
		end := byte(EOT)
		if i == len(blocks)-1 {
			end = ETX
		}
		msg, err := s.exchange(Block(cmd, b, true, end))
		if errors.Is(err, errBreak) {
			return errors.New("the meter ended the session during the write (B0)")
		}
		if err != nil {
			return err
		}
		if msg.Kind == ACK {
			continue
		}
		if ds, err := ParseDataSets(msg.Data); err == nil {
			if e, ok := ErrorValue(ds); ok {
				return fmt.Errorf("the meter refused the write with error %s", e)
			}
		}
		return fmt.Errorf("unexpected answer to the write: %q", msg.Data)
	}
	return nil
}

// Execute sends an E2 formatted execute (annex C.5): the meter answers
// ACK (no data sets), or a data message for the readout functions, or an
// error message.
func (s *Session) Execute(code, data string) ([]DataSet, error) {
	msg, err := s.exchange(Block("E2", code+"("+data+")", true, ETX))
	if errors.Is(err, errBreak) {
		return nil, errors.New("the meter ended the session during the execute (B0)")
	}
	if err != nil {
		return nil, err
	}
	if msg.Kind == ACK {
		return nil, nil
	}
	var all strings.Builder
	for {
		if msg.Kind != STX {
			return nil, fmt.Errorf("unexpected answer %q to the execute", msg.Kind)
		}
		all.WriteString(msg.Data)
		if !msg.Partial {
			break
		}
		if msg, err = s.exchange([]byte{ACK}); err != nil {
			return nil, err
		}
	}
	ds, err := ParseDataSets(all.String())
	if err != nil {
		return nil, err
	}
	if e, ok := ErrorValue(ds); ok {
		return nil, fmt.Errorf("the meter refused the execute with error %s", e)
	}
	if ds == nil {
		ds = []DataSet{}
	}
	return ds, nil
}

// timedReader waits without limit for the first character of a message
// and at most ta for each of the others (6.4.4.2).
type timedReader struct {
	c       *conn
	ta      time.Duration
	started bool
}

func (r *timedReader) ReadByte() (byte, error) {
	if r.started {
		r.c.setDeadline(r.ta)
	} else {
		r.c.p.SetDeadline(time.Time{})
	}
	b, err := r.c.ReadByte()
	r.started = err == nil
	return b, err
}

// ListenModeD opens the line at 2400 baud and hands each mode D message
// the meter sends to onPush until ctx ends or the line fails. A message
// with a parity error goes to onParity and the line is drained. ta is the
// longest wait between two characters of a message (6.4.4.2).
func ListenModeD(ctx context.Context, line Line, ta time.Duration, onPush func(Push), onParity func(error)) error {
	c, err := dial(ctx, line, ModeDBaud)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	defer c.Close()
	for {
		r := &timedReader{c: c, ta: ta}
		push, err := ReadPush(r)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errTimeout) {
			err = errors.New("the mode D message stopped mid-way")
		}
		if err != nil {
			if errors.Is(err, ErrParity) {
				if onParity != nil {
					onParity(err)
				}
				c.p.drain()
				continue
			}
			return err
		}
		onPush(push)
	}
}

// ParseStamp reads "YYMMDDhhmm" or "YYMMDDhhmmss", optionally after a
// season digit.
func ParseStamp(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "-:") {
		// Annex C form: YY-MM-DD, YY-MM-DD hh:mm (or hh mm, hh.mm).
		s = strings.NewReplacer("-", "", ":", "", " ", "", ".", "").Replace(s)
		if len(s) == 6 {
			s += "0000"
		}
		if len(s) != 10 {
			return time.Time{}, false
		}
	}
	if len(s) == 11 || len(s) == 13 {
		s = s[1:]
	}
	if len(s) != 10 && len(s) != 12 {
		return time.Time{}, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
	}
	n := func(i int) int { v, _ := strconv.Atoi(s[i : i+2]); return v }
	sec := 0
	if len(s) == 12 {
		sec = n(10)
	}
	year := 2000 + n(0)
	if n(0) >= 70 {
		year -= 100 // two-digit years: 70 to 99 are 1970 to 1999
	}
	t := time.Date(year, time.Month(n(2)), n(4), n(6), n(8), sec, 0, loc)
	if t.Month() != time.Month(n(2)) || t.Day() != n(4) {
		return time.Time{}, false
	}
	return t, true
}

// Stamp writes a time as YYMMDDhhmm in loc, as profile requests take it.
func Stamp(t time.Time, loc *time.Location) string { return t.In(loc).Format("0601021504") }

// ProfileRow is one load profile period.
type ProfileRow struct {
	Time   time.Time
	Status string
	Values map[string]any // by channel name (OBIS table name or code), numbers where they parse
}

// ParseProfile reads a profile answer: a header data set "P.01" with the
// start time, status, period in minutes, channel count and one (code)(unit)
// pair per channel, then value-only data sets, one row per period. A new
// header may appear anywhere and restarts the clock.
func ParseProfile(ds []DataSet, address string, loc *time.Location) ([]ProfileRow, error) {
	var rows []ProfileRow
	var t time.Time
	var period time.Duration
	var names []string
	var status string
	var vals []string
	flush := func() {
		for len(vals) >= len(names) && len(names) > 0 {
			row := ProfileRow{Time: t, Status: status, Values: map[string]any{}}
			for i, n := range names {
				if f, ok := Number(vals[i]); ok {
					row.Values[n] = f
				} else {
					row.Values[n] = vals[i]
				}
			}
			rows = append(rows, row)
			vals = vals[len(names):]
			t = t.Add(period)
		}
	}
	for _, d := range ds {
		if d.Address == "" {
			if names == nil {
				return rows, errors.New("profile values before the header")
			}
			vals = append(vals, d.Value)
			vals = append(vals, d.Extra...)
			flush()
			continue
		}
		if !strings.EqualFold(d.Address, address) {
			continue
		}
		g := append([]string{d.Value}, d.Extra...)
		if len(g) < 4 {
			return rows, fmt.Errorf("profile header %v is too short", g)
		}
		st, ok := ParseStamp(g[0], loc)
		if !ok {
			return rows, fmt.Errorf("profile header time %q is not YYMMDDhhmm", g[0])
		}
		p, err1 := strconv.Atoi(g[2])
		n, err2 := strconv.Atoi(g[3])
		if err1 != nil || err2 != nil || p <= 0 || n <= 0 || len(g) < 4+2*n {
			return rows, fmt.Errorf("profile header %v has a bad period or channel list", g)
		}
		t, status, period = st, g[1], time.Duration(p)*time.Minute
		names = names[:0:0]
		for i := 0; i < n; i++ {
			names = append(names, PointName(g[4+2*i]))
		}
		vals = nil
	}
	return rows, nil
}

// Identification is the meter's answer to the sign-on.
func (s *Session) Identification() Identification { return s.id }

// Binary reports a session switched to the mode E binary phase: the
// line carries HDLC now (binaryPort).
func (s *Session) Binary() bool { return s.binary }

// BinaryPort is the line after a mode E switch, for a DLMS client over
// HDLC (cosem.NewPortClient); closing it closes the line.
func (s *Session) BinaryPort() io.ReadWriteCloser { return binaryPort{c: s.c} }

// CloseLine closes the line without ending the session first.
func (s *Session) CloseLine() { s.c.Close() }
