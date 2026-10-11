package phy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// source is where the physical connection manager exchanges octets with
// the line while the data link layer is not using it: the Hayes command
// dialogue (annex A) and the identification messages (6.3.3).
type source interface {
	recv(timeout time.Duration) ([]byte, error)
	send(b []byte) error
}

// errTimeout is a receive time-out.
var errTimeout = errors.New("time-out")

// connSource reads a connection directly (no reader goroutine yet).
type connSource struct{ c net.Conn }

func (s connSource) recv(timeout time.Duration) ([]byte, error) {
	_ = s.c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = s.c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 512)
	n, err := s.c.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil, errTimeout
	}
	return nil, err
}

func (s connSource) send(b []byte) error { _, err := s.c.Write(b); return err }

// lines reads Hayes result messages: text lines ended by CR or LF, empty
// lines skipped.
type lines struct {
	src source
	buf []byte
}

// next returns the next non-empty line within the deadline.
func (l *lines) next(deadline time.Time) (string, error) {
	for {
		if i := bytes.IndexAny(l.buf, "\r\n"); i >= 0 {
			line := strings.TrimSpace(string(l.buf[:i]))
			l.buf = l.buf[i+1:]
			if line != "" {
				return line, nil
			}
			continue
		}
		left := time.Until(deadline)
		if left <= 0 {
			return "", errTimeout
		}
		b, err := l.src.recv(left)
		if err != nil {
			return "", err
		}
		l.buf = append(l.buf, b...)
	}
}

// Hayes results (annex A.2.2, A.2.5, A.2.6).
const (
	resOK        = "OK"
	resConnect   = "CONNECT"
	resError     = "ERROR"
	resNoDial    = "NO DIALTONE"
	resNoCarrier = "NO CARRIER"
	resBusy      = "BUSY"
	resRing      = "RING"
)

// ErrConnect is a PH-CONNECT.confirm with a negative result.
var ErrConnect = errors.New("the physical connection was not established")

// result reads lines until one of the final results; an echo of the
// command and unknown lines are skipped.
func (l *lines) result(deadline time.Time, final ...string) (string, error) {
	for {
		line, err := l.next(deadline)
		if err != nil {
			return "", err
		}
		u := strings.ToUpper(strings.ReplaceAll(line, "_", " "))
		for _, f := range final {
			if u == f || strings.HasPrefix(u, f+" ") {
				return u, nil
			}
		}
	}
}

// command sends a Hayes command line and waits for OK.
func command(l *lines, cmd string, timeout time.Duration) error {
	if err := l.src.send([]byte(cmd + "\r")); err != nil {
		return err
	}
	r, err := l.result(time.Now().Add(timeout), resOK, resError)
	if err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}
	if r != resOK {
		return fmt.Errorf("%s: the modem answered %s", cmd, r)
	}
	return nil
}

// rateOf reads the rate a CONNECT message reports ("CONNECT 9600", or
// "CONNECT 9600/ARQ"); 0 when it names none.
func rateOf(r string) int {
	f := strings.Fields(strings.TrimPrefix(r, resConnect))
	if len(f) == 0 {
		return 0
	}
	d := f[0]
	for i, c := range d {
		if c < '0' || c > '9' {
			d = d[:i]
			break
		}
	}
	n, _ := strconv.Atoi(d)
	return n
}

// dial performs PH-CONNECT.request over an intelligent Hayes modem (annex
// A.2.1, A.2.2): the initialisation commands, then ATD with the number;
// CONNECT is a positive PH-CONNECT.confirm with the rate it reports, and
// ERROR, NO DIALTONE, NO CARRIER and BUSY negative ones.
func dial(l *lines, number string, init []string, cmdTimeout, connectTimeout time.Duration) (int, error) {
	for _, c := range init {
		if err := command(l, c, cmdTimeout); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrConnect, err)
		}
	}
	if err := l.src.send([]byte("ATD" + number + "\r")); err != nil {
		return 0, err
	}
	r, err := l.result(time.Now().Add(connectTimeout), resConnect, resError, resNoDial, resNoCarrier, resBusy)
	if err != nil {
		return 0, fmt.Errorf("%w: dialling %s: %v", ErrConnect, number, err)
	}
	if !strings.HasPrefix(r, resConnect) {
		return 0, fmt.Errorf("%w: dialling %s: %s", ErrConnect, number, r)
	}
	return rateOf(r), nil
}

// hangup performs PH-ABORT.request over a Hayes modem (annex A.2.5): a
// guard time of silence, "+++", the guard time again, OK (command mode),
// then ATH, confirmed by NO CARRIER (F-1139: OK is taken too); ERROR means
// the line is still up.
func hangup(l *lines, guard, cmdTimeout time.Duration) error {
	// The guard time is a minimum: waiting exactly that long leaves a
	// modem whose timer runs a little late (or a busy gateway) taking the
	// "+++" as data, and the call stays up. A quarter more, at least
	// 50 ms, is margin.
	time.Sleep(guard + max(guard/4, 50*time.Millisecond))
	if err := l.src.send([]byte("+++")); err != nil {
		return err
	}
	r, err := l.result(time.Now().Add(guard+cmdTimeout), resOK, resNoCarrier)
	if err != nil {
		return fmt.Errorf("escape to command mode: %w", err)
	}
	if r == resNoCarrier {
		return nil // the line was already down
	}
	if err := l.src.send([]byte("ATH\r")); err != nil {
		return err
	}
	r, err = l.result(time.Now().Add(cmdTimeout), resNoCarrier, resOK, resError)
	if err != nil {
		return fmt.Errorf("ATH: %w", err)
	}
	if r == resError {
		return errors.New("ATH: the modem answered ERROR; the connection is still up")
	}
	return nil
}

// Answer is the called side's PH-CONNECT (annex A.2.3) on a line from a
// Hayes modem not in auto-answer mode: wait for RING, send ATA, and take
// CONNECT as PH-CONNECT.indication. It returns the rate CONNECT reports
// and the octets that already followed it (the start of the data).
func Answer(c net.Conn, timeout time.Duration) (int, []byte, error) {
	l := &lines{src: connSource{c}}
	deadline := time.Now().Add(timeout)
	if _, err := l.result(deadline, resRing); err != nil {
		return 0, nil, fmt.Errorf("waiting for RING: %w", err)
	}
	if err := l.src.send([]byte("ATA\r")); err != nil {
		return 0, nil, err
	}
	r, err := l.result(time.Now().Add(timeout), resConnect, resError, resNoCarrier, resBusy)
	if err != nil {
		return 0, nil, fmt.Errorf("answering: %w", err)
	}
	if !strings.HasPrefix(r, resConnect) {
		return 0, nil, fmt.Errorf("%w: answering: %s", ErrConnect, r)
	}
	rest := l.buf
	if len(rest) > 0 && rest[0] == '\n' { // the LF of CONNECT's CR LF
		rest = rest[1:]
	}
	return rateOf(r), rest, nil
}

// identify is the client's IDENTIFY.request and .confirm (6.3.3): the
// request, then the four-octet response, due within 1 500 ms.
func identify(src source, device *uint16, timeout time.Duration) (Identity, []byte, error) {
	if err := src.send(IdentifyRequest(device)); err != nil {
		return Identity{}, nil, err
	}
	var got []byte
	deadline := time.Now().Add(timeout)
	for len(got) < 4 {
		left := time.Until(deadline)
		if left <= 0 {
			return Identity{}, nil, errors.New("no identification response (the server discards a request it does not take)")
		}
		b, err := src.recv(left)
		if err != nil {
			if errors.Is(err, errTimeout) {
				continue
			}
			return Identity{}, nil, err
		}
		got = append(got, b...)
	}
	id, err := ParseIdentity(got[:4])
	return id, got[4:], err
}

// Identify runs the identification service on a connection nothing else
// reads yet (a meter that called us); it also returns octets that came
// after the response.
func Identify(c net.Conn, device *uint16, timeout time.Duration) (Identity, []byte, error) {
	return identify(connSource{c}, device, timeout)
}
