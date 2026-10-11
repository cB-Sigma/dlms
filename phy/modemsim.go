package phy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ModemSim plays an intelligent Hayes modem and the line behind it, for
// tests and the meter simulator: AT commands are answered OK, ATD with
// Number connects to Remote (CONNECT and the rate), other numbers get
// NO CARRIER (or BUSY); in data mode octets pass to and from Remote until
// the escape sequence (guard time, "+++", guard time) returns to command
// mode, where ATH ends the call (NO CARRIER). Call rings a client instead
// (RING, ATA, CONNECT).
type ModemSim struct {
	Number string
	Rate   int           // reported in CONNECT (default 9600)
	Busy   bool          // the number is busy
	Guard  time.Duration // escape guard time (default 1 s)
	// Remote serves the far end of a call on its connection and returns
	// when that connection ends.
	Remote func(net.Conn)

	mu      sync.Mutex
	calls   int
	hangups int
	cmds    []string
}

// Calls is how many calls were connected, Hangups how many ATH ended one.
func (m *ModemSim) Calls() (calls, hangups int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls, m.hangups
}

// Commands are the command lines received.
func (m *ModemSim) Commands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.cmds...)
}

func (m *ModemSim) guard() time.Duration {
	if m.Guard <= 0 {
		return time.Second
	}
	return m.Guard
}

func (m *ModemSim) connect() string {
	r := m.Rate
	if r == 0 {
		r = 9600
	}
	return fmt.Sprintf("\r\nCONNECT %d\r\n", r)
}

// lockedWriter serialises the remote's writes with the modem's.
type lockedWriter struct {
	net.Conn
	mu *sync.Mutex
	w  net.Conn
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// Serve plays the modem on the DTE's connection c until it closes.
func (m *ModemSim) Serve(c net.Conn) error {
	var wmu sync.Mutex
	say := func(s string) error {
		wmu.Lock()
		defer wmu.Unlock()
		_, err := c.Write([]byte(s))
		return err
	}
	l := &lines{src: connSource{c}}
	var line net.Conn // our end of the call, nil when none
	for {
		cmd, err := l.next(time.Now().Add(time.Hour))
		if err != nil {
			if line != nil {
				_ = line.Close()
			}
			return err
		}
		u := strings.ToUpper(cmd)
		m.mu.Lock()
		m.cmds = append(m.cmds, u)
		m.mu.Unlock()
		switch {
		case strings.HasPrefix(u, "ATD"):
			n := strings.TrimLeft(u[3:], "TP")
			if n != m.Number {
				_ = say("\r\nNO CARRIER\r\n")
				continue
			}
			if m.Busy {
				_ = say("\r\nBUSY\r\n")
				continue
			}
			line = m.startCall(c, &wmu)
			_ = say(m.connect())
			if err := m.dataMode(c, line, l); err != nil {
				_ = line.Close()
				return err
			}
			_ = say("\r\nOK\r\n")
		case u == "ATH" || u == "ATH0":
			if line != nil {
				_ = line.Close()
				line = nil
				m.mu.Lock()
				m.hangups++
				m.mu.Unlock()
			}
			_ = say("\r\nNO CARRIER\r\n")
		case strings.HasPrefix(u, "AT"):
			_ = say("\r\nOK\r\n")
		default:
			_ = say("\r\nERROR\r\n")
		}
	}
}

func (m *ModemSim) startCall(c net.Conn, wmu *sync.Mutex) net.Conn {
	ours, theirs := net.Pipe()
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	go func() {
		if m.Remote != nil {
			m.Remote(lockedWriter{Conn: theirs, mu: wmu, w: c})
		}
		_ = theirs.Close()
	}()
	// The remote's octets reach c through lockedWriter; ours carries the
	// DTE's octets to it.
	return ours
}

// dataMode passes octets from the DTE to the call until the escape
// sequence; buffered octets in l are passed first.
func (m *ModemSim) dataMode(c net.Conn, line net.Conn, l *lines) error {
	g := m.guard()
	if len(l.buf) > 0 {
		_, _ = line.Write(l.buf)
		l.buf = nil
	}
	buf := make([]byte, 2048)
	// The guard time is measured from the last octet received, as a
	// modem's S12 timer does: not from when this loop next got to run.
	last := time.Now().Add(-g) // silence for a guard time before
	plus := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(g))
		n, err := c.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if plus == 3 && time.Since(last) >= g {
					_ = c.SetReadDeadline(time.Time{})
					return nil // escape: command mode
				}
				continue
			}
			return err
		}
		now := time.Now()
		data := buf[:n]
		idle := plus > 0 || now.Sub(last) >= g // silence before the first '+'
		last = now
		if idle && plus+n <= 3 && strings.Trim(string(data), "+") == "" {
			plus += n
			continue
		}
		if plus > 0 {
			_, _ = line.Write([]byte(strings.Repeat("+", plus)))
			plus = 0
		}
		if _, err := line.Write(data); err != nil {
			return nil // the far end hung up
		}
	}
}

// Call rings the client on c (a called client, annex A.2.3): RING until
// ATA, then CONNECT, and the call is passed to Remote until c closes.
func (m *ModemSim) Call(c net.Conn) error {
	var wmu sync.Mutex
	l := &lines{src: connSource{c}}
	for {
		wmu.Lock()
		_, err := c.Write([]byte("\r\nRING\r\n"))
		wmu.Unlock()
		if err != nil {
			return err
		}
		cmd, err := l.next(time.Now().Add(2 * time.Second))
		if errors.Is(err, errTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.ToUpper(cmd) == "ATA" {
			break
		}
	}
	line := m.startCall(c, &wmu)
	defer line.Close()
	wmu.Lock()
	_, err := c.Write([]byte(m.connect()))
	wmu.Unlock()
	if err != nil {
		return err
	}
	return m.dataMode(c, line, l)
}
