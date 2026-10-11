package iec6205621

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"sync"
	"time"

	"github.com/goburrow/serial"
)

// openSerial opens a local serial port (7 data bits, even parity, 1 stop
// bit); tests replace it.
var openSerial = func(dev string, baud int) (io.ReadWriteCloser, error) {
	return serial.Open(&serial.Config{Address: dev, BaudRate: baud, DataBits: 7, StopBits: 1, Parity: "E", Timeout: 100 * time.Millisecond})
}

// openSerialBinary opens the port with 8 data bits, no parity, 1 stop bit:
// the character format after a mode E switch to HDLC.
var openSerialBinary = func(dev string, baud int) (io.ReadWriteCloser, error) {
	return serial.Open(&serial.Config{Address: dev, BaudRate: baud, DataBits: 8, StopBits: 1, Parity: "N", Timeout: 100 * time.Millisecond})
}

// conn is a meter connection: a serial port that can change its baud
// rate, or a TCP connection to a transparent converter. With emulate7E1
// the converter runs 8N1 and we add and check the even parity bit
// ourselves, which is how most serial-to-IP converters in the field are
// set up for optical probes.
type conn struct {
	line     Line
	p        *port
	baud     int
	emulate  bool
	parityOK bool
}

// Line is how a meter's optical probe or serial line is reached: a local
// serial port (Device), or a transparent serial-to-IP converter (TCP, at
// Address) whose rate is its own. With Emulate7E1 the converter runs 8N1
// and the even parity bit is added and checked here.
type Line struct {
	Device     string
	Address    string
	TCP        bool
	Emulate7E1 bool
}

// dial opens the meter's port at baud (300 for a sign-on, 2400 for mode
// D); a converter's rate is its own.
func dial(ctx context.Context, line Line, baud int) (*conn, error) {
	c := &conn{line: line, baud: baud, emulate: line.TCP && line.Emulate7E1}
	var rw io.ReadWriteCloser
	var err error
	if line.TCP {
		var d net.Dialer
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		rw, err = d.DialContext(dctx, "tcp", line.Address)
		cancel()
	} else {
		rw, err = openSerial(line.Device, baud)
	}
	if err != nil {
		return nil, err
	}
	c.p = newPort(rw)
	return c, nil
}

// setBaud changes the local serial port's rate (reopening it); on TCP the
// converter's rate is fixed and nothing changes.
func (c *conn) setBaud(baud int) error {
	if c.baud == baud {
		return nil
	}
	c.baud = baud
	if c.line.TCP {
		return nil
	}
	_ = c.p.Close()
	rw, err := openSerial(c.line.Device, baud)
	if err != nil {
		return fmt.Errorf("reopening %s at %d baud: %w", c.line.Device, baud, err)
	}
	c.p = newPort(rw)
	return nil
}

func (c *conn) Close() { _ = c.p.Close() }

// setBinary switches to the mode E binary phase: 8N1 at baud on a serial
// port (reopened), raw 8-bit bytes through a converter (no parity
// emulation; the converter must run 8N1).
func (c *conn) setBinary(baud int) error {
	c.baud, c.emulate = baud, false
	if c.line.TCP {
		return nil
	}
	_ = c.p.Close()
	rw, err := openSerialBinary(c.line.Device, baud)
	if err != nil {
		return fmt.Errorf("reopening %s at %d baud, 8N1: %w", c.line.Device, baud, err)
	}
	c.p = newPort(rw)
	return nil
}

// binaryPort is the connection handed over after a mode E switch: plain
// reads and writes of 8-bit bytes, no deadlines (the HDLC layer times its
// replies). Closing it closes the connection.
type binaryPort struct{ c *conn }

func (b binaryPort) Read(p []byte) (int, error)  { return b.c.p.readSome(p) }
func (b binaryPort) Write(p []byte) (int, error) { return b.c.p.Write(p) }
func (b binaryPort) Close() error                { b.c.Close(); return nil }

func (c *conn) write(b []byte) error {
	out := make([]byte, len(b))
	for i, x := range b {
		x &= 0x7f
		if c.emulate && bits.OnesCount8(x)%2 == 1 {
			x |= 0x80
		}
		out[i] = x
	}
	_, err := c.p.Write(out)
	return err
}

// ErrParity is returned for a character whose even parity bit is wrong
// (7E1 emulation only).
var ErrParity = errors.New("parity error")

// ReadByte returns the next 7-bit character.
func (c *conn) ReadByte() (byte, error) {
	b, err := c.p.ReadByte()
	if err != nil {
		return 0, err
	}
	if c.emulate && bits.OnesCount8(b)%2 == 1 {
		return b & 0x7f, ErrParity
	}
	return b & 0x7f, nil
}

func (c *conn) setDeadline(d time.Duration) { c.p.SetDeadline(time.Now().Add(d)) }

// port turns a byte stream into ReadByte calls with a deadline. A reader
// goroutine feeds a channel, so serial read timeouts and TCP reads look
// the same.
type port struct {
	rw       io.ReadWriteCloser
	in       chan []byte
	buf      []byte
	deadline time.Time
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
}

var errTimeout = errors.New("no answer within the timeout")

func newPort(rw io.ReadWriteCloser) *port {
	p := &port{rw: rw, in: make(chan []byte, 64), done: make(chan struct{})}
	go p.read()
	return p
}

func (p *port) read() {
	for {
		b := make([]byte, 256)
		n, err := p.rw.Read(b)
		if n > 0 {
			select {
			case p.in <- b[:n]:
			case <-p.done:
				return
			}
		}
		if err != nil {
			if errors.Is(err, serial.ErrTimeout) {
				continue
			}
			p.fail(err)
			return
		}
	}
}

func (p *port) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
}

// Err is why the port stopped.
func (p *port) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close ends the port.
func (p *port) Close() error {
	p.fail(errors.New("closed"))
	return p.rw.Close()
}

func (p *port) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, p.Err()
	default:
	}
	n, err := p.rw.Write(b)
	if err != nil {
		p.fail(err)
	}
	return n, err
}

// SetDeadline bounds the following ReadByte calls; zero waits forever.
func (p *port) SetDeadline(t time.Time) { p.deadline = t }

// ReadByte returns the next byte, errTimeout after the deadline.
func (p *port) ReadByte() (byte, error) {
	for len(p.buf) == 0 {
		var timer <-chan time.Time
		if !p.deadline.IsZero() {
			d := time.Until(p.deadline)
			if d <= 0 {
				select {
				case b := <-p.in:
					p.buf = b
					continue
				default:
					return 0, errTimeout
				}
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timer = t.C
		}
		select {
		case b := <-p.in:
			p.buf = b
		case <-p.done:
			select {
			case b := <-p.in:
				p.buf = b
				continue
			default:
			}
			return 0, p.Err()
		case <-timer:
			return 0, errTimeout
		}
	}
	c := p.buf[0]
	p.buf = p.buf[1:]
	return c, nil
}

// readSome blocks until bytes arrive or the port stops.
func (p *port) readSome(b []byte) (int, error) {
	for len(p.buf) == 0 {
		select {
		case x := <-p.in:
			p.buf = x
		case <-p.done:
			select {
			case x := <-p.in:
				p.buf = x
				continue
			default:
			}
			return 0, p.Err()
		}
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *port) drain() {
	p.buf = nil
	for {
		select {
		case <-p.in:
		default:
			return
		}
	}
}

// SetSerialOpener replaces the function that opens a local serial port at
// 7E1 (goburrow/serial by default; tests use a simulated line) and returns
// a function restoring it.
func SetSerialOpener(f func(dev string, baud int) (io.ReadWriteCloser, error)) func() {
	prev := openSerial
	openSerial = f
	return func() { openSerial = prev }
}

// SetSerialBinaryOpener replaces the 8N1 opener used after a mode E switch.
func SetSerialBinaryOpener(f func(dev string, baud int) (io.ReadWriteCloser, error)) func() {
	prev := openSerialBinary
	openSerialBinary = f
	return func() { openSerialBinary = prev }
}
