package cosem

// DLMS over a local serial port: an RS-485 or RS-232 line, or an optical
// head (IEC 62056-21) on the gateway itself, instead of TCP to a
// converter. An address serial:///dev/ttyUSB0 (or serial://COM3) names the
// port, and HDLC (IEC 62056-46, the IEC 62056-7-6 profile) runs on it.
// SerialSettings gives the line: baud (default 9600), data bits, parity
// (N, E or O) and stop bits, and with Optical the IEC 62056-21 mode E
// opening (sign-on at 300 baud 7E1, then HDLC at the meter's rate, 8N1)
// with SignOnAddress as the device address of the sign-on. Meters on one
// port share it as a multi-drop line (hdlc.Bus); a push line takes HDLC
// pushes from meters on a port (ServeHDLCPushes).

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/goburrow/serial"
)

// SerialSettings are the line settings of a meter on a local serial port.
type SerialSettings struct {
	Baud          int    `json:"baud,omitempty"`
	DataBits      int    `json:"dataBits,omitempty"`
	Parity        string `json:"parity,omitempty"`
	StopBits      int    `json:"stopBits,omitempty"`
	Optical       bool   `json:"optical,omitempty"`
	SignOnAddress string `json:"signOnAddress,omitempty"`
}

// SerialPrefix starts an address naming a local serial port.
const SerialPrefix = "serial://"

// SerialDevice returns the port an address names (serial:///dev/ttyUSB0,
// serial://COM3), and whether it names one.
func SerialDevice(address string) (string, bool) {
	rest, ok := strings.CutPrefix(address, SerialPrefix)
	if !ok {
		return "", false
	}
	return rest, rest != ""
}

// Defaults fills in the defaults (9600 baud, 8N1) and checks the
// settings.
func (s *SerialSettings) Defaults() error {
	if s.Baud == 0 {
		s.Baud = 9600
	}
	if _, ok := baudChars[s.Baud]; !ok && s.Baud != 115200 && s.Baud != 57600 && s.Baud != 38400 {
		return fmt.Errorf("serialLine.baud %d is not 300 to 115200", s.Baud)
	}
	if s.DataBits == 0 {
		s.DataBits = 8
	}
	if s.DataBits != 7 && s.DataBits != 8 {
		return fmt.Errorf("serialLine.dataBits %d is not 7 or 8", s.DataBits)
	}
	s.Parity = strings.ToUpper(s.Parity)
	if s.Parity == "" {
		s.Parity = "N"
	}
	if s.Parity != "N" && s.Parity != "E" && s.Parity != "O" {
		return fmt.Errorf("serialLine.parity %q is not N, E or O", s.Parity)
	}
	if s.StopBits == 0 {
		s.StopBits = 1
	}
	if s.StopBits != 1 && s.StopBits != 2 {
		return fmt.Errorf("serialLine.stopBits %d is not 1 or 2", s.StopBits)
	}
	if strings.ContainsAny(s.SignOnAddress, "/!?\r\n") {
		return fmt.Errorf("serialLine.signOnAddress %q holds a character the sign-on cannot carry", s.SignOnAddress)
	}
	return nil
}

// SerialConfig is one opening of a port.
type SerialConfig struct {
	Device   string
	Baud     int
	DataBits int
	Parity   string
	StopBits int
}

// openSerialPort opens a local serial port (goburrow/serial, pure Go);
// tests replace it with a simulated line.
var openSerialPort = func(c SerialConfig) (io.ReadWriteCloser, error) {
	return serial.Open(&serial.Config{Address: c.Device, BaudRate: c.Baud, DataBits: c.DataBits, Parity: c.Parity,
		StopBits: c.StopBits, Timeout: 100 * time.Millisecond})
}

// SetSerialOpener replaces the function that opens local serial ports
// (goburrow/serial by default): for tests with a simulated line, or a
// platform with its own serial driver. It returns a function restoring
// the previous one.
func SetSerialOpener(f func(SerialConfig) (io.ReadWriteCloser, error)) (restore func()) {
	old := openSerialPort
	openSerialPort = f
	return func() { openSerialPort = old }
}

// Mode C/E baud rate characters (IEC 62056-21 6.3.14 item 13).
var baudChars = map[int]byte{300: '0', 600: '1', 1200: '2', 2400: '3', 4800: '4', 9600: '5', 19200: '6'}

func baudOf(z byte) int {
	for b, c := range baudChars {
		if c == z {
			return b
		}
	}
	return 0
}

// OpenSerialLine opens the line of a meter on device: with optical, the
// IEC 62056-21 mode E sign-on and switch to HDLC first.
func OpenSerialLine(device string, s SerialSettings, timeout time.Duration) (net.Conn, error) {
	if !s.Optical {
		rw, err := openSerialPort(SerialConfig{Device: device, Baud: s.Baud, DataBits: s.DataBits, Parity: s.Parity, StopBits: s.StopBits})
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", device, err)
		}
		return newSerialConn(rw, device), nil
	}
	return modeE(device, s.SignOnAddress, timeout)
}

// modeE runs the IEC 62056-21 mode E opening on an optical head: sign-on
// at 300 baud 7E1, the identification must offer HDLC (escape \2), the
// option select for the binary protocol at the meter's rate, then the
// port runs 8N1 at that rate and the meter's switch confirm is read
// (its 7E1 characters seen as 8N1 octets carry the parity bit in bit 7;
// a confirm without it is taken too).
func modeE(device, address string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 1500 * time.Millisecond // the character wait of IEC 62056-21
	}
	rw, err := openSerialPort(SerialConfig{Device: device, Baud: 300, DataBits: 7, Parity: "E", StopBits: 1})
	if err != nil {
		return nil, fmt.Errorf("opening %s at 300 baud: %w", device, err)
	}
	c := newSerialConn(rw, device)
	fail := func(err error) (net.Conn, error) { _ = c.Close(); return nil, err }
	if _, err := c.Write([]byte("/?" + address + "!\r\n")); err != nil {
		return fail(err)
	}
	line, err := readSerialLine(c, timeout)
	if err == nil && strings.HasPrefix(line, "/?") { // a half-duplex probe's echo
		line, err = readSerialLine(c, timeout)
	}
	if err != nil {
		return fail(fmt.Errorf("optical sign-on on %s: no identification: %w", device, err))
	}
	if len(line) < 5 || line[0] != '/' {
		return fail(fmt.Errorf("optical sign-on on %s: %q is not an identification", device, line))
	}
	z := line[4]
	baud := baudOf(z)
	if baud == 0 || !strings.Contains(line[5:], `\2`) {
		return fail(fmt.Errorf("optical sign-on on %s: the meter (%q) does not offer DLMS/HDLC (mode E)", device, line))
	}
	if _, err := c.Write([]byte{0x06, '2', z, '2', '\r', '\n'}); err != nil {
		return fail(err)
	}
	time.Sleep(300 * time.Millisecond) // the option select leaves before the rate changes
	_ = c.Close()
	rw, err = openSerialPort(SerialConfig{Device: device, Baud: baud, DataBits: 8, Parity: "N", StopBits: 1})
	if err != nil {
		return nil, fmt.Errorf("reopening %s at %d baud 8N1: %w", device, baud, err)
	}
	c = newSerialConn(rw, device)
	want := []byte{0x06, '2', z, '2', '\r', '\n'}
	got := make([]byte, 0, len(want))
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	b := make([]byte, 1)
	for len(got) < len(want) {
		if _, err := c.Read(b); err != nil {
			return fail(fmt.Errorf("mode E on %s: no switch confirm (got % X): %w", device, got, err))
		}
		if b[0]&0x7F != want[len(got)] {
			return fail(fmt.Errorf("mode E on %s: the meter answered % X, not the switch confirm", device, append(got, b[0])))
		}
		got = append(got, b[0])
	}
	_ = c.SetReadDeadline(time.Time{})
	return c, nil
}

// readSerialLine reads characters up to CR LF (7-bit), within timeout per
// character.
func readSerialLine(c net.Conn, timeout time.Duration) (string, error) {
	var out []byte
	b := make([]byte, 1)
	for len(out) < 128 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		if _, err := c.Read(b); err != nil {
			return string(out), err
		}
		out = append(out, b[0]&0x7F)
		if n := len(out); n >= 2 && out[n-2] == '\r' && out[n-1] == '\n' {
			return string(out[:n-2]), nil
		}
	}
	return string(out), errors.New("the line is too long")
}

// serialConn is a serial port as a net.Conn: a reader goroutine feeds a
// channel, so read deadlines work as on TCP (the HDLC layer and the push
// listener time their reads).
type serialConn struct {
	rw   io.ReadWriteCloser
	dev  string
	in   chan []byte
	buf  []byte
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
	err      error
}

var errSerialTimeout = &serialTimeout{}

type serialTimeout struct{}

func (*serialTimeout) Error() string   { return "serial read timed out" }
func (*serialTimeout) Timeout() bool   { return true }
func (*serialTimeout) Temporary() bool { return true }

func newSerialConn(rw io.ReadWriteCloser, dev string) *serialConn {
	c := &serialConn{rw: rw, dev: dev, in: make(chan []byte, 64), done: make(chan struct{})}
	go c.read()
	return c
}

func (c *serialConn) read() {
	for {
		b := make([]byte, 512)
		n, err := c.rw.Read(b)
		if n > 0 {
			select {
			case c.in <- b[:n]:
			case <-c.done:
				return
			}
		}
		if err != nil {
			if errors.Is(err, serial.ErrTimeout) {
				continue
			}
			c.mu.Lock()
			if c.err == nil {
				c.err = err
			}
			c.mu.Unlock()
			c.once.Do(func() { close(c.done) })
			return
		}
	}
}

func (c *serialConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		c.mu.Lock()
		dl := c.deadline
		c.mu.Unlock()
		var timer <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, errSerialTimeout
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timer = t.C
		}
		select {
		case b := <-c.in:
			c.buf = b
		case <-c.done:
			select {
			case b := <-c.in:
				c.buf = b
			default:
				c.mu.Lock()
				err := c.err
				c.mu.Unlock()
				if err == nil {
					err = io.EOF
				}
				return 0, err
			}
		case <-timer:
			return 0, errSerialTimeout
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *serialConn) Write(p []byte) (int, error) { return c.rw.Write(p) }

func (c *serialConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.rw.Close()
}

func (c *serialConn) LocalAddr() net.Addr  { return serialAddr(c.dev) }
func (c *serialConn) RemoteAddr() net.Addr { return serialAddr(c.dev) }

func (c *serialConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *serialConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline is not enforced: a serial write does not block on the
// far end.
func (c *serialConn) SetWriteDeadline(time.Time) error { return nil }

type serialAddr string

func (a serialAddr) Network() string { return "serial" }
func (a serialAddr) String() string  { return SerialPrefix + string(a) }
