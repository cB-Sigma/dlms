package wrapper

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Transport is the client side of the wrapper over TCP or UDP, a gosem
// transport: each Send is one WPDU; each WPDU received from the server's
// wPort to ours is delivered whole. WPDUs of another version or for
// another wPort are discarded (5.3.5, 6.2.5.2).
type Transport struct {
	network, address string
	timeout          time.Duration

	mu        sync.Mutex
	client    uint16
	server    uint16
	conn      net.Conn
	dc        gdlms.DataChannel
	logger    *log.Logger
	done      chan struct{}
	discarded int
}

// New builds a transport to address ("host:port") over "tcp" or "udp".
func New(network, address string, client, server int, timeout time.Duration) (*Transport, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("network %q is not tcp or udp", network)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Transport{network: network, address: address, timeout: timeout, client: uint16(client), server: uint16(server)}, nil
}

// Connect opens the TCP connection (or binds the UDP socket).
func (t *Transport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		return nil
	}
	var c net.Conn
	var err error
	if t.network == "udp" {
		c, err = dialUDP(t.address, t.timeout)
	} else {
		c, err = net.DialTimeout(t.network, t.address, t.timeout)
	}
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	t.conn, t.done = c, make(chan struct{})
	go t.read(c, t.done)
	return nil
}

func (t *Transport) read(c net.Conn, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 65536)
	for {
		var h Header
		var apdu []byte
		var err error
		if t.network == "udp" {
			var n int
			if n, err = c.Read(buf); err == nil {
				h, apdu, err = ParseDatagram(buf[:n])
				if err != nil {
					t.discard()
					continue
				}
				apdu = append([]byte(nil), apdu...)
			}
		} else {
			h, apdu, err = ReadWPDU(c)
			if errors.Is(err, ErrVersion) {
				t.discard()
				continue
			}
		}
		if err != nil {
			t.mu.Lock()
			if t.conn == c {
				_ = c.Close()
				t.conn = nil
			}
			t.mu.Unlock()
			return
		}
		t.mu.Lock()
		ok := h.Dst == t.client && h.Src == t.server
		dc, logger := t.dc, t.logger
		t.mu.Unlock()
		if !ok {
			t.discard()
			continue
		}
		if logger != nil {
			logger.Printf("wrapper RX %d→%d % X", h.Src, h.Dst, apdu)
		}
		if dc != nil {
			dc <- apdu
		}
	}
}

func (t *Transport) discard() {
	t.mu.Lock()
	t.discarded++
	t.mu.Unlock()
}

// Discarded counts WPDUs dropped for their version, length or wPorts.
func (t *Transport) Discarded() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.discarded
}

// Disconnect closes the connection and waits for the reader.
func (t *Transport) Disconnect() error {
	t.mu.Lock()
	c, done := t.conn, t.done
	t.conn = nil
	t.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}

// Close disconnects and closes the reception channel.
func (t *Transport) Close() {
	_ = t.Disconnect()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
		t.dc = nil
	}
}

// IsConnected reports an open connection.
func (t *Transport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn != nil
}

// SetAddress sets our (client) and the server's wPort.
func (t *Transport) SetAddress(client, server int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.client, t.server = uint16(client), uint16(server)
}

// SetReception sets where APDUs go.
func (t *Transport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
	}
	t.dc = dc
}

// SetLogger logs APDUs.
func (t *Transport) SetLogger(l *log.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logger = l
}

// Send sends one APDU in one WPDU. Over TCP the whole WPDU is written
// however many writes it takes (6.3.5.4); over UDP it must fit one
// datagram (5.2.1).
func (t *Transport) Send(apdu []byte) error {
	t.mu.Lock()
	c, client, server := t.conn, t.client, t.server
	t.mu.Unlock()
	if c == nil {
		return errors.New("not connected")
	}
	if t.network == "udp" && len(apdu) > MaxUDPAPDU {
		return fmt.Errorf("an APDU of %d octets does not fit one UDP datagram", len(apdu))
	}
	b, err := Encode(client, server, apdu)
	if err != nil {
		return err
	}
	_ = c.SetWriteDeadline(time.Now().Add(t.timeout))
	if _, err := writeAll(c, b); err != nil {
		_ = t.Disconnect()
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// SendBroadcast sends an unconfirmed APDU; over IP it is an ordinary WPDU
// (IEC 62056-9-7 9.1, the invoke-id's service class bit says it).
func (t *Transport) SendBroadcast(apdu []byte) error { return t.Send(apdu) }

// writeAll repeats writes until everything is sent (A.4, Figure A.5).
func writeAll(w io.Writer, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := w.Write(b[n:])
		n += k
		if err != nil {
			return n, err
		}
		if k == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}
