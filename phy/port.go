package phy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Config sets up a client Port.
type Config struct {
	// Open opens the line: a TCP connection to a serial converter, or to a
	// converter with a Hayes modem behind it.
	Open func() (net.Conn, error)
	// Dial, when set, is the number the modem dials (annex A.2.1); Init
	// are Hayes commands sent first, each answered OK.
	Dial string
	Init []string
	// Guard is the escape guard time (annex A.2.5, default 1 s);
	// CommandTimeout bounds a Hayes command (default 5 s), ConnectTimeout
	// the dialling (default 60 s).
	Guard, CommandTimeout, ConnectTimeout time.Duration
	// Identify runs the identification service after the physical
	// connection is set up (6.3.3), for Device when set (a multidrop
	// physical device). Expect is the answer we take (default COSEM).
	Identify bool
	Device   *uint16
	Expect   *Identity
	// IdentifyTimeout waits for the response (default 2 s: the server has
	// 1 500 ms).
	IdentifyTimeout time.Duration
	// OnAbort is PH-ABORT.indication to the physical connection manager:
	// the line went down without being asked to.
	OnAbort func(error)
}

// Connection is what PH-CONNECT.confirm reported.
type Connection struct {
	Rate     int       // the rate the modem's CONNECT named, 0 when none or no modem
	Identity *Identity // the identification response, when the service was used
}

// Port is the client side physical layer (6.3, Figure 7) as a gosem
// transport: Connect is PH-CONNECT.request (open the line, dial, identify),
// Send is PH-DATA.request, received octets are PH-DATA.indication to the
// data link layer once identification is over (the Destination_process
// parameter of 6.3.3.3), Disconnect is PH-ABORT.request (hang up, close).
type Port struct {
	cfg Config

	mu        sync.Mutex
	conn      net.Conn
	connected bool
	toUpper   bool // Destination_process: the data link layer, else the manager
	dc        gdlms.DataChannel
	mgr       chan []byte
	done      chan struct{}
	last      Connection
	aborting  bool
}

// NewPort builds a client physical layer.
func NewPort(cfg Config) (*Port, error) {
	if cfg.Open == nil {
		return nil, errors.New("no line to open")
	}
	if cfg.Guard <= 0 {
		cfg.Guard = time.Second
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 5 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 60 * time.Second
	}
	if cfg.IdentifyTimeout <= 0 {
		cfg.IdentifyTimeout = 2 * time.Second
	}
	if cfg.Expect == nil {
		e := COSEM
		cfg.Expect = &e
	}
	return &Port{cfg: cfg}, nil
}

// Connection is the last PH-CONNECT.confirm.
func (p *Port) Connection() Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// portSource is the manager's view while Destination_process is not set.
type portSource struct{ p *Port }

func (s portSource) recv(timeout time.Duration) ([]byte, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case b := <-s.p.mgr:
		return b, nil
	case <-s.p.done:
		return nil, errors.New("the line is down")
	case <-t.C:
		return nil, errTimeout
	}
}

func (s portSource) send(b []byte) error { return s.p.Send(b) }

func (p *Port) read(c net.Conn, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			b := append([]byte(nil), buf[:n]...)
			p.mu.Lock()
			up, dc := p.toUpper, p.dc
			p.mu.Unlock()
			if up && dc != nil {
				dc <- b
			} else if !up {
				select {
				case p.mgr <- b:
				default: // the manager is not listening: dropped
				}
			}
		}
		if err != nil {
			p.mu.Lock()
			was := p.connected && p.conn == c
			if was {
				p.connected = false
			}
			asked := p.aborting
			p.mu.Unlock()
			if was && !asked && p.cfg.OnAbort != nil {
				p.cfg.OnAbort(err) // PH-ABORT.indication
			}
			return
		}
	}
}

// Connect is PH-CONNECT.request.
func (p *Port) Connect() error {
	p.mu.Lock()
	if p.connected {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	c, err := p.cfg.Open()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnect, err)
	}
	p.mu.Lock()
	p.conn, p.connected, p.toUpper, p.aborting = c, true, false, false
	p.mgr, p.done = make(chan []byte, 64), make(chan struct{})
	done := p.done
	p.mu.Unlock()
	go p.read(c, done)
	var got Connection
	fail := func(err error) error {
		p.mu.Lock()
		p.aborting, p.connected = true, false
		p.mu.Unlock()
		_ = c.Close()
		<-done
		return err
	}
	if p.cfg.Dial != "" {
		rate, err := dial(&lines{src: portSource{p}}, p.cfg.Dial, p.cfg.Init, p.cfg.CommandTimeout, p.cfg.ConnectTimeout)
		if err != nil {
			return fail(err)
		}
		got.Rate = rate
	}
	var rest []byte
	if p.cfg.Identify {
		id, more, err := identify(portSource{p}, p.cfg.Device, p.cfg.IdentifyTimeout)
		rest = more
		if err != nil {
			return fail(fmt.Errorf("identification: %w", err))
		}
		got.Identity = &id
		if id != *p.cfg.Expect {
			return fail(fmt.Errorf("identification: the server's stack is %v, not %v", id, *p.cfg.Expect))
		}
	}
	p.mu.Lock()
	p.toUpper, p.last = true, got // identification over: octets go to the data link layer
	dc := p.dc
	p.mu.Unlock()
	if len(rest) > 0 && dc != nil {
		dc <- rest
	}
	return nil
}

// Disconnect is PH-ABORT.request: over a modem, escape and hang up
// (annex A.2.5), then close the line. It is confirmed locally.
func (p *Port) Disconnect() error {
	p.mu.Lock()
	c, connected, done := p.conn, p.connected, p.done
	if !connected {
		p.mu.Unlock()
		return nil
	}
	p.toUpper, p.aborting = false, true
	p.mu.Unlock()
	var err error
	if p.cfg.Dial != "" {
		err = hangup(&lines{src: portSource{p}}, p.cfg.Guard, p.cfg.CommandTimeout)
	}
	p.mu.Lock()
	p.connected = false
	p.mu.Unlock()
	_ = c.Close()
	<-done
	return err
}

// Close disconnects and closes the reception channel.
func (p *Port) Close() {
	_ = p.Disconnect()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dc != nil {
		close(p.dc)
		p.dc = nil
	}
}

// IsConnected reports a physical connection.
func (p *Port) IsConnected() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connected
}

// SetAddress does nothing: the physical layer has no addresses (the
// gosem transport interface asks for it).
func (p *Port) SetAddress(int, int) {}

// SetReception sets the data link layer's channel.
func (p *Port) SetReception(dc gdlms.DataChannel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dc = dc
}

// Send is PH-DATA.request for each octet.
func (p *Port) Send(b []byte) error {
	p.mu.Lock()
	c, ok := p.conn, p.connected
	p.mu.Unlock()
	if !ok {
		return errors.New("no physical connection")
	}
	_ = c.SetWriteDeadline(time.Now().Add(p.cfg.CommandTimeout))
	_, err := c.Write(b)
	return err
}

// SetLogger does nothing: the port does not log (the gosem transport
// interface asks for it).
func (p *Port) SetLogger(*log.Logger) {}
