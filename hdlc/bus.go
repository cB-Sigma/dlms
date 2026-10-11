package hdlc

import (
	"errors"
	"log"
	"sync"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Bus is one physical line shared by several servers: a multi-drop
// arrangement behind one converter (IEC 62056-7-6 9.6, IEC 62056-46
// 6.4.2.2), each meter a physical device with its own lower HDLC address.
// It gives every client a Port on the one lower transport, hands them all
// the octets received (each client keeps the frames addressed to it and
// from its server), and runs one exchange at a time: a client holds the
// bus from its command with P until the final frame of the answer, so only
// one secondary has the right to talk (the master/slave rule of 9.6).
type Bus struct {
	lower gdlms.Transport

	ex sync.Mutex // one exchange at a time

	mu    sync.Mutex
	ports map[*busPort]bool // attached; true while counted as connected
	in    gdlms.DataChannel
	refs  int
}

// NewBus shares lower, which it owns.
func NewBus(lower gdlms.Transport) *Bus {
	b := &Bus{lower: lower, ports: map[*busPort]bool{}, in: make(gdlms.DataChannel, 64)}
	lower.SetReception(b.in)
	go b.fanOut()
	return b
}

// Close closes the line.
func (b *Bus) Close() { b.lower.Close() }

// Port is a transport on the bus for one client.
func (b *Bus) Port() gdlms.Transport {
	p := &busPort{b: b, done: make(chan struct{})}
	b.mu.Lock()
	b.ports[p] = false
	b.mu.Unlock()
	return p
}

// Ports is the number of attached ports.
func (b *Bus) Ports() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.ports)
}

func (b *Bus) fanOut() {
	for chunk := range b.in {
		b.mu.Lock()
		var to []*busPort
		for p := range b.ports {
			to = append(to, p)
		}
		b.mu.Unlock()
		for _, p := range to {
			p.deliver(chunk)
		}
	}
}

// busPort is one client's view of the bus.
type busPort struct {
	b    *Bus
	mu   sync.Mutex
	dc   gdlms.DataChannel
	done chan struct{}
	once sync.Once
}

func (p *busPort) deliver(chunk []byte) {
	p.mu.Lock()
	dc := p.dc
	p.mu.Unlock()
	if dc == nil {
		return
	}
	select {
	case dc <- append([]byte(nil), chunk...):
	case <-p.done:
	}
}

func (p *busPort) Connect() error {
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	counted, ok := b.ports[p]
	if !ok {
		return errors.New("the port was closed")
	}
	if !b.lower.IsConnected() {
		if err := b.lower.Connect(); err != nil {
			return err
		}
	}
	if !counted {
		b.ports[p] = true
		b.refs++
	}
	return nil
}

// Disconnect lets go of the line; the last client closes it.
func (p *busPort) Disconnect() error {
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ports[p] {
		b.ports[p] = false
		b.refs--
		if b.refs == 0 {
			return b.lower.Disconnect()
		}
	}
	return nil
}

func (p *busPort) Close() {
	p.once.Do(func() { close(p.done) })
	_ = p.Disconnect()
	p.b.mu.Lock()
	delete(p.b.ports, p)
	p.b.mu.Unlock()
	// The client owns its reception channel and has stopped reading it.
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dc = nil
}

func (p *busPort) IsConnected() bool {
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ports[p] && b.lower.IsConnected()
}

func (p *busPort) SetAddress(int, int) {}

func (p *busPort) SetReception(dc gdlms.DataChannel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dc = dc
}

func (p *busPort) Send(b []byte) error { return p.b.lower.Send(b) }

func (p *busPort) SetLogger(*log.Logger) {}

// hold takes the bus for one exchange; release gives it back.
func (c *Client) hold() func() {
	if c.cfg.Bus == nil {
		return func() {}
	}
	c.cfg.Bus.ex.Lock()
	return c.cfg.Bus.ex.Unlock
}
