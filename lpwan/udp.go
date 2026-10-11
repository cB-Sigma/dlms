// Package lpwan carries DLMS/COSEM over low-power wide-area networks:
// NB-IoT (and LTE-M) meters that call in over UDP from
// behind carrier NAT and sleep between calls (udp.go, queue.go, wake.go),
// and LoRaWAN meters reached through a network server with SCHC
// compression and fragmentation (RFC 8724, RFC 9011; bridge.go, ns.go,
// regional.go). The network server is reached through the NetworkServer
// interface: MemNS in memory for tests, or an application's MQTT
// integration.
//
// Both present each meter as a net.Conn carrying IEC 62056-4-7 wrapper
// frames, so a client runs its inbound-meter logic (cosem.InboundConn:
// identity proof, pushes, associations told apart by wPort) over them
// unchanged.
package lpwan

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/wrapper"
)

// ErrReplyWindowClosed is returned by a write to an NB-IoT meter after
// its reply window: the carrier NAT binding (or the meter's receive
// window before it sleeps again) is taken to have closed.
var ErrReplyWindowClosed = errors.New("the meter's reply window has closed (it is asleep or its NAT binding expired); the command waits for its next call")

// UDPOptions configure ListenUDP.
type UDPOptions struct {
	// ReplyWindow is how long after a meter's last datagram we may still
	// send to its source address and port (default 30 s). Carrier NAT
	// bindings for UDP commonly last 30 s to a few minutes; the meter's
	// PSM active time may be shorter.
	ReplyWindow time.Duration
	// MaxPeers bounds the meters talking at once (default 10000); the
	// oldest idle peer is dropped for a new one.
	MaxPeers int
	// OnDiscard is told about datagrams that are not whole wrapper frames
	// (IEC 62056-4-7 5.2.1: one WPDU fills its datagram).
	OnDiscard func(from net.Addr, err error)
	// Now is the clock (tests).
	Now func() time.Time
}

// UDPListener accepts one net.Conn per meter source address on a UDP
// socket: the first datagram from an address makes a new conn, which
// Accept returns; later datagrams from it go to that conn, and writes go
// back to that address while its reply window is open. It is a
// net.Listener, so meters that call over UDP are served like those that
// call over TCP.
type UDPListener struct {
	pc  net.PacketConn
	opt UDPOptions

	mu     sync.Mutex
	peers  map[string]*PeerConn
	accept chan *PeerConn
	closed chan struct{}
	once   sync.Once
}

// ListenUDP listens on addr ("0.0.0.0:4059").
func ListenUDP(addr string, opt UDPOptions) (*UDPListener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	return ServeUDP(pc, opt), nil
}

// ServeUDP serves an existing packet socket.
func ServeUDP(pc net.PacketConn, opt UDPOptions) *UDPListener {
	if opt.ReplyWindow <= 0 {
		opt.ReplyWindow = 30 * time.Second
	}
	if opt.MaxPeers <= 0 {
		opt.MaxPeers = 10000
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	l := &UDPListener{pc: pc, opt: opt, peers: map[string]*PeerConn{}, accept: make(chan *PeerConn, 64), closed: make(chan struct{})}
	go l.read()
	return l
}

func (l *UDPListener) read() {
	buf := make([]byte, 65536)
	for {
		n, from, err := l.pc.ReadFrom(buf)
		if err != nil {
			_ = l.Close()
			return
		}
		d := append([]byte(nil), buf[:n]...)
		if _, _, err := wrapper.ParseDatagram(d); err != nil {
			if l.opt.OnDiscard != nil {
				l.opt.OnDiscard(from, err)
			}
			continue
		}
		key := from.String()
		l.mu.Lock()
		p := l.peers[key]
		isNew := p == nil || p.isClosed()
		if isNew {
			if len(l.peers) >= l.opt.MaxPeers {
				l.dropOldest()
			}
			p = &PeerConn{l: l, remote: from, in: make(chan []byte, 32), done: make(chan struct{})}
			l.peers[key] = p
		}
		l.mu.Unlock()
		p.push(d)
		if isNew {
			select {
			case l.accept <- p:
			case <-l.closed:
				return
			}
		}
	}
}

// dropOldest closes the peer heard from longest ago (l.mu held).
func (l *UDPListener) dropOldest() {
	var old *PeerConn
	for _, p := range l.peers {
		if old == nil || p.lastRx().Before(old.lastRx()) {
			old = p
		}
	}
	if old != nil {
		delete(l.peers, old.remote.String())
		go old.Close()
	}
}

// Accept waits for a new meter.
func (l *UDPListener) Accept() (net.Conn, error) {
	select {
	case p := <-l.accept:
		return p, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the listener and every peer.
func (l *UDPListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		_ = l.pc.Close()
		l.mu.Lock()
		ps := l.peers
		l.peers = map[string]*PeerConn{}
		l.mu.Unlock()
		for _, p := range ps {
			_ = p.Close()
		}
	})
	return nil
}

// Addr is the socket's address.
func (l *UDPListener) Addr() net.Addr { return l.pc.LocalAddr() }

func (l *UDPListener) forget(p *PeerConn) {
	l.mu.Lock()
	if l.peers[p.remote.String()] == p {
		delete(l.peers, p.remote.String())
	}
	l.mu.Unlock()
}

// PeerConn is one meter's datagrams as a byte stream of whole wrapper
// frames; each Write goes out as one datagram.
type PeerConn struct {
	l      *UDPListener
	remote net.Addr

	mu       sync.Mutex
	buf      []byte
	last     time.Time
	rdl      time.Time
	in       chan []byte
	done     chan struct{}
	closed   bool
	rxCount  int
	wake     time.Time // first datagram of this call
	onClosed func()
}

func (p *PeerConn) push(d []byte) {
	p.mu.Lock()
	now := p.l.opt.Now()
	if p.rxCount == 0 {
		p.wake = now
	}
	p.last = now
	p.rxCount++
	p.mu.Unlock()
	select {
	case p.in <- d:
	case <-p.done:
	default:
		// The reader is behind: the oldest frame is dropped, as UDP would.
		select {
		case <-p.in:
		default:
		}
		select {
		case p.in <- d:
		default:
		}
	}
}

func (p *PeerConn) lastRx() time.Time { p.mu.Lock(); defer p.mu.Unlock(); return p.last }

func (p *PeerConn) isClosed() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.closed }

// Read returns bytes of the frames received, in order.
func (p *PeerConn) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		if len(p.buf) > 0 {
			n := copy(b, p.buf)
			p.buf = p.buf[n:]
			p.mu.Unlock()
			return n, nil
		}
		dl := p.rdl
		p.mu.Unlock()
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case d := <-p.in:
			p.mu.Lock()
			p.buf = append(p.buf, d...)
			p.mu.Unlock()
		case <-p.done:
			return 0, io.EOF
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write sends b as one datagram to the meter's last source address, if
// its reply window is still open.
func (p *PeerConn) Write(b []byte) (int, error) {
	if p.isClosed() {
		return 0, net.ErrClosed
	}
	if !p.ReplyOpen() {
		return 0, ErrReplyWindowClosed
	}
	return p.l.pc.WriteTo(b, p.remote)
}

// ReplyOpen reports whether the reply window is open.
func (p *PeerConn) ReplyOpen() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.l.opt.Now().Sub(p.last) <= p.l.opt.ReplyWindow
}

// ReplyUntil is when the reply window closes, unless the meter sends again.
func (p *PeerConn) ReplyUntil() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last.Add(p.l.opt.ReplyWindow)
}

// WokeAt is when this call's first datagram arrived.
func (p *PeerConn) WokeAt() time.Time { p.mu.Lock(); defer p.mu.Unlock(); return p.wake }

// Close ends the conn; a later datagram from the address makes a new one.
func (p *PeerConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	f := p.onClosed
	p.mu.Unlock()
	close(p.done)
	p.l.forget(p)
	if f != nil {
		f()
	}
	return nil
}

// LocalAddr is the listener's address.
func (p *PeerConn) LocalAddr() net.Addr { return p.l.pc.LocalAddr() }

// RemoteAddr is the meter's address as the NAT shows it.
func (p *PeerConn) RemoteAddr() net.Addr { return p.remote }

// SetDeadline sets the read deadline (writes do not block).
func (p *PeerConn) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

// SetReadDeadline sets the read deadline.
func (p *PeerConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.rdl = t
	p.mu.Unlock()
	return nil
}

// SetWriteDeadline does nothing: a datagram write does not block.
func (p *PeerConn) SetWriteDeadline(time.Time) error { return nil }
