package cosem

// The shared connection to a data concentrator unit (DCU) through which
// meters are read: the DLMS/COSEM gateway protocol of IEC 62056-5-3:2023
// annex C (package gateway), where each request carries a prefix naming
// the meter's network and physical address, or a DCU that serves each
// meter as one of its own logical devices (told apart by the wPorts
// alone). The connection is opened once and shared by every meter's
// association; answers find their association by their prefix and wPorts,
// and APDUs a meter sends unasked (pushes) go to a callback. Protection
// stays end to end between the client and the meter (C.5): the DCU passes
// protected APDUs on untouched.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/gateway"
	"github.com/cB-Sigma/dlms/wrapper"
)

// Kinds of GatewayEvent.
const (
	// GatewayMalformed is a gateway prefix from the DCU that does not
	// parse.
	GatewayMalformed = "malformed"
	// GatewayAddressMismatch is an answer from another address than the
	// meter's, given to the only request waiting.
	GatewayAddressMismatch = "address-mismatch"
	// GatewayUnknownAddress is an answer or push from an address no meter
	// is known at.
	GatewayUnknownAddress = "unknown-address"
)

// GatewayEvent is something about a DCU's traffic an application may
// want to show: Kind is one of the Gateway constants, Message says what
// happened, and Detail is the address concerned.
type GatewayEvent struct {
	Kind, Message, Detail string
}

// GatewayConfig configures a Gateway.
type GatewayConfig struct {
	// ID names the DCU in messages.
	ID string
	// Address is the host:port of the DCU's wrapper port, Network tcp
	// (default) or udp.
	Address, Network string
	// MaxOutstanding is how many requests may wait for an answer at once,
	// across its meters (default 1: the meters in turn).
	MaxOutstanding int
	// Timeout bounds connecting (default 10s). After a failed attempt,
	// requests within it fail at once with the same error.
	Timeout time.Duration
	// Dial opens the connection (default net.DialTimeout).
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)
	// Logger receives debug and warning lines (nil: none).
	Logger *slog.Logger
	// Event receives GatewayEvents (nil: logged only).
	Event func(GatewayEvent)
	// Push receives an APDU a meter sent unasked through the DCU: pre is
	// its gateway prefix (nil when it came without one), src its source
	// wPort (the logical device in logical-device mode).
	Push func(pre *gateway.Prefix, src uint16, apdu []byte)
	// HasMeter reports whether a gateway-mode meter is configured at a
	// network and physical address (pushes some DCUs forward as answers
	// are recognised by it).
	HasMeter func(network byte, address []byte) bool
	// Health is called after every connection attempt, outside the
	// gateway's locks, with the state before it (-1 unknown, 0
	// unreachable, 1 connected) and the attempt's error.
	Health func(was int8, err error)
}

// Gateway is the shared connection to a DCU and its health.
type Gateway struct {
	cfg GatewayConfig

	mu       sync.Mutex
	conn     net.Conn
	done     chan struct{}
	subs     map[gwKey]*gwTransport
	dials    int
	lastDial time.Time
	wmu      sync.Mutex // one WPDU written at a time
	turn     chan struct{}

	hmu     sync.Mutex
	online  int8 // -1 unknown, 0 unreachable, 1 connected
	lastErr string
	since   time.Time
	lastOK  time.Time
}

// NewGateway prepares a gateway; nothing is dialled until a transport
// connects or Ensure is called.
func NewGateway(cfg GatewayConfig) *Gateway {
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.MaxOutstanding <= 0 {
		cfg.MaxOutstanding = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Dial == nil {
		cfg.Dial = net.DialTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Gateway{cfg: cfg, subs: map[gwKey]*gwTransport{}, turn: make(chan struct{}, cfg.MaxOutstanding), online: -1}
}

func (l *Gateway) event(kind, msg, detail string) {
	if l.cfg.Event != nil {
		l.cfg.Event(GatewayEvent{Kind: kind, Message: msg, Detail: detail})
		return
	}
	l.cfg.Logger.Warn(msg, "dcu", l.cfg.ID, "detail", detail)
}

// GatewayDest names one association's peer behind a DCU: a logical
// device of the DCU (Logical, at Server) or a meter at a network and
// physical address (gateway mode).
type GatewayDest struct {
	Logical        bool
	Network        byte
	Address        []byte
	Client, Server uint16
	// Name names the meter in messages.
	Name string
	// Timeout bounds each request (default 20s).
	Timeout time.Duration
}

// gwKey names the exchanges of one meter association on a DCU's
// connection.
type gwKey struct {
	logical        bool
	network        byte
	address        string // physical device address octets
	client, server uint16
}

// GatewayDown is the error of a DCU that cannot be reached.
type GatewayDown struct{ msg string }

// Error says which DCU is down and why.
func (e *GatewayDown) Error() string { return e.msg }

// IsGatewayDown reports an error of an unreachable DCU (retrying the
// meter does not help).
func IsGatewayDown(err error) bool {
	var e *GatewayDown
	return errors.As(err, &e)
}

// Unreachable reports whether the DCU's last connection attempt failed.
func (l *Gateway) Unreachable() bool {
	l.hmu.Lock()
	defer l.hmu.Unlock()
	return l.online == 0
}

// Ensure opens the DCU's connection if it is not open. After a failed
// attempt, requests within the DCU's timeout fail at once with the same
// error instead of each dialling again.
func (l *Gateway) Ensure() error {
	l.mu.Lock()
	if l.conn != nil {
		l.mu.Unlock()
		return nil
	}
	l.hmu.Lock()
	down, lastErr := l.online == 0, l.lastErr
	l.hmu.Unlock()
	if down && time.Since(l.lastDial) < l.cfg.Timeout {
		l.mu.Unlock()
		return &GatewayDown{fmt.Sprintf("DCU %s at %s is unreachable: %s", l.cfg.ID, l.cfg.Address, lastErr)}
	}
	l.lastDial = time.Now()
	c, err := l.cfg.Dial(l.cfg.Network, l.cfg.Address, l.cfg.Timeout)
	if err == nil {
		l.dials++
		l.conn, l.done = c, make(chan struct{})
		go l.read(c, l.done)
	}
	l.mu.Unlock()
	// Health is reported outside the lock: an application marking meters
	// offline may take its time.
	l.health(err)
	if err != nil {
		return &GatewayDown{fmt.Sprintf("DCU %s at %s is unreachable: %v", l.cfg.ID, l.cfg.Address, err)}
	}
	return nil
}

// Dials counts the connections opened to the DCU.
func (l *Gateway) Dials() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dials
}

// health records a connection attempt and reports it.
func (l *Gateway) health(err error) {
	l.hmu.Lock()
	was := l.online
	if err == nil {
		l.online, l.lastErr, l.lastOK = 1, "", time.Now()
	} else {
		l.online, l.lastErr = 0, err.Error()
	}
	now := int8(0)
	if err == nil {
		now = 1
	}
	if now != was {
		l.since = time.Now()
	}
	l.hmu.Unlock()
	if l.cfg.Health != nil {
		l.cfg.Health(was, err)
	}
}

// Online reports the DCU's last known state: -1 unknown, 0 unreachable,
// 1 connected.
func (l *Gateway) Online() int8 {
	l.hmu.Lock()
	defer l.hmu.Unlock()
	return l.online
}

// GatewayHealth is a DCU's connection state.
type GatewayHealth struct {
	Online  int8 // -1 unknown, 0 unreachable, 1 connected
	LastErr string
	Since   time.Time // when Online last changed
	LastOK  time.Time // the last successful connection
}

// Health reports the DCU's connection state.
func (l *Gateway) Health() GatewayHealth {
	l.hmu.Lock()
	defer l.hmu.Unlock()
	return GatewayHealth{Online: l.online, LastErr: l.lastErr, Since: l.since, LastOK: l.lastOK}
}

// Run keeps trying an unreachable DCU every interval until ctx ends, so
// its meters' state is known without waiting for their reads.
func (l *Gateway) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		_ = l.Ensure()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close closes the DCU's connection and waits for its reader.
func (l *Gateway) Close() {
	l.mu.Lock()
	c, done := l.conn, l.done
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	if done != nil {
		<-done
	}
}

// read takes WPDUs from the DCU until the connection closes.
func (l *Gateway) read(c net.Conn, done chan struct{}) {
	defer close(done)
	buf := make([]byte, 65536)
	for {
		var h wrapper.Header
		var apdu []byte
		var err error
		if l.cfg.Network == "udp" {
			var n int
			if n, err = c.Read(buf); err == nil {
				if h, apdu, err = wrapper.ParseDatagram(buf[:n]); err != nil {
					continue
				}
				apdu = append([]byte(nil), apdu...)
			}
		} else {
			h, apdu, err = wrapper.ReadWPDU(c)
			if errors.Is(err, wrapper.ErrVersion) {
				continue
			}
		}
		if err != nil {
			l.mu.Lock()
			if l.conn == c {
				_ = c.Close()
				l.conn = nil
			}
			l.mu.Unlock()
			return
		}
		l.dispatch(h, apdu)
	}
}

// PushTag reports APDUs a meter sends unasked: data-notification,
// general-glo-ciphering (a protected push) and general block transfer.
func PushTag(apdu []byte) bool {
	return len(apdu) > 0 && (apdu[0] == 0x0F || apdu[0] == TagGeneralGlo || apdu[0] == TagGBT)
}

func (l *Gateway) hasMeter(network byte, addr []byte) bool {
	return l.cfg.HasMeter != nil && l.cfg.HasMeter(network, addr)
}

func (l *Gateway) pushed(pre *gateway.Prefix, src uint16, apdu []byte) {
	if l.cfg.Push != nil {
		l.cfg.Push(pre, src, apdu)
	}
}

// dispatch hands one APDU from the DCU to the association it answers, or
// to push reception.
func (l *Gateway) dispatch(h wrapper.Header, apdu []byte) {
	pre, inner, prefixed, err := gateway.Parse(apdu)
	if err != nil {
		l.event(GatewayMalformed, fmt.Sprintf("DCU %s sent a gateway prefix that does not parse; dropped", l.cfg.ID), err.Error())
		return
	}
	if !prefixed {
		k := gwKey{logical: true, client: h.Dst, server: h.Src}
		if t := l.sub(k); t != nil && !(PushTag(apdu) && apdu[0] == 0x0F) {
			t.receive(apdu)
			return
		}
		if PushTag(apdu) {
			// Annex C.4.3: a meter that does not know the gateway pushes
			// plain APDUs; or a logical device of the DCU pushed.
			l.pushed(nil, h.Src, apdu)
			return
		}
		l.cfg.Logger.Warn("DCU: an APDU for no open association dropped", "dcu", l.cfg.ID, "from", h.Src, "to", h.Dst)
		return
	}
	// E6 from the DCU is a meter's own request: a push (C.2, C.4.2).
	if pre.Header == gateway.Request {
		l.pushed(&pre, h.Src, inner)
		return
	}
	k := gwKey{network: pre.Network, address: string(pre.Address), client: h.Dst, server: h.Src}
	if t := l.sub(k); t != nil {
		t.receive(inner)
		return
	}
	if PushTag(inner) && l.hasMeter(pre.Network, pre.Address) && inner[0] != TagGBT {
		// Some DCUs forward pushes under E7.
		l.pushed(&pre, h.Src, inner)
		return
	}
	if t := l.onlyPending(); t != nil {
		// The one exchange waiting takes it: its DCU answered from another
		// address than the meter's (C.3 does not say which it uses).
		l.event(GatewayAddressMismatch,
			fmt.Sprintf("DCU %s answered for meter %s from %s; taken as that meter's answer since it was the only request waiting", l.cfg.ID, t.name, pre),
			pre.String())
		t.receive(inner)
		return
	}
	if PushTag(inner) {
		l.pushed(&pre, h.Src, inner)
		return
	}
	l.event(GatewayUnknownAddress, fmt.Sprintf("DCU %s sent an answer from %s, where no meter is waiting; dropped", l.cfg.ID, pre), pre.String())
}

func (l *Gateway) sub(k gwKey) *gwTransport {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.subs[k]
}

// onlyPending is the only gateway-mode exchange waiting for an answer, when
// exactly one is.
func (l *Gateway) onlyPending() *gwTransport {
	l.mu.Lock()
	defer l.mu.Unlock()
	var one *gwTransport
	for _, t := range l.subs {
		if t.key.logical || !t.isPending() {
			continue
		}
		if one != nil {
			return nil
		}
		one = t
	}
	return one
}

// write sends one WPDU on the DCU's connection.
func (l *Gateway) write(b []byte, timeout time.Duration) error {
	l.mu.Lock()
	c := l.conn
	l.mu.Unlock()
	if c == nil {
		return fmt.Errorf("DCU %s: not connected", l.cfg.ID)
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := writeAllConn(c, b); err != nil {
		l.mu.Lock()
		if l.conn == c {
			_ = c.Close()
			l.conn = nil
		}
		l.mu.Unlock()
		return fmt.Errorf("DCU %s: write failed: %w", l.cfg.ID, err)
	}
	return nil
}

func writeAllConn(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Write(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// gwTransport is one association's transport through a DCU (a gosem
// transport): Send prefixes the APDU for the meter (gateway mode) and
// waits for the DCU's turn; the DCU's reader delivers the answers.
// Disconnect ends the association's use of the connection without closing
// it.
type gwTransport struct {
	l       *Gateway
	name    string
	key     gwKey
	prefix  *gateway.Prefix
	timeout time.Duration

	mu        sync.Mutex
	connected bool
	dc        gdlms.DataChannel
	logger    *log.Logger
	pending   bool
	gen       uint64
}

// Transport is a gosem transport to a meter behind the DCU. Connect
// joins the DCU's connection (dialling it when needed); Disconnect ends
// the association's use of it without closing it.
func (l *Gateway) Transport(d GatewayDest) gdlms.Transport {
	to := d.Timeout
	if to <= 0 {
		to = 20 * time.Second
	}
	t := &gwTransport{l: l, name: d.Name, timeout: to, key: gwKey{client: d.Client, server: d.Server}}
	if d.Logical {
		t.key.logical = true
	} else {
		t.key.network, t.key.address = d.Network, string(d.Address)
		t.prefix = &gateway.Prefix{Header: gateway.Request, Network: d.Network, Address: d.Address}
	}
	return t
}

func (t *gwTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connected {
		return nil
	}
	if err := t.l.Ensure(); err != nil {
		return err
	}
	t.l.mu.Lock()
	defer t.l.mu.Unlock()
	if o := t.l.subs[t.key]; o != nil && o != t {
		return fmt.Errorf("client %d already has an association with meter %s through DCU %s", t.key.client, t.name, t.l.cfg.ID)
	}
	t.l.subs[t.key] = t
	t.connected = true
	return nil
}

func (t *gwTransport) Disconnect() error {
	t.release(0, true)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected {
		return nil
	}
	t.l.mu.Lock()
	if t.l.subs[t.key] == t {
		delete(t.l.subs, t.key)
	}
	t.l.mu.Unlock()
	t.connected = false
	return nil
}

func (t *gwTransport) Close() {
	_ = t.Disconnect()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
		t.dc = nil
	}
}

func (t *gwTransport) IsConnected() bool {
	t.mu.Lock()
	ok := t.connected
	t.mu.Unlock()
	if !ok {
		return false
	}
	t.l.mu.Lock()
	defer t.l.mu.Unlock()
	return t.l.conn != nil
}

func (t *gwTransport) SetAddress(client, server int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.key.client, t.key.server = uint16(client), uint16(server)
}

func (t *gwTransport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
	}
	t.dc = dc
}

func (t *gwTransport) SetLogger(l *log.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logger = l
}

func (t *gwTransport) isPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending
}

// release gives the DCU's turn back after an answer (any) or a time-out
// (only the request it was taken for).
func (t *gwTransport) release(gen uint64, whatever bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.pending || (!whatever && gen != t.gen) {
		return
	}
	t.pending = false
	<-t.l.turn
}

// Send sends one APDU to the meter, waiting for the DCU's turn.
func (t *gwTransport) Send(apdu []byte) error { return t.send(apdu, true) }

// SendBroadcast sends an unconfirmed APDU: nothing is awaited.
func (t *gwTransport) SendBroadcast(apdu []byte) error { return t.send(apdu, false) }

func (t *gwTransport) send(apdu []byte, confirmed bool) error {
	t.mu.Lock()
	ok, key := t.connected, t.key
	t.mu.Unlock()
	if !ok {
		return errors.New("not connected")
	}
	// Waiting for the DCU's turn does not count against the meter's
	// time-out, which starts when its request is sent; a meter that does
	// not answer holds the turn for its own time-out only.
	wait := max(time.Minute, 4*t.timeout)
	select {
	case t.l.turn <- struct{}{}:
	case <-time.After(wait):
		return fmt.Errorf("DCU %s stayed busy with other meters for %s", t.l.cfg.ID, wait)
	}
	t.mu.Lock()
	t.pending = true
	t.gen++
	gen := t.gen
	t.mu.Unlock()
	payload := apdu
	if t.prefix != nil {
		var err error
		if payload, err = gateway.Encode(*t.prefix, apdu); err != nil {
			t.release(gen, false)
			return err
		}
	}
	b, err := wrapper.Encode(key.client, key.server, payload)
	if err == nil && t.l.cfg.Network == "udp" && len(payload) > wrapper.MaxUDPAPDU {
		err = fmt.Errorf("an APDU of %d octets does not fit one UDP datagram", len(payload))
	}
	if err == nil {
		err = t.l.write(b, t.timeout)
	}
	if err != nil || !confirmed {
		t.release(gen, false)
		return err
	}
	time.AfterFunc(t.timeout, func() { t.release(gen, false) })
	return nil
}

// receive passes an answer on (never blocking the DCU's reader longer
// than the meter's time-out).
func (t *gwTransport) receive(apdu []byte) {
	t.release(0, true)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.logger != nil {
		t.logger.Printf("DCU %s RX meter %s % X", t.l.cfg.ID, t.name, apdu)
	}
	if t.dc == nil {
		return
	}
	select {
	case t.dc <- append([]byte(nil), apdu...):
	case <-time.After(t.timeout):
	}
}
