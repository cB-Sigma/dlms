package cosem

// A client of one meter: associations opened as needed with the frame
// counter handled (never repeated across associations or restarts), and
// the meter's system title remembered from its first association.

import (
	"errors"
	"sync/atomic"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/iotsec"
)

var errNoAssociation = errors.New("no association")

// FrameCounterObject is the object holding a client's invocation counter
// in the meter (class 1, value attribute), read through an
// unauthenticated association of ClientAddress (default 16, the public
// client) before a protected association, so the client's counter never
// falls behind the meter's.
type FrameCounterObject struct {
	OBIS          string
	ClientAddress int
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// Transport opens the supporting layers for a client address.
	Transport func(client int) (gdlms.Transport, error)
	// ClientAddress is the association's client address.
	ClientAddress int
	// HLS is the authentication and APDU protection (SecurityConfig.Build);
	// it is read at every Connect, so a key change takes effect on the
	// next association. Password is the low-level password.
	HLS      *HLS
	Password []byte
	// InvocationCounter, when set, is read before each protected
	// association.
	InvocationCounter *FrameCounterObject
	// Reserve, when set, raises an association's first invocation counter
	// to a stored reservation and keeps the reservation ahead of it
	// (ICReservation.Reserve); first is true until the client has used a
	// counter.
	Reserve func(ic uint32, first bool) (uint32, error)
	// ExpectSystemTitle is the meter's system title; when nil, the one it
	// names in its first association is expected afterwards.
	ExpectSystemTitle []byte
	// Timeout bounds each request (default 10s).
	Timeout time.Duration
	// Writes, Alive, Check, Policy and Use are as in AssociationConfig.
	Writes *atomic.Int64
	Alive  func() bool
	Check  func(gdlms.Client) error
	Policy iotsec.CryptoPolicy
	Use    string
	// Name and Where name the meter and its address in errors.
	Name, Where string
}

// Client is a client of one meter. It is not safe for concurrent use:
// callers run one exchange at a time.
type Client struct {
	Config ClientConfig

	a         *Association
	st        *SecureTransport // the last association's, even when it failed
	lastIC    uint32
	learnedST []byte
}

// NewClient returns a client; nothing is sent until Connect.
func NewClient(cfg ClientConfig) *Client { return &Client{Config: cfg} }

// Association is the open association, nil when there is none.
func (c *Client) Association() *Association { return c.a }

// Secure is the secure transport of the last association attempted.
func (c *Client) Secure() *SecureTransport { return c.st }

// LastIC is the next invocation counter the client would use;
// SetLastIC sets it (a counter kept elsewhere).
func (c *Client) LastIC() uint32 { return c.lastIC }

// SetLastIC sets the next invocation counter the client would use.
func (c *Client) SetLastIC(ic uint32) { c.lastIC = ic }

// MeterSystemTitle is the system title the meter named in its first
// association (nil before).
func (c *Client) MeterSystemTitle() []byte { return c.learnedST }

// Connect opens an association with the current settings, closing any
// open one first.
func (c *Client) Connect() error {
	c.Close()
	cfg := &c.Config
	h := cfg.HLS
	if h == nil {
		h = &HLS{}
	}
	var ic uint32 = 1
	var err error
	if h.Security.Policy != 0 || h.Mechanism == MechGMAC {
		if ic, err = c.nextInvocationCounter(); err != nil {
			return err
		}
	}
	tr, err := cfg.Transport(cfg.ClientAddress)
	if err != nil {
		return err
	}
	expect := cfg.ExpectSystemTitle
	if expect == nil {
		expect = c.learnedST
	}
	a, err := Associate(AssociationConfig{Transport: tr, Mechanism: h.Mechanism, Password: cfg.Password, HLS: h,
		FirstIC: ic, ExpectSystemTitle: expect, Timeout: cfg.Timeout, Writes: cfg.Writes, Alive: cfg.Alive,
		Check: cfg.Check, Policy: cfg.Policy, Use: cfg.Use, Name: cfg.Name, Where: cfg.Where})
	if a != nil {
		c.st = a.Secure
	}
	if err != nil {
		if a != nil {
			c.lastIC = a.Secure.UsedIC()
		}
		return err
	}
	c.a = a
	if c.learnedST == nil && a.Secure.meterST != nil {
		c.learnedST = append([]byte(nil), a.Secure.meterST...)
	}
	return nil
}

// nextInvocationCounter is the frame counter to start a protected
// association with: past both the meter's stored counter for this client
// (when configured) and the last one this client used, so the meter never
// sees a counter twice.
func (c *Client) nextInvocationCounter() (uint32, error) {
	next := c.lastIC
	cfg := &c.Config
	reserve := func(ic uint32) (uint32, error) {
		if cfg.Reserve == nil {
			return ic, nil
		}
		return cfg.Reserve(ic, c.lastIC == 0)
	}
	fc := cfg.InvocationCounter
	if fc == nil {
		if next == 0 {
			next = 1
		}
		return reserve(next)
	}
	client := fc.ClientAddress
	if client == 0 {
		client = 16
	}
	tr, err := cfg.Transport(client)
	if err != nil {
		return 0, err
	}
	to := cfg.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	v, err := ReadInvocationCounter(tr, fc.OBIS, to, cfg.Name, cfg.Where)
	if err != nil {
		return 0, err
	}
	if v+1 > next {
		next = v + 1
	}
	return reserve(next)
}

// Close releases the open association, if any, and disconnects.
func (c *Client) Close() {
	if c.a == nil {
		return
	}
	// Every protected request advanced the counter; never reuse one.
	if ic := c.a.Secure.UsedIC(); ic > c.lastIC {
		c.lastIC = ic
	}
	if c.a.Client.IsAssociated() {
		_ = c.a.Client.CloseAssociation()
	}
	_ = c.a.Client.Disconnect()
	c.a = nil
}

// Get reads one attribute on the open association.
func (c *Client) Get(class uint16, obis string, attr int8) (axdr.DlmsData, error) {
	var d axdr.DlmsData
	if c.a == nil {
		return d, errNoAssociation
	}
	err := c.a.Client.GetRequest(gdlms.CreateAttributeDescriptor(class, obis, attr), &d)
	return d, err
}
