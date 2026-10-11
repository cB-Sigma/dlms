package cosem

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
	"gitlab.com/circutor-library/gosem/pkg/dlmsclient"

	"github.com/cB-Sigma/dlms/hdlc"
)

// A DLMS client over a byte stream someone else opened: an IEC 62056-21
// client hands its optical probe or serial port over after a mode E option
// select (IEC 62056-21 annex E), and the rest of the session is HDLC
// (IEC 62056-46) carrying the same COSEM services this package uses over
// TCP.

// PortOptions configures NewPortClient.
type PortOptions struct {
	// ClientAddress is our HDLC client address (default 16, the public
	// client, without authentication; 32 with low-level security).
	ClientAddress int
	// ServerAddress is the logical device, the HDLC upper address
	// (default 1).
	ServerAddress int
	// HDLCAddress is the physical device, the HDLC lower address; it is
	// sent only with a 2 or 4 byte server address.
	HDLCAddress int
	// HDLCAddressSize is the server address length: 1 (default: logical
	// device only, usual on a point-to-point optical port), 2 or 4.
	HDLCAddressSize int
	// Authentication is "none" (default) or "low"; high-level security
	// over a handed-over port is not supported.
	Authentication string
	Password       string
	// Timeout bounds each reply (default 10s).
	Timeout time.Duration
}

// PortClient is a DLMS client (logical name referencing) over HDLC on an
// already open port: gosem's client over our HDLC layer (package hdlc).
type PortClient struct {
	gdlms.Client
	tr   *hdlc.Client
	once sync.Once
}

// NewPortClient builds a DLMS client over HDLC on rwc, which it owns from
// now on. Nothing is sent until Connect (the SNRM) and Associate (the
// AARQ). Close ends the association and the link and closes rwc.
func NewPortClient(rwc io.ReadWriteCloser, o PortOptions) (*PortClient, error) {
	if rwc == nil {
		return nil, errors.New("no port to hand over")
	}
	set, err := o.settings()
	if err != nil {
		return nil, err
	}
	tr, err := hdlc.NewClient(newRWCTransport(rwc), hdlc.Config{
		Client:          o.ClientAddress,
		Server:          hdlc.ServerAddress(o.ServerAddress, o.HDLCAddress, o.HDLCAddressSize),
		ResponseTimeout: max(o.Timeout/3, time.Second),
	})
	if err != nil {
		return nil, err
	}
	return &PortClient{Client: dlmsclient.New(set, tr, o.Timeout, 0), tr: tr}, nil
}

// Check reports options NewPortClient would refuse.
func (o PortOptions) Check() error {
	_, err := o.settings()
	return err
}

// settings fills in the defaults and returns the association settings.
func (o *PortOptions) settings() (gdlms.Settings, error) {
	set, err := gdlms.NewSettingsWithoutAuthentication()
	if err != nil {
		return set, err
	}
	switch strings.ToLower(o.Authentication) {
	case "", "none":
		if o.ClientAddress == 0 {
			o.ClientAddress = 16
		}
	case "low":
		if o.Password == "" {
			return set, errors.New("low-level security needs a password")
		}
		set.Authentication, set.Password = gdlms.AuthenticationLow, []byte(o.Password)
		if o.ClientAddress == 0 {
			o.ClientAddress = 32
		}
	default:
		return set, fmt.Errorf("authentication %q over a handed-over port is not none or low", o.Authentication)
	}
	if o.ServerAddress == 0 {
		o.ServerAddress = 1
	}
	if o.HDLCAddressSize == 0 {
		o.HDLCAddressSize = 1
	}
	if o.HDLCAddressSize != 1 && o.HDLCAddressSize != 2 && o.HDLCAddressSize != 4 {
		return set, errors.New("hdlcAddressSize must be 1, 2 or 4")
	}
	if err := CheckHDLCAddresses(o.ClientAddress, o.ServerAddress, o.HDLCAddress, o.HDLCAddressSize); err != nil {
		return set, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	return set, nil
}

// Close releases the association, disconnects the HDLC link and closes
// the port. It is safe to call more than once.
func (p *PortClient) Close() {
	p.once.Do(func() {
		if p.Client.IsAssociated() {
			_ = p.Client.CloseAssociation()
		}
		_ = p.Client.Disconnect()
		p.tr.Close()
	})
}

// ReadScaled reads one attribute. A register's value (class 3 or 4
// attribute 2, class 5 attributes 2 and 3) is scaled by its scaler_unit
// (attribute 3, or 4 for class 5), whose unit is returned;
// clock values and 12-byte date-times are returned as RFC 3339 text.
func ReadScaled(c gdlms.Client, o Object, loc *time.Location) (v any, unit string, err error) {
	attr := o.Attribute
	if attr == 0 {
		attr = 2
	}
	if loc == nil {
		loc = time.UTC
	}
	var d axdr.DlmsData
	if err := c.GetRequest(gdlms.CreateAttributeDescriptor(o.Class, o.OBIS, attr), &d); err != nil {
		return nil, "", err
	}
	v = Value(d, loc, o.Class == ClassClock || o.OBIS == "0.0.0.1.2.255")
	unit = o.Unit
	if ScaledValue(o.Class, attr) {
		if f, ok := Number(d); ok {
			var su axdr.DlmsData
			if err := c.GetRequest(gdlms.CreateAttributeDescriptor(o.Class, o.OBIS, ScalerAttr(o.Class)), &su); err == nil {
				if s, u, err := ScalerUnit(su); err == nil {
					f = Scaled(f, s)
					if unit == "" {
						unit = UnitSymbol(u)
					}
				}
			} else if !Rejected(err) {
				return nil, "", err
			}
			v = f
		}
	}
	return v, unit, nil
}

// Rejected reports a DLMS error that concerns one object (the meter
// refused the request) rather than the link.
func Rejected(err error) bool { return err != nil && !CommError(err) }

// rwcTransport is a gosem Transport over an io.ReadWriteCloser: bytes
// written go to the port, bytes read are delivered to the layer above
// (HDLC, which finds its frames in them).
type rwcTransport struct {
	rwc       io.ReadWriteCloser
	mu        sync.Mutex
	dc        gdlms.DataChannel
	connected bool
	closed    bool
	started   bool
	done      chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

func newRWCTransport(rwc io.ReadWriteCloser) *rwcTransport {
	return &rwcTransport{rwc: rwc, done: make(chan struct{}), stop: make(chan struct{})}
}

func (t *rwcTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("the port is closed")
	}
	t.connected = true
	if !t.started {
		t.started = true
		go t.read()
	}
	return nil
}

func (t *rwcTransport) read() {
	defer close(t.done)
	buf := make([]byte, 2048)
	for {
		n, err := t.rwc.Read(buf)
		if n > 0 {
			t.mu.Lock()
			dc, ok := t.dc, t.connected
			t.mu.Unlock()
			if ok && dc != nil {
				select {
				case dc <- append([]byte(nil), buf[:n]...):
				case <-t.stop:
					return
				}
			}
		}
		if err != nil {
			t.mu.Lock()
			t.connected = false
			t.mu.Unlock()
			return
		}
	}
}

// shut closes the port once and waits for the reader to stop.
func (t *rwcTransport) shut() {
	t.closeOnce.Do(func() { close(t.stop); _ = t.rwc.Close() })
	t.mu.Lock()
	started := t.started
	t.connected, t.closed = false, true
	t.mu.Unlock()
	if started {
		<-t.done
	}
}

// Disconnect ends the session: the port was handed over for it alone.
func (t *rwcTransport) Disconnect() error {
	t.shut()
	return nil
}

func (t *rwcTransport) Close() {
	t.shut()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
		t.dc = nil
	}
}

func (t *rwcTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

func (t *rwcTransport) SetAddress(int, int) {}

func (t *rwcTransport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dc != nil {
		close(t.dc)
	}
	t.dc = dc
}

func (t *rwcTransport) Send(b []byte) error {
	t.mu.Lock()
	ok := t.connected
	t.mu.Unlock()
	if !ok {
		return errors.New("not connected")
	}
	if _, err := t.rwc.Write(b); err != nil {
		t.shut()
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

func (t *rwcTransport) SetLogger(*log.Logger) {}
