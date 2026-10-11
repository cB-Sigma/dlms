package lpwan

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/schc"
)

// BridgeSettings are a bridge's LoRaWAN settings. The DLMS UA's
// LoRaWAN communication profile is not available to us, so every choice
// it would fix (FPorts, SCHC rules, what header is compressed, the
// fragmentation modes and tile size) is a setting here; the defaults
// follow RFC 9011 and are reported as unverified (ProfileWarning).
type BridgeSettings struct {
	// Region names the regional parameters (default IN865): the largest
	// payload per data rate and the duty cycle (regional.go).
	Region string `json:"region,omitempty"`
	// Class is the meters' LoRaWAN class: A (default), B or C.
	Class    string   `json:"class,omitempty"`
	PingSlot Duration `json:"pingSlot,omitempty"` // class B ping slot period (default 32 s)
	// FPorts of the SCHC rules (RFC 9011 5.2: 20, 21 and 22 by default).
	FPortUp            int `json:"fPortUp,omitempty"`
	FPortDown          int `json:"fPortDown,omitempty"`
	FPortNoCompression int `json:"fPortNoCompression,omitempty"`
	// Header is what the SCHC Packet carries: "wrapper" (default: the IEC
	// 62056-4-7 wrapper frame, its header compressed to a few bits),
	// "none" (the bare APDU: the wrapper is dropped on the air and made up
	// again here) or "ipv6/udp/wrapper" (the wrapper in UDP over IPv6,
	// compressed as RFC 8724 clause 10 describes).
	Header string `json:"header,omitempty"`
	// IPv6 addresses and ports for header ipv6/udp/wrapper.
	IPv6 *IPv6Settings `json:"ipv6,omitempty"`
	// Rules replaces the built-in SCHC rules (package schc's JSON). The
	// fragmentation rules on fPortUp and fPortDown and the no-compression
	// rule are added when missing.
	Rules json.RawMessage `json:"rules,omitempty"`
	// DownlinkFragmentation is ack-always (default, RFC 9011 unicast) or
	// no-ack.
	DownlinkFragmentation string `json:"downlinkFragmentation,omitempty"`
	// TileBytes is the uplink ACK-on-Error tile size (default 10, RFC 9011
	// 5.6.2).
	TileBytes int `json:"tileBytes,omitempty"`
	// AckEveryWindow: acknowledge every uplink window (default true, RFC
	// 9011's advice for battery meters).
	AckEveryWindow *bool `json:"ackEveryWindow,omitempty"`
	// InactivityTimer overrides the uplink reassembly inactivity timer
	// (default 12 h, RFC 9011 5.6.2).
	InactivityTimer Duration `json:"inactivityTimer,omitempty"`
	// RetransmissionTimer overrides the downlink retransmission timer
	// (default by class, RFC 9011 5.6.3.5: class A 4 h, B three ping
	// slots, C 30 s).
	RetransmissionTimer Duration `json:"retransmissionTimer,omitempty"`
	// MaxPayload overrides the downlink payload limit in bytes (default:
	// from the region and data rate); PayloadReserve keeps bytes free for
	// MAC commands the network server adds (FOpts).
	MaxPayload     int `json:"maxPayload,omitempty"`
	PayloadReserve int `json:"payloadReserve,omitempty"`
	// DownlinkDataRate fixes the data rate assumed for downlinks (default:
	// the lower of RX1 at the last uplink's rate and RX2).
	DownlinkDataRate *int `json:"downlinkDataRate,omitempty"`
	// DutyCycle paces our own downlinks per meter (0 to 1; default the
	// region's: none in IN865, 1% in EU868). The network server still
	// enforces the gateways' limits.
	DutyCycle *float64 `json:"dutyCycle,omitempty"`
	// Confirmed sends downlinks as LoRaWAN confirmed frames (SCHC does not
	// need them, RFC 9011 4.3; default false).
	Confirmed bool `json:"confirmed,omitempty"`
	// RequestTimeout is each DLMS request's time-out over LoRaWAN
	// (default 10 min for class A, whose downlinks wait for an uplink;
	// 2 min for B and C).
	RequestTimeout Duration `json:"requestTimeout,omitempty"`
}

// IPv6Settings are the addresses a header ipv6/udp/wrapper packet uses.
type IPv6Settings struct {
	DevPrefix string `json:"devPrefix,omitempty"` // default fe80::/64
	AppPrefix string `json:"appPrefix,omitempty"` // default fe80::/64
	AppIID    string `json:"appIid,omitempty"`    // default ::1
	Port      int    `json:"port,omitempty"`      // UDP port both ends (default 4059, IEC 62056-9-7)
	HopLimit  int    `json:"hopLimit,omitempty"`  // default 255
}

// MeterLoRaWAN is a meter's LoRaWAN identity.
type MeterLoRaWAN struct {
	DevEUI string `json:"devEui"`
	// AppSKey (hex, secret) lets the Dev IPv6 IID be computed as RFC 9011
	// 5.3 says; DevIID (hex, 8 bytes) gives it directly. Only for header
	// ipv6/udp/wrapper.
	AppSKey string `json:"appSKey,omitempty"`
	DevIID  string `json:"devIid,omitempty"`
	Class   string `json:"class,omitempty"` // overrides the class of the bridge (lorawan.class)
}

// Check checks a meter's LoRaWAN identity.
func (m *MeterLoRaWAN) Check() error {
	eui := strings.ReplaceAll(m.DevEUI, "-", "")
	if e, err := hex.DecodeString(eui); err != nil || len(e) != 8 {
		return fmt.Errorf("devEui %q is not 8 bytes of hex", m.DevEUI)
	}
	if m.DevIID != "" {
		if b, err := hex.DecodeString(m.DevIID); err != nil || len(b) != 8 {
			return errors.New("devIid is not 8 bytes of hex")
		}
	}
	if m.AppSKey != "" && !strings.HasPrefix(m.AppSKey, "env:") && !strings.HasPrefix(m.AppSKey, "file:") {
		if b, err := hex.DecodeString(m.AppSKey); err != nil || len(b) != 16 {
			return errors.New("appSKey is not 16 bytes of hex")
		}
	}
	switch strings.ToUpper(m.Class) {
	case "", schc.ClassA, schc.ClassB, schc.ClassC:
	default:
		return fmt.Errorf("class %q is not A, B or C", m.Class)
	}
	return nil
}

// Check fills in defaults and checks the settings.
func (s *BridgeSettings) Check() error {
	if _, err := LookupRegion(s.Region); err != nil {
		return fmt.Errorf("lorawan.region: %w", err)
	}
	if s.Region == "" {
		s.Region = "IN865"
	}
	s.Class = strings.ToUpper(s.Class)
	switch s.Class {
	case "":
		s.Class = schc.ClassA
	case schc.ClassA, schc.ClassB, schc.ClassC:
	default:
		return fmt.Errorf("lorawan.class %q is not A, B or C", s.Class)
	}
	if s.FPortUp == 0 {
		s.FPortUp = schc.FPortUp
	}
	if s.FPortDown == 0 {
		s.FPortDown = schc.FPortDown
	}
	if s.FPortNoCompression == 0 {
		s.FPortNoCompression = schc.FPortNoCompression
	}
	for _, p := range []int{s.FPortUp, s.FPortDown, s.FPortNoCompression} {
		if p < 1 || p > 223 {
			return fmt.Errorf("lorawan: FPort %d is outside 1–223", p)
		}
	}
	if s.FPortUp == s.FPortDown || s.FPortUp == s.FPortNoCompression || s.FPortDown == s.FPortNoCompression {
		return errors.New("lorawan: fPortUp, fPortDown and fPortNoCompression must differ (RFC 9011 5.2)")
	}
	if s.Header == "" {
		s.Header = "wrapper"
	}
	st, err := schc.ParseStack(s.Header)
	if err != nil {
		return fmt.Errorf("lorawan.header: %w", err)
	}
	if len(st) > 0 && st[len(st)-1] != "wrapper" {
		return errors.New("lorawan.header: the packet ends in the wrapper (wrapper, ipv6/udp/wrapper) or is the bare APDU (none)")
	}
	switch s.DownlinkFragmentation {
	case "":
		s.DownlinkFragmentation = schc.AckAlways
	case schc.AckAlways, schc.NoAck:
	default:
		return fmt.Errorf("lorawan.downlinkFragmentation %q is not ack-always or no-ack", s.DownlinkFragmentation)
	}
	if s.TileBytes == 0 {
		s.TileBytes = 10
	}
	if s.TileBytes < 1 || s.TileBytes > 240 {
		return errors.New("lorawan.tileBytes is 1 to 240")
	}
	if s.AckEveryWindow == nil {
		t := true
		s.AckEveryWindow = &t
	}
	if s.MaxPayload < 0 || s.MaxPayload > 242 || s.PayloadReserve < 0 || s.PayloadReserve > 15 {
		return errors.New("lorawan.maxPayload is 0 to 242 and payloadReserve 0 to 15 bytes")
	}
	if s.DutyCycle != nil && (*s.DutyCycle < 0 || *s.DutyCycle > 1) {
		return errors.New("lorawan.dutyCycle is 0 to 1")
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = Duration(10 * time.Minute)
		if s.Class != schc.ClassA {
			s.RequestTimeout = Duration(2 * time.Minute)
		}
	}
	if _, err := s.RuleSet(); err != nil {
		return fmt.Errorf("lorawan.rules: %w", err)
	}
	return nil
}

// ProfileWarning names the settings that stand in for the DLMS UA LoRaWAN
// profile, which we could not read: they must match the meters'.
func (s *BridgeSettings) ProfileWarning() (msg, detail string) {
	rules := "built-in"
	if len(s.Rules) > 0 {
		rules = "from lorawan.rules"
	}
	return "DLMS over LoRaWAN runs on settings that stand in for the DLMS UA LoRaWAN profile, which is not available to us: check them against the meters' documentation. Compliance with that profile is not claimed.",
		fmt.Sprintf("fPortUp=%d fPortDown=%d fPortNoCompression=%d header=%s rules=%s downlinkFragmentation=%s tileBytes=%d ackEveryWindow=%t",
			s.FPortUp, s.FPortDown, s.FPortNoCompression, s.Header, rules, s.DownlinkFragmentation, s.TileBytes, *s.AckEveryWindow)
}

// RuleSet is the SCHC context: lorawan.rules or the built-in one, with the
// fragmentation and no-compression rules added where missing.
func (s *BridgeSettings) RuleSet() (*schc.RuleSet, error) {
	var rs schc.RuleSet
	if len(s.Rules) > 0 {
		if err := json.Unmarshal(s.Rules, &rs); err != nil {
			return nil, err
		}
	} else {
		rs = builtinRules(s.Header)
	}
	has := func(id int) bool {
		for _, r := range rs.Rules {
			if int(r.ID) == id && (r.IDLength == 0 || r.IDLength == 8) {
				return true
			}
		}
		return false
	}
	if !has(s.FPortUp) {
		rs.Rules = append(rs.Rules, schc.LoRaWANUplinkRule(uint8(s.FPortUp), s.TileBytes, s.AckEveryWindow == nil || *s.AckEveryWindow))
		if s.InactivityTimer > 0 {
			f := rs.Rules[len(rs.Rules)-1].Fragmentation
			f.Inactivity = schc.Duration(s.InactivityTimer)
			f.Retransmission = schc.Duration(s.InactivityTimer)
		}
	}
	if !has(s.FPortDown) {
		if s.DownlinkFragmentation == schc.NoAck {
			rs.Rules = append(rs.Rules, schc.LoRaWANMulticastRule(uint8(s.FPortDown)))
		} else {
			rs.Rules = append(rs.Rules, schc.LoRaWANDownlinkRule(uint8(s.FPortDown), s.Class, s.PingSlot.D()))
			if s.RetransmissionTimer > 0 {
				rs.Rules[len(rs.Rules)-1].Fragmentation.Retransmission = schc.Duration(s.RetransmissionTimer)
			}
		}
	}
	if !has(s.FPortNoCompression) {
		rs.Rules = append(rs.Rules, schc.Rule{ID: uint32(s.FPortNoCompression), IDLength: 8, Kind: schc.KindNoCompression})
	}
	for _, r := range rs.Rules {
		if r.IDLength != 0 && r.IDLength != 8 {
			return nil, fmt.Errorf("rule %d: on LoRaWAN a RuleID is 8 bits, the FPort (RFC 9011 5.2)", r.ID)
		}
		if r.ID < 1 || r.ID > 223 {
			return nil, fmt.Errorf("rule %d is not an FPort (1–223)", r.ID)
		}
	}
	if err := rs.Compile(); err != nil {
		return nil, err
	}
	for _, id := range []int{s.FPortUp, s.FPortDown} {
		if r := rs.ByID(uint32(id)); r == nil || r.Kind != schc.KindFragmentation {
			return nil, fmt.Errorf("rule %d must be a fragmentation rule", id)
		}
	}
	return &rs, nil
}

// builtinRules are our default compression rules: rule 1 for the common
// case (the meter's wPort 1, a client wPort from the IS 15959 and
// management SAPs), rule 2 for any wPorts.
func builtinRules(header string) schc.RuleSet {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	fd := func(fid string, fl int, tv, mo, cda string) schc.FieldDescriptor {
		f := schc.FieldDescriptor{FID: fid, FL: fl, MO: mo, CDA: cda}
		if tv != "" {
			f.TV = raw(tv)
		}
		return f
	}
	wrapper1 := []schc.FieldDescriptor{
		fd(schc.FWrapperVersion, 16, "1", "equal", "not-sent"),
		fd(schc.FWrapperDevWPort, 16, "1", "equal", "not-sent"),
		fd(schc.FWrapperAppWPort, 16, "[16,32,48,64,80,96,102,1]", "match-mapping", "mapping-sent"),
		fd(schc.FWrapperLength, 16, "", "ignore", "compute"),
	}
	wrapper2 := []schc.FieldDescriptor{
		fd(schc.FWrapperVersion, 16, "1", "equal", "not-sent"),
		fd(schc.FWrapperDevWPort, 16, "", "ignore", "value-sent"),
		fd(schc.FWrapperAppWPort, 16, "", "ignore", "value-sent"),
		fd(schc.FWrapperLength, 16, "", "ignore", "compute"),
	}
	st, _ := schc.ParseStack(header)
	switch {
	case len(st) == 0:
		return schc.RuleSet{Rules: []schc.Rule{{ID: 1, Name: "apdu"}}}
	case len(st) == 1:
		return schc.RuleSet{Rules: []schc.Rule{{ID: 1, Name: "wrapper", Fields: wrapper1}, {ID: 2, Name: "wrapper-any-wport", Fields: wrapper2}}}
	}
	ip := []schc.FieldDescriptor{
		fd(schc.FIPv6Version, 4, "6", "equal", "not-sent"),
		fd(schc.FIPv6TrafficClass, 8, "0", "equal", "not-sent"),
		fd(schc.FIPv6FlowLabel, 20, "0", "equal", "not-sent"),
		fd(schc.FIPv6PayloadLength, 16, "", "ignore", "compute"),
		fd(schc.FIPv6NextHeader, 8, "17", "equal", "not-sent"),
		fd(schc.FIPv6HopLimit, 8, "255", "ignore", "not-sent"),
		fd(schc.FIPv6DevPrefix, 64, `"fe80::/64"`, "equal", "not-sent"),
		fd(schc.FIPv6DevIID, 64, "", "ignore", "deviid"),
		fd(schc.FIPv6AppPrefix, 64, `"fe80::/64"`, "equal", "not-sent"),
		fd(schc.FIPv6AppIID, 64, `"::1"`, "equal", "not-sent"),
		fd(schc.FUDPDevPort, 16, "4059", "equal", "not-sent"),
		fd(schc.FUDPAppPort, 16, "4059", "equal", "not-sent"),
		fd(schc.FUDPLength, 16, "", "ignore", "compute"),
		fd(schc.FUDPChecksum, 16, "", "ignore", "compute"),
	}
	return schc.RuleSet{Rules: []schc.Rule{
		{ID: 1, Name: "ipv6-udp-wrapper", Fields: append(append([]schc.FieldDescriptor{}, ip...), wrapper1...)},
		{ID: 2, Name: "ipv6-udp-wrapper-any-wport", Fields: append(append([]schc.FieldDescriptor{}, ip...), wrapper2...)},
	}}
}

// Warning is something odd about a device, for an application's warnings.
type Warning struct {
	Kind                          WarningKind
	Subject, Setting, Msg, Detail string
}

// WarningKind tells warnings apart; an application names them.
type WarningKind int

// Warning kinds.
const (
	WarnSCHC           WarningKind = iota // a SCHC transfer failed
	WarnUnknownDevice                     // an uplink from a DevEUI no meter has
	WarnDownlinkFailed                    // the network server did not take a downlink
	WarnBacklog                           // packets arrived faster than read
)

// LinkInfo is what the console shows of a meter's LoRaWAN link.
type LinkInfo struct {
	DevEUI       string    `json:"devEui"`
	LastUplink   time.Time `json:"lastUplink,omitempty"`
	FCnt         *int64    `json:"fCnt,omitempty"`
	DR           *int      `json:"dr,omitempty"`
	RSSI         *float64  `json:"rssi,omitempty"`
	SNR          *float64  `json:"snr,omitempty"`
	Frequency    int64     `json:"frequency,omitempty"`
	Uplinks      int       `json:"uplinks"`
	Downlinks    int       `json:"downlinks"`
	Waiting      int       `json:"waitingFrames"` // downlink frames waiting for a receive window
	MaxPayload   int       `json:"maxPayload"`    // bytes now allowed per downlink
	Reassembling bool      `json:"reassembling"`
	Fragmenting  bool      `json:"fragmenting"`
	LastError    string    `json:"lastError,omitempty"`
}

// Bridge runs SCHC between the network server and the meters, one Device
// (and DeviceConn) per DevEUI.
type Bridge struct {
	s      BridgeSettings
	region Region
	rules  *schc.RuleSet
	stack  schc.Stack
	ns     NetworkServer
	log    *slog.Logger
	now    func() time.Time
	// OnWarning reports something odd about a device (an application
	// passes it on to its warnings).
	OnWarning func(Warning)
	// OnUplink, when set, is told of every uplink from a known device.
	OnUplink func(devEUI string)

	mu   sync.Mutex
	devs map[string]*Device
}

// NewBridge builds a bridge; Check must have run on s.
func NewBridge(s BridgeSettings, ns NetworkServer, log *slog.Logger, now func() time.Time) (*Bridge, error) {
	rs, err := s.RuleSet()
	if err != nil {
		return nil, err
	}
	st, _ := schc.ParseStack(s.Header)
	reg, _ := LookupRegion(s.Region)
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Bridge{s: s, region: reg, rules: rs, stack: st, ns: ns, log: log, now: now, devs: map[string]*Device{},
		OnWarning: func(Warning) {}}, nil
}

// DeviceOptions describe one meter on the bridge.
type DeviceOptions struct {
	Meter MeterLoRaWAN
	// ServerWPort is the meter's wPort (default 1); PushWPort the wPort an
	// unsolicited APDU is addressed to when the header is none (default
	// 64).
	ServerWPort uint16
	PushWPort   uint16
}

// Add registers a meter and returns its conn.
func (b *Bridge) Add(o DeviceOptions) (*DeviceConn, error) {
	eui := strings.ToLower(strings.ReplaceAll(o.Meter.DevEUI, "-", ""))
	if e, err := hex.DecodeString(eui); err != nil || len(e) != 8 {
		return nil, fmt.Errorf("devEui %q is not 8 bytes of hex", o.Meter.DevEUI)
	}
	class := b.s.Class
	if o.Meter.Class != "" {
		class = strings.ToUpper(o.Meter.Class)
		if class != schc.ClassA && class != schc.ClassB && class != schc.ClassC {
			return nil, fmt.Errorf("class %q is not A, B or C", o.Meter.Class)
		}
	}
	d := &Device{b: b, eui: eui, class: class, sw: o.ServerWPort, pw: o.PushWPort}
	if d.sw == 0 {
		d.sw = 1
	}
	if d.pw == 0 {
		d.pw = 64
	}
	switch {
	case o.Meter.DevIID != "":
		iid, err := hex.DecodeString(o.Meter.DevIID)
		if err != nil || len(iid) != 8 {
			return nil, errors.New("devIid is not 8 bytes of hex")
		}
		d.ctx.DevIID = iid
	case o.Meter.AppSKey != "":
		k, err := hex.DecodeString(o.Meter.AppSKey)
		if err != nil {
			return nil, errors.New("appSKey is not hex")
		}
		e, _ := hex.DecodeString(eui)
		if d.ctx.DevIID, err = schc.LoRaWANIID(k, e); err != nil {
			return nil, err
		}
	default:
		// The EUI-64 with the universal/local bit flipped (a modified
		// EUI-64 IID); RFC 9011 5.3 prefers the CMAC one, which needs the
		// AppSKey.
		e, _ := hex.DecodeString(eui)
		e[0] ^= 0x02
		d.ctx.DevIID = e
	}
	if b.s.IPv6 != nil || b.stack.String() != "wrapper" {
		d.ctx.AppIID = b.appIID()
	}
	d.conn = &DeviceConn{d: d, in: make(chan []byte, 32), done: make(chan struct{})}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.devs[eui] != nil {
		return nil, fmt.Errorf("devEui %s is used twice", eui)
	}
	b.devs[eui] = d
	return d.conn, nil
}

func (b *Bridge) ipv6() IPv6Settings {
	v := IPv6Settings{}
	if b.s.IPv6 != nil {
		v = *b.s.IPv6
	}
	if v.DevPrefix == "" {
		v.DevPrefix = "fe80::/64"
	}
	if v.AppPrefix == "" {
		v.AppPrefix = "fe80::/64"
	}
	if v.AppIID == "" {
		v.AppIID = "::1"
	}
	if v.Port == 0 {
		v.Port = 4059
	}
	if v.HopLimit == 0 {
		v.HopLimit = 255
	}
	return v
}

func (b *Bridge) appIID() []byte {
	v, err := schc.IPv6Value(b.ipv6().AppIID)
	if err != nil {
		return nil
	}
	return v.Bytes()
}

// Run connects to the network server and runs the timers until ctx ends.
func (b *Bridge) Run(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() { errc <- b.ns.Run(ctx, b.HandleUplink) }()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			b.closeAll()
			return nil
		case err := <-errc:
			if err != nil {
				b.closeAll()
				return err
			}
			errc = nil
		case <-t.C:
			b.Tick(ctx)
		}
	}
}

func (b *Bridge) closeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range b.devs {
		_ = d.conn.Close()
	}
}

// Link is a meter's link information.
func (b *Bridge) Link(devEUI string) (LinkInfo, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.devs[strings.ToLower(devEUI)]
	if d == nil {
		return LinkInfo{}, false
	}
	li := d.link
	li.DevEUI = d.eui
	li.Waiting = len(d.queue)
	li.MaxPayload = b.payload(d)
	li.Reassembling = d.recv != nil && !d.recv.Done()
	li.Fragmenting = d.send != nil && !d.send.Done()
	return li, true
}

// payload is the downlink payload limit in bytes (b.mu held).
func (b *Bridge) payload(d *Device) int {
	if b.s.MaxPayload > 0 {
		return b.s.MaxPayload - b.s.PayloadReserve
	}
	rx2 := b.region.Payload(b.region.RX2DR)
	p := rx2
	switch {
	case b.s.DownlinkDataRate != nil:
		p = b.region.Payload(*b.s.DownlinkDataRate)
	case d.class == schc.ClassA && d.link.DR != nil:
		if rx1 := b.region.Payload(*d.link.DR); rx1 > 0 && rx1 < p {
			p = rx1
		}
	}
	if p <= 0 {
		p = 51
	}
	return p - b.s.PayloadReserve
}

func (b *Bridge) dutyCycle() float64 {
	if b.s.DutyCycle != nil {
		return *b.s.DutyCycle
	}
	return b.region.DutyCycle
}

// Device is one meter's SCHC state.
type Device struct {
	b     *Bridge
	eui   string
	class string
	sw    uint16 // meter wPort
	pw    uint16 // push wPort (header none)
	ctx   schc.Context
	conn  *DeviceConn

	recv    *schc.Receiver
	send    *schc.Sender
	pending [][]byte  // packets waiting for the fragmented one before them
	queue   []queued  // frames waiting for a downlink opportunity
	nextTx  time.Time // duty cycle
	link    LinkInfo
	client  uint16 // the wPort of the last request sent (header none)

	lastDelivered *schc.Receiver
}

type queued struct {
	f   schc.LoRaWANFrame
	ack bool // a SCHC ACK for an uplink: goes first
}

// HandleUplink takes one uplink from the network server.
func (b *Bridge) HandleUplink(u Uplink) {
	b.mu.Lock()
	d := b.devs[strings.ToLower(u.DevEUI)]
	if d == nil {
		b.mu.Unlock()
		b.OnWarning(Warning{Kind: WarnUnknownDevice, Subject: u.DevEUI, Setting: "meters[].lorawan.devEui",
			Msg: "An uplink came from a DevEUI no meter has; it was ignored.", Detail: fmt.Sprintf("fPort %d", u.FPort)})
		return
	}
	now := b.now()
	d.link.LastUplink, d.link.Uplinks = now, d.link.Uplinks+1
	if u.FCnt != nil {
		d.link.FCnt = u.FCnt
	}
	if u.DR != nil {
		d.link.DR = u.DR
	}
	d.link.RSSI, d.link.SNR, d.link.Frequency = u.RSSI, u.SNR, u.Frequency
	var deliver [][]byte
	if u.FPort != 0 {
		deliver = d.uplink(now, u)
	}
	out := d.pump(now, true)
	conn := d.conn
	b.mu.Unlock()
	if b.OnUplink != nil {
		b.OnUplink(d.eui)
	}
	for _, p := range deliver {
		conn.push(p)
	}
	b.transmit(out)
}

// Reopen gives a device a new conn when its old one was closed (the DLMS
// layer closes a conn after a failed write).
func (b *Bridge) Reopen(devEUI string) *DeviceConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.devs[strings.ToLower(devEUI)]
	if d == nil {
		return nil
	}
	d.conn.mu.Lock()
	closed := d.conn.closed
	d.conn.mu.Unlock()
	if closed {
		d.conn = &DeviceConn{d: d, in: make(chan []byte, 32), done: make(chan struct{})}
	}
	return d.conn
}

// uplink handles a SCHC message (b.mu held) and returns whole packets
// ready for the meter's conn.
func (d *Device) uplink(now time.Time, u Uplink) [][]byte {
	b := d.b
	msg := schc.FromLoRaWAN(uint8(u.FPort), u.Data)
	switch u.FPort {
	case b.s.FPortUp:
		r := b.rules.ByID(uint32(u.FPort))
		if d.recv == nil || d.recv.Err() != nil || (d.recv.Done() && isNewPacket(r, msg)) {
			d.recv = schc.NewReceiver(r, 8, 0, b.rules.MaxPacketSize, now)
		}
		acks, err := d.recv.Receive(now, msg)
		d.queueAcks(acks)
		if err != nil {
			d.fail("uplink reassembly", err)
		}
		if pkt, ok := d.recv.Packet(); ok && !d.delivered(d.recv) {
			return d.decompress(pkt)
		}
		return nil
	case b.s.FPortDown:
		if d.send == nil || d.send.Done() {
			return nil
		}
		more, err := d.send.Receive(now, msg, 8+8*b.payload(d))
		d.queueFrames(more)
		if err != nil {
			d.fail("downlink fragmentation", err)
		}
		if d.send.Done() {
			d.startNext(now)
		}
		return nil
	}
	return d.decompress(msg)
}

// isNewPacket tells a first fragment of a new packet from a late message
// of the one just reassembled.
func isNewPacket(r *schc.Rule, msg schc.Bits) bool {
	m, err := schc.DecodeAtReceiver(r, msg, 8)
	return err == nil && m.Kind == schc.MsgFragment
}

// delivered marks a receiver's packet as handed on once.
func (d *Device) delivered(r *schc.Receiver) bool {
	if d.lastDelivered == r {
		return true
	}
	d.lastDelivered = r
	return false
}

func (d *Device) fail(what string, err error) {
	d.link.LastError = what + ": " + err.Error()
	d.b.OnWarning(Warning{Kind: WarnSCHC, Subject: d.eui, Setting: "lorawan",
		Msg: "A SCHC transfer with the meter failed.", Detail: d.link.LastError})
}

// decompress rebuilds the packet and turns it into a wrapper frame.
func (d *Device) decompress(msg schc.Bits) [][]byte {
	b := d.b
	pkt, r, err := b.rules.Decompress(b.stack, msg, schc.Up, d.ctx)
	if err != nil {
		d.fail("decompression", err)
		return nil
	}
	if r.Kind == schc.KindFragmentation {
		return nil
	}
	frame, err := d.toFrame(pkt)
	if err != nil {
		d.fail("decompression", err)
		return nil
	}
	return [][]byte{frame}
}

// toFrame turns a decompressed packet into the wrapper frame the DLMS
// layer reads.
func (d *Device) toFrame(pkt []byte) ([]byte, error) {
	switch d.b.stack.String() {
	case "wrapper":
		return pkt, nil
	case "none":
		dst := d.pw
		if d.client != 0 && !isPush(pkt) {
			dst = d.client
		}
		return wrap(d.sw, dst, pkt), nil
	}
	// ipv6/udp/wrapper: the wrapper frame is the UDP payload.
	if len(pkt) < 48 || pkt[6] != 17 {
		return nil, errors.New("the packet is not IPv6/UDP")
	}
	return pkt[48:], nil
}

// isPush reports an APDU the meter sends unasked: a data-notification, or
// one protected with general-glo/ded ciphering or general signing whose
// content we cannot see (without a wrapper, answers to a request we sent
// are told apart only by our having one outstanding).
func isPush(apdu []byte) bool { return len(apdu) > 0 && apdu[0] == 0x0F }

func wrap(src, dst uint16, apdu []byte) []byte {
	f := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(f[0:], 1)
	binary.BigEndian.PutUint16(f[2:], src)
	binary.BigEndian.PutUint16(f[4:], dst)
	binary.BigEndian.PutUint16(f[6:], uint16(len(apdu)))
	return append(f, apdu...)
}

// fromFrame turns a wrapper frame from the DLMS layer into the packet to
// compress.
func (d *Device) fromFrame(frame []byte) ([]byte, error) {
	if len(frame) < 8 || binary.BigEndian.Uint16(frame[6:]) != uint16(len(frame)-8) {
		return nil, errors.New("not a whole wrapper frame")
	}
	switch d.b.stack.String() {
	case "wrapper":
		return frame, nil
	case "none":
		d.client = binary.BigEndian.Uint16(frame[2:])
		return frame[8:], nil
	}
	v := d.b.ipv6()
	vals := map[string]schc.Bits{
		schc.FIPv6Version: schc.Uint(6, 4), schc.FIPv6TrafficClass: schc.Uint(0, 8), schc.FIPv6FlowLabel: schc.Uint(0, 20),
		schc.FIPv6NextHeader: schc.Uint(17, 8), schc.FIPv6HopLimit: schc.Uint(uint64(v.HopLimit), 8),
		schc.FUDPDevPort: schc.Uint(uint64(v.Port), 16), schc.FUDPAppPort: schc.Uint(uint64(v.Port), 16),
		schc.FIPv6DevIID: schc.BytesOf(d.ctx.DevIID), schc.FIPv6AppIID: schc.BytesOf(d.ctx.AppIID),
	}
	for fid, p := range map[string]string{schc.FIPv6DevPrefix: v.DevPrefix, schc.FIPv6AppPrefix: v.AppPrefix} {
		x, err := prefixBits(p)
		if err != nil {
			return nil, err
		}
		vals[fid] = x
	}
	return schc.Stack{"ipv6", "udp"}.Build(vals, frame, schc.Down)
}

func prefixBits(p string) (schc.Bits, error) {
	v, err := schc.IPv6Value(p)
	if err != nil {
		return schc.Bits{}, fmt.Errorf("lorawan.ipv6: %w", err)
	}
	return v, nil
}

// send compresses a packet and queues its frames (b.mu held).
func (d *Device) sendPacket(now time.Time, pkt []byte) error {
	b := d.b
	msg, _, err := b.rules.Compress(b.stack, pkt, schc.Down, d.ctx)
	if err != nil {
		return err
	}
	mtu := 8 + 8*b.payload(d)
	padded := msg.Clone()
	padded.Pad(8)
	if padded.Len() <= mtu {
		f, err := schc.ToLoRaWAN(padded)
		if err != nil {
			return err
		}
		d.queue = append(d.queue, queued{f: f})
		return nil
	}
	if d.send != nil && !d.send.Done() {
		if len(d.pending) >= 8 {
			return errors.New("eight packets already wait for the meter's downlink fragmentation")
		}
		d.pending = append(d.pending, pkt)
		return nil
	}
	return d.fragment(now, msg)
}

func (d *Device) fragment(now time.Time, msg schc.Bits) error {
	b := d.b
	r := b.rules.ByID(uint32(b.s.FPortDown))
	s, err := schc.NewSender(r, 8, 0, msg)
	if err != nil {
		return err
	}
	d.send = s
	out, err := s.Start(now, 8+8*b.payload(d))
	d.queueFrames(out)
	return err
}

// startNext starts the next packet waiting for fragmentation.
func (d *Device) startNext(now time.Time) {
	for len(d.pending) > 0 {
		p := d.pending[0]
		d.pending = d.pending[1:]
		if err := d.sendPacket(now, p); err != nil {
			d.fail("downlink", err)
			continue
		}
		if d.send != nil && !d.send.Done() {
			return
		}
	}
}

func (d *Device) queueFrames(msgs []schc.Bits) {
	for _, m := range msgs {
		if f, err := schc.ToLoRaWAN(m); err == nil {
			d.queue = append(d.queue, queued{f: f})
		}
	}
}

func (d *Device) queueAcks(msgs []schc.Bits) {
	var acks []queued
	for _, m := range msgs {
		if f, err := schc.ToLoRaWAN(m); err == nil {
			acks = append(acks, queued{f: f, ack: true})
		}
	}
	d.queue = append(acks, d.queue...)
}

// pump takes the frames that may go now (b.mu held): class A one per
// uplink (the network server sends it in that uplink's receive windows),
// classes B and C whenever the duty cycle allows.
func (d *Device) pump(now time.Time, opportunity bool) []Downlink {
	var out []Downlink
	for len(d.queue) > 0 {
		if d.class == schc.ClassA && !opportunity {
			break
		}
		if now.Before(d.nextTx) && d.class != schc.ClassA {
			break
		}
		q := d.queue[0]
		d.queue = d.queue[1:]
		out = append(out, Downlink{DevEUI: d.eui, FPort: int(q.f.FPort), Data: q.f.Payload, Confirmed: d.b.s.Confirmed})
		d.link.Downlinks++
		if dc := d.b.dutyCycle(); dc > 0 {
			dr := d.b.region.RX2DR
			if d.link.DR != nil {
				dr = *d.link.DR
			}
			air := d.b.region.Airtime(dr, len(q.f.Payload)+PHYOverhead)
			d.nextTx = now.Add(time.Duration(float64(air) * (1/dc - 1)))
		}
		if d.class == schc.ClassA {
			break
		}
	}
	return out
}

func (b *Bridge) transmit(out []Downlink) {
	for _, dl := range out {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := b.ns.Send(ctx, dl); err != nil {
			b.OnWarning(Warning{Kind: WarnDownlinkFailed, Subject: dl.DevEUI, Setting: "lorawan.broker",
				Msg: "A downlink could not be queued at the network server; SCHC will retry it.", Detail: err.Error()})
		}
		cancel()
	}
}

// Tick runs the SCHC timers and releases class B and C frames.
func (b *Bridge) Tick(ctx context.Context) {
	b.mu.Lock()
	now := b.now()
	var out []Downlink
	for _, d := range b.devs {
		if d.recv != nil {
			d.queueAcks(d.recv.Tick(now))
		}
		if d.send != nil && !d.send.Done() {
			more, err := d.send.Tick(now)
			d.queueFrames(more)
			if err != nil {
				d.fail("downlink fragmentation", err)
			}
			if d.send.Done() {
				d.startNext(now)
			}
		}
		out = append(out, d.pump(now, false)...)
	}
	b.mu.Unlock()
	b.transmit(out)
}

// DeviceConn is a meter's LoRaWAN link as a stream of wrapper frames.
type DeviceConn struct {
	d *Device

	mu     sync.Mutex
	buf    []byte
	rdl    time.Time
	in     chan []byte
	done   chan struct{}
	closed bool
}

func (c *DeviceConn) push(frame []byte) {
	select {
	case c.in <- frame:
	case <-c.done:
	default:
		c.d.b.OnWarning(Warning{Kind: WarnBacklog, Subject: c.d.eui, Setting: "",
			Msg: "Packets from the meter arrived faster than they were read; one was dropped.", Detail: ""})
	}
}

// DevEUI is the meter's DevEUI.
func (c *DeviceConn) DevEUI() string { return c.d.eui }

// Read returns bytes of the wrapper frames received.
func (c *DeviceConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			c.mu.Unlock()
			return n, nil
		}
		dl := c.rdl
		c.mu.Unlock()
		var timeout <-chan time.Time
		if !dl.IsZero() {
			w := time.Until(dl)
			if w <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(w)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case f := <-c.in:
			c.mu.Lock()
			c.buf = append(c.buf, f...)
			c.mu.Unlock()
		case <-c.done:
			return 0, io.EOF
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write sends one or more whole wrapper frames to the meter.
func (c *DeviceConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	b := c.d.b
	var out []Downlink
	for rest := p; len(rest) > 0; {
		if len(rest) < 8 {
			return 0, errors.New("not a whole wrapper frame")
		}
		n := 8 + int(binary.BigEndian.Uint16(rest[6:]))
		if n > len(rest) {
			return 0, errors.New("not a whole wrapper frame")
		}
		pkt, err := c.d.fromFrame(rest[:n])
		if err != nil {
			return 0, err
		}
		b.mu.Lock()
		now := b.now()
		err = c.d.sendPacket(now, pkt)
		out = append(out, c.d.pump(now, false)...)
		b.mu.Unlock()
		if err != nil {
			return 0, err
		}
		rest = rest[n:]
	}
	b.transmit(out)
	return len(p), nil
}

// Close ends the conn.
func (c *DeviceConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	return nil
}

// LocalAddr and RemoteAddr name the LoRaWAN ends.
func (c *DeviceConn) LocalAddr() net.Addr { return loraAddr("network-server") }

// RemoteAddr names the device by its DevEUI.
func (c *DeviceConn) RemoteAddr() net.Addr { return loraAddr("lorawan:" + c.d.eui) }

// SetDeadline sets the read deadline.
func (c *DeviceConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline sets the read deadline.
func (c *DeviceConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline does nothing: writes only queue.
func (c *DeviceConn) SetWriteDeadline(time.Time) error { return nil }

type loraAddr string

func (a loraAddr) Network() string { return "lorawan" }
func (a loraAddr) String() string  { return string(a) }
