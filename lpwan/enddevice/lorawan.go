// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enddevice

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cB-Sigma/dlms/lpwan"
	"github.com/cB-Sigma/schc"
)

// Radio is the device's LoRaWAN modem: it sends uplinks and delivers the
// downlinks received in the receive windows.
type Radio interface {
	Uplink(fport int, payload []byte) error
	Downlinks() <-chan lpwan.Downlink
}

// MemRadio is a radio on package lpwan's in-memory network server.
func MemRadio(ns *lpwan.MemNS, devEUI, class string) Radio {
	return &memRadio{ns: ns, eui: devEUI, rx: ns.Attach(devEUI, class)}
}

type memRadio struct {
	ns  *lpwan.MemNS
	eui string
	rx  <-chan lpwan.Downlink
}

func (r *memRadio) Uplink(fport int, payload []byte) error {
	r.ns.Uplink(r.eui, fport, payload)
	return nil
}

func (r *memRadio) Downlinks() <-chan lpwan.Downlink { return r.rx }

// LoRaWAN is a meter behind a LoRaWAN radio.
type LoRaWAN struct {
	Handler Handler
	// ServerAddress is the logical device's SAP in the wrapper header of
	// uplinks (default 1).
	ServerAddress uint16
	DevEUI        string
	Radio         Radio
	Settings      lpwan.BridgeSettings // FPorts, header, rules: the head end's
	// UplinkPayload is the largest uplink FRMPayload in octets (default
	// 51, data rates 0 to 2 in IN865).
	UplinkPayload int
	// Poll is how often the meter sends an empty uplink to open a receive
	// window (default 200 ms).
	Poll time.Duration
	// NoneClient is the client SAP taken for requests when the header is
	// none (no wPorts on the air; default 48).
	NoneClient uint16

	mu       sync.Mutex
	rules    *schc.RuleSet
	stack    schc.Stack
	ctxt     schc.Context
	recv     *schc.Receiver
	send     *schc.Sender
	pending  []schc.Bits
	lastRecv *schc.Receiver
	uplinks  int
	served   int
	cancel   context.CancelFunc
}

// Start checks the settings and runs the meter until Stop.
func (d *LoRaWAN) Start() error {
	if d.Handler == nil || d.Radio == nil {
		return errors.New("enddevice: LoRaWAN needs a Handler and a Radio")
	}
	if err := d.Settings.Check(); err != nil {
		return err
	}
	rs, err := d.Settings.RuleSet()
	if err != nil {
		return err
	}
	d.rules = rs
	d.stack, _ = schc.ParseStack(d.Settings.Header)
	if d.UplinkPayload == 0 {
		d.UplinkPayload = 51
	}
	if d.Poll == 0 {
		d.Poll = 200 * time.Millisecond
	}
	if d.NoneClient == 0 {
		d.NoneClient = 48
	}
	if d.ServerAddress == 0 {
		d.ServerAddress = 1
	}
	if d.ctxt.DevIID == nil {
		// The head end's defaults: the modified EUI-64 and ::1.
		e, err := hex.DecodeString(d.DevEUI)
		if err != nil || len(e) != 8 {
			return fmt.Errorf("devEUI %q is not 8 bytes of hex", d.DevEUI)
		}
		e[0] ^= 0x02
		app := make([]byte, 8)
		app[7] = 1
		d.ctxt = schc.Context{DevIID: e, AppIID: app}
	}
	rx := d.Radio.Downlinks()
	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.cancel = cancel
	d.mu.Unlock()
	go func() {
		t := time.NewTicker(d.Poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case dl := <-rx:
				d.downlink(dl)
			case <-t.C:
				d.mu.Lock()
				out := d.tick()
				d.mu.Unlock()
				d.up(out)
				_ = d.Radio.Uplink(0, nil) // an empty frame opens a receive window
			}
		}
	}()
	return nil
}

// Stop stops the meter.
func (d *LoRaWAN) Stop() {
	d.mu.Lock()
	c := d.cancel
	d.mu.Unlock()
	if c != nil {
		c()
	}
}

// Served is how many requests the meter answered.
func (d *LoRaWAN) Served() int { d.mu.Lock(); defer d.mu.Unlock(); return d.served }

// Uplinks is how many SCHC messages the meter sent.
func (d *LoRaWAN) Uplinks() int { d.mu.Lock(); defer d.mu.Unlock(); return d.uplinks }

// SetIIDs sets the IPv6 interface identifiers the meter uses with header
// ipv6/udp/wrapper (the head end's defaults: EUI-64 based and ::1). Call
// it before Start.
func (d *LoRaWAN) SetIIDs(dev, app []byte) { d.ctxt = schc.Context{DevIID: dev, AppIID: app} }

func (d *LoRaWAN) tick() []schc.Bits {
	now := time.Now()
	var out []schc.Bits
	if d.send != nil && !d.send.Done() {
		m, _ := d.send.Tick(now)
		out = append(out, m...)
	}
	if d.recv != nil {
		out = append(out, d.recv.Tick(now)...)
	}
	return out
}

// up sends SCHC messages as uplinks.
func (d *LoRaWAN) up(msgs []schc.Bits) {
	for _, m := range msgs {
		f, err := schc.ToLoRaWAN(m)
		if err != nil {
			continue
		}
		d.mu.Lock()
		d.uplinks++
		d.mu.Unlock()
		_ = d.Radio.Uplink(int(f.FPort), f.Payload)
	}
}

func (d *LoRaWAN) downlink(dl lpwan.Downlink) {
	d.mu.Lock()
	now := time.Now()
	msg := schc.FromLoRaWAN(uint8(dl.FPort), dl.Data)
	var out, packets []schc.Bits
	switch dl.FPort {
	case d.Settings.FPortDown:
		r := d.rules.ByID(uint32(dl.FPort))
		if d.recv == nil || d.recv.Err() != nil || d.recv.Done() {
			if m, err := schc.DecodeAtReceiver(r, msg, 8); d.recv == nil || d.recv.Err() != nil || (err == nil && m.Kind == schc.MsgFragment && m.W == 0) {
				d.recv = schc.NewReceiver(r, 8, 0, 0, now)
			}
		}
		acks, _ := d.recv.Receive(now, msg)
		out = append(out, acks...)
		if p, ok := d.recv.Packet(); ok && d.lastRecv != d.recv {
			d.lastRecv = d.recv
			packets = append(packets, p)
		}
	case d.Settings.FPortUp:
		if d.send != nil {
			more, _ := d.send.Receive(now, msg, 8+8*d.UplinkPayload)
			out = append(out, more...)
			if d.send.Done() && len(d.pending) > 0 {
				next := d.pending[0]
				d.pending = d.pending[1:]
				out = append(out, d.fragment(next)...)
			}
		}
	default:
		packets = append(packets, msg)
	}
	var pkts [][]byte
	for _, p := range packets {
		pkt, _, err := d.rules.Decompress(d.stack, p, schc.Down, d.ctxt)
		if err == nil {
			pkts = append(pkts, pkt)
		}
	}
	d.mu.Unlock()
	// Requests are served without the lock: a handler may take its time.
	var replies [][]byte
	for _, pkt := range pkts {
		if r := d.serve(pkt); r != nil {
			replies = append(replies, r)
		}
	}
	d.mu.Lock()
	for _, r := range replies {
		out = append(out, d.encode(r)...)
	}
	d.mu.Unlock()
	d.up(out)
}

// serve answers one decompressed packet.
func (d *LoRaWAN) serve(pkt []byte) []byte {
	var src, dst uint16
	var apdu []byte
	switch d.stack.String() {
	case "none":
		// Without the wrapper the client is not named: NoneClient.
		src, dst, apdu = d.NoneClient, d.ServerAddress, pkt
	default:
		if d.stack.String() != "wrapper" {
			if len(pkt) < 48 {
				return nil
			}
			pkt = pkt[48:]
		}
		if len(pkt) < 8 {
			return nil
		}
		src, dst, apdu = binary.BigEndian.Uint16(pkt[2:]), binary.BigEndian.Uint16(pkt[4:]), pkt[8:]
	}
	if !d.Handler.Serves(dst) {
		if dr, ok := d.Handler.(Dropper); ok {
			dr.Drop()
		}
		return nil
	}
	resp := d.Handler.Handle(src, apdu)
	if resp == nil || dst == 0x7F {
		return nil
	}
	d.mu.Lock()
	d.served++
	d.mu.Unlock()
	return d.frame(src, resp)
}

// Push sends an APDU the meter pushes (a data-notification) to a client
// SAP as uplinks.
func (d *LoRaWAN) Push(client uint16, apdu []byte) error {
	d.mu.Lock()
	if d.rules == nil {
		d.mu.Unlock()
		return errors.New("enddevice: Start the meter first")
	}
	out := d.encode(d.frame(client, apdu))
	d.mu.Unlock()
	if len(out) == 0 {
		return errors.New("the push could not be compressed")
	}
	d.up(out)
	return nil
}

// frame is a wrapper frame from the meter to a client wPort.
func (d *LoRaWAN) frame(client uint16, apdu []byte) []byte {
	f := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(f[0:], 1)
	binary.BigEndian.PutUint16(f[2:], d.ServerAddress)
	binary.BigEndian.PutUint16(f[4:], client)
	binary.BigEndian.PutUint16(f[6:], uint16(len(apdu)))
	return append(f, apdu...)
}

// encode compresses a wrapper frame from the meter and fragments it if it
// does not fit one uplink (d.mu held).
func (d *LoRaWAN) encode(frame []byte) []schc.Bits {
	pkt := frame
	switch d.stack.String() {
	case "none":
		pkt = frame[8:]
	case "wrapper":
	default:
		ip := d.Settings.IPv6
		v := lpwan.IPv6Settings{DevPrefix: "fe80::/64", AppPrefix: "fe80::/64", AppIID: "::1", Port: 4059, HopLimit: 255}
		if ip != nil {
			v = *ip
		}
		vals := map[string]schc.Bits{
			schc.FIPv6Version: schc.Uint(6, 4), schc.FIPv6TrafficClass: schc.Uint(0, 8), schc.FIPv6FlowLabel: schc.Uint(0, 20),
			schc.FIPv6NextHeader: schc.Uint(17, 8), schc.FIPv6HopLimit: schc.Uint(uint64(v.HopLimit), 8),
			schc.FUDPDevPort: schc.Uint(uint64(v.Port), 16), schc.FUDPAppPort: schc.Uint(uint64(v.Port), 16),
			schc.FIPv6DevIID: schc.BytesOf(d.ctxt.DevIID), schc.FIPv6AppIID: schc.BytesOf(d.ctxt.AppIID),
		}
		vals[schc.FIPv6DevPrefix], _ = schc.IPv6Value(v.DevPrefix)
		vals[schc.FIPv6AppPrefix], _ = schc.IPv6Value(v.AppPrefix)
		b, err := schc.Stack{"ipv6", "udp"}.Build(vals, frame, schc.Up)
		if err != nil {
			return nil
		}
		pkt = b
	}
	msg, _, err := d.rules.Compress(d.stack, pkt, schc.Up, d.ctxt)
	if err != nil {
		return nil
	}
	padded := msg.Clone()
	padded.Pad(8)
	if padded.Len() <= 8+8*d.UplinkPayload {
		return []schc.Bits{padded}
	}
	if d.send != nil && !d.send.Done() {
		d.pending = append(d.pending, msg)
		return nil
	}
	return d.fragment(msg)
}

func (d *LoRaWAN) fragment(msg schc.Bits) []schc.Bits {
	r := d.rules.ByID(uint32(d.Settings.FPortUp))
	s, err := schc.NewSender(r, 8, 0, msg)
	if err != nil {
		return nil
	}
	d.send = s
	out, _ := s.Start(time.Now(), 8+8*d.UplinkPayload)
	return out
}
