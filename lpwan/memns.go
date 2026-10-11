package lpwan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// MemNS is an in-memory LoRaWAN network server for tests and the meter
// simulator: devices send uplinks with Uplink; downlinks queued with Send
// reach a class A device only in the receive window after its next
// uplink (one per uplink), a class C device at once. It does no radio,
// MAC commands, ADR or security.
type MemNS struct {
	mu      sync.Mutex
	deliver func(Uplink)
	ready   chan struct{}
	once    sync.Once
	devs    map[string]*memDev
	// DR, RSSI and SNR are reported with every uplink.
	DR         int
	RSSI, SNR  float64
	DropDown   func(n int, d Downlink) bool // lose a downlink (tests)
	DropUp     func(n int, u Uplink) bool   // lose an uplink (tests)
	downs, ups int
	fcnt       map[string]int64
}

type memDev struct {
	class string
	queue []Downlink
	rx    chan Downlink
}

// NewMemNS makes a network server; its data rate is DR5.
func NewMemNS() *MemNS {
	return &MemNS{ready: make(chan struct{}), devs: map[string]*memDev{}, DR: 5, RSSI: -97, SNR: 7.5, fcnt: map[string]int64{}}
}

// Run takes uplinks for the bridge until ctx ends.
func (n *MemNS) Run(ctx context.Context, deliver func(Uplink)) error {
	n.mu.Lock()
	n.deliver = deliver
	n.mu.Unlock()
	n.once.Do(func() { close(n.ready) })
	<-ctx.Done()
	return nil
}

// Ready is closed once the bridge is listening.
func (n *MemNS) Ready() <-chan struct{} { return n.ready }

// Attach registers a device; its downlinks arrive on the returned channel.
func (n *MemNS) Attach(devEUI, class string) <-chan Downlink {
	n.mu.Lock()
	defer n.mu.Unlock()
	d := &memDev{class: strings.ToUpper(class), rx: make(chan Downlink, 256)}
	n.devs[strings.ToLower(devEUI)] = d
	return d.rx
}

// Send queues a downlink.
func (n *MemNS) Send(_ context.Context, dl Downlink) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	d := n.devs[strings.ToLower(dl.DevEUI)]
	if d == nil {
		return errors.New("unknown device")
	}
	if d.class == "C" {
		n.out(d, dl)
		return nil
	}
	d.queue = append(d.queue, dl)
	return nil
}

func (n *MemNS) out(d *memDev, dl Downlink) {
	n.downs++
	if n.DropDown != nil && n.DropDown(n.downs, dl) {
		return
	}
	d.rx <- dl
}

// Uplink sends a frame from a device; for class A its receive window then
// carries the first queued downlink.
func (n *MemNS) Uplink(devEUI string, fport int, data []byte) {
	<-n.ready
	n.mu.Lock()
	eui := strings.ToLower(devEUI)
	n.fcnt[eui]++
	fc, dr, rssi, snr := n.fcnt[eui], n.DR, n.RSSI, n.SNR
	u := Uplink{DevEUI: eui, FPort: fport, Data: append([]byte(nil), data...), FCnt: &fc, DR: &dr, RSSI: &rssi, SNR: &snr, Time: time.Now(), Frequency: 865062500}
	n.ups++
	lost := n.DropUp != nil && n.DropUp(n.ups, u)
	deliver := n.deliver
	n.mu.Unlock()
	if !lost {
		deliver(u)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if d := n.devs[eui]; !lost && d != nil && d.class != "C" && len(d.queue) > 0 {
		dl := d.queue[0]
		d.queue = d.queue[1:]
		n.out(d, dl)
	}
}

// Queued is how many downlinks wait at the network server for a device.
func (n *MemNS) Queued(devEUI string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if d := n.devs[strings.ToLower(devEUI)]; d != nil {
		return len(d.queue)
	}
	return 0
}
