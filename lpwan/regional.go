package lpwan

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Regional LoRaWAN limits: the largest FRMPayload (N, without FOpts) per
// data rate, each data rate's spreading factor and bandwidth, the RX2 data
// rate and the duty cycle a head end should pace its own downlinks by.
// The figures are our reading of the LoRa Alliance Regional Parameters
// (RP002-1.0.x, dwell time off); they are not checked against a network
// server here, and the maxPayload and dutyCycle settings override them.
type Region struct {
	Name       string
	MaxPayload []int // by DR; 0 is not a LoRa data rate here
	SF         []int
	BW         []int // kHz
	RX2DR      int
	DutyCycle  float64 // 0: none imposed
}

var regions = map[string]Region{
	// India 865–867 MHz: no duty cycle limit in the Indian rules.
	"IN865": {Name: "IN865", MaxPayload: []int{51, 51, 51, 115, 242, 242}, SF: []int{12, 11, 10, 9, 8, 7}, BW: []int{125, 125, 125, 125, 125, 125}, RX2DR: 2},
	"EU868": {Name: "EU868", MaxPayload: []int{51, 51, 51, 115, 242, 242, 242}, SF: []int{12, 11, 10, 9, 8, 7, 7}, BW: []int{125, 125, 125, 125, 125, 125, 250}, RX2DR: 0, DutyCycle: 0.01},
	"AS923": {Name: "AS923", MaxPayload: []int{51, 51, 51, 115, 242, 242, 242}, SF: []int{12, 11, 10, 9, 8, 7, 7}, BW: []int{125, 125, 125, 125, 125, 125, 250}, RX2DR: 2},
	// US915 downlink data rates DR8–DR13 (500 kHz); uplinks DR0–DR4.
	"US915": {Name: "US915", MaxPayload: []int{11, 53, 125, 242, 242, 0, 0, 0, 53, 129, 242, 242, 242, 242},
		SF: []int{10, 9, 8, 7, 8, 0, 0, 0, 12, 11, 10, 9, 8, 7}, BW: []int{125, 125, 125, 125, 500, 0, 0, 0, 500, 500, 500, 500, 500, 500}, RX2DR: 8},
}

// LookupRegion finds a region by name ("IN865", "in865-867"…).
func LookupRegion(name string) (Region, error) {
	n := strings.ToUpper(strings.TrimSpace(name))
	if n == "" {
		n = "IN865"
	}
	for k, r := range regions {
		if strings.HasPrefix(n, k) {
			return r, nil
		}
	}
	return Region{}, fmt.Errorf("region %q is not IN865, EU868, AS923 or US915", name)
}

// Payload is the largest FRMPayload at a data rate (0 when unknown).
func (r Region) Payload(dr int) int {
	if dr < 0 || dr >= len(r.MaxPayload) {
		return 0
	}
	return r.MaxPayload[dr]
}

// Airtime is the LoRa time on air of a frame with n bytes of PHY payload
// at a data rate (Semtech's formula, preamble 8, explicit header, CRC on,
// coding rate 4/5, low data rate optimisation at SF11 and SF12 on 125 kHz).
func (r Region) Airtime(dr, n int) time.Duration {
	if dr < 0 || dr >= len(r.SF) || r.SF[dr] == 0 {
		return 0
	}
	sf, bw := float64(r.SF[dr]), float64(r.BW[dr])*1000
	tsym := math.Pow(2, sf) / bw
	de := 0.0
	if r.SF[dr] >= 11 && r.BW[dr] == 125 {
		de = 1
	}
	pl := math.Ceil((8*float64(n)-4*sf+28+16)/(4*(sf-2*de))) * 5
	syms := 8 + 4.25 + 8 + math.Max(pl, 0)
	return time.Duration(syms * tsym * float64(time.Second))
}

// PHYOverhead is the LoRaWAN bytes around an FRMPayload without FOpts:
// MHDR, DevAddr, FCtrl, FCnt, FPort and MIC.
const PHYOverhead = 13
