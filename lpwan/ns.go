// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lpwan

import (
	"context"
	"time"
)

// Uplink is a LoRaWAN uplink from the network server.
type Uplink struct {
	DevEUI      string
	Application string
	FPort       int // 0: a frame without FPort (MAC only, or empty)
	Data        []byte
	FCnt        *int64
	DR          *int
	RSSI, SNR   *float64 // the best gateway's
	Frequency   int64
	Time        time.Time
	Confirmed   bool
}

// Downlink is a frame to queue at the network server.
type Downlink struct {
	DevEUI    string
	FPort     int
	Data      []byte
	Confirmed bool
}

// NetworkServer is a LoRaWAN network server's application integration.
type NetworkServer interface {
	// Run delivers uplinks until ctx ends.
	Run(ctx context.Context, deliver func(Uplink)) error
	// Send queues a downlink; the network server sends it in the device's
	// next receive window (class A) or ping slot (B), or at once (C).
	Send(ctx context.Context, d Downlink) error
}
