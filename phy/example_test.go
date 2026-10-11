// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package phy_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/phy"
)

// The identification request before HDLC, to any device and to the device
// with lower HDLC address 0x11 on a multidrop line.
func ExampleIdentifyRequest() {
	fmt.Printf("% X\n", phy.IdentifyRequest(nil))
	dev := uint16(0x11)
	fmt.Printf("% X\n", phy.IdentifyRequest(&dev))
	// Output:
	// 20
	// 20 00 11
}
