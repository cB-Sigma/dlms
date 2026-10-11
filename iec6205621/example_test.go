// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec6205621_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/dlms/iec6205621"
)

// A data readout of a mode C meter through a serial-to-IP converter that
// passes 8N1, with the 7E1 parity emulated. (It needs a meter, so it is
// compiled but not run; the dlms-sim module runs the same steps against
// its simulated IEC 62056-21 meter.)
func ExampleOpenSession() {
	cfg := &iec6205621.SessionConfig{Line: iec6205621.Line{TCP: true, Address: "192.0.2.30:4001", Emulate7E1: true}, Timeout: time.Second}
	s, _, err := iec6205621.OpenSession(context.Background(), cfg, '0', false)
	if err != nil {
		panic(err)
	}
	defer s.CloseLine()
	ds, err := s.ReadData()
	if err != nil {
		panic(err)
	}
	for _, d := range ds {
		fmt.Println(iec6205621.PointName(d.Address), d.Value, d.Unit) // activeEnergyImport 001234.5 kWh
	}
}

// The point name of a reduced-ID register address.
func ExamplePointName() {
	fmt.Println(iec6205621.PointName("1.8.0"))
	// Output: activeEnergyImport
}
