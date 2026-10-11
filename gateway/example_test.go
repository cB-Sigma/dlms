// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/gateway"
)

// A request to the meter at physical address 0A:01 behind a data
// concentrator, and the concentrator's answer taken apart again.
func ExampleEncode() {
	addr, _ := gateway.ParseAddress("0A01")
	req, err := gateway.Encode(gateway.Prefix{Header: gateway.Request, Address: addr}, []byte{0xC0, 0x01, 0xC1})
	if err != nil {
		panic(err)
	}
	fmt.Printf("% X\n", req)
	p, apdu, ok, err := gateway.Parse(req)
	fmt.Println(p, ok, err)
	fmt.Printf("% X\n", apdu)
	// Output:
	// E6 00 02 0A 01 C0 01 C1
	// network 0 address 0A01 true <nil>
	// C0 01 C1
}
