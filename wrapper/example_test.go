// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wrapper_test

import (
	"bytes"
	"fmt"

	"github.com/cB-Sigma/dlms/wrapper"
)

// A GET of the clock (class 8, 0.0.1.0.0.255, attribute 2) from client
// wPort 16 to the meter's management logical device (wPort 1), framed and
// read back.
func ExampleEncode() {
	get := []byte{0xC0, 0x01, 0xC1, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x02, 0x00}
	wpdu, err := wrapper.Encode(16, 1, get)
	if err != nil {
		panic(err)
	}
	fmt.Printf("header % X\n", wpdu[:wrapper.HeaderLen])
	h, apdu, err := wrapper.ReadWPDU(bytes.NewReader(wpdu))
	fmt.Println(h.Src, h.Dst, len(apdu), err)
	// Output:
	// header 00 01 00 10 00 01 00 0D
	// 16 1 13 <nil>
}
