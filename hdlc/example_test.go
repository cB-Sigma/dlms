// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package hdlc_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/hdlc"
)

// An SNRM from client 16 to a meter at upper address 1, lower address 17,
// with two-octet server addresses; the frame is decoded back.
func ExampleFrame() {
	f := hdlc.Frame{Dest: hdlc.ServerAddress(1, 17, 2), Src: hdlc.ClientAddress(16), Control: 0x93}
	b, err := f.Encode()
	if err != nil {
		panic(err)
	}
	fmt.Printf("% X\n", b)
	g, err := hdlc.Decode(b)
	fmt.Println(g.Control == 0x93, g.Src == f.Src, err)
	// Output:
	// 7E A0 08 02 23 21 93 BD 64 7E
	// true true <nil>
}
