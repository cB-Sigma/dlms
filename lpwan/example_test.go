// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package lpwan_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/lpwan"
)

// The largest LoRaWAN payload at a data rate in India's band.
func ExampleLookupRegion() {
	r, err := lpwan.LookupRegion("IN865")
	if err != nil {
		panic(err)
	}
	fmt.Println(r.Name, r.Payload(0), r.Payload(5))
	// Output: IN865 51 242
}
