// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package obis_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/obis"
)

// What OBIS codes mean, and the point names derived from them.
func ExampleDescribe() {
	for _, s := range []string{"1.0.1.8.0.255", "1.0.32.7.0.255", "1.0.1.8.0.3", "7.0.13.2.0.255"} {
		i := obis.Describe(obis.MustParse(s))
		fmt.Println(s, i.Kind, i.Name)
	}
	// A reduced code as an IEC 62056-21 readout writes it.
	c, _ := obis.ParseAny("1.8.0")
	fmt.Println(obis.Name(c))
	// Output:
	// 1.0.1.8.0.255 standard activeEnergyImport
	// 1.0.32.7.0.255 standard voltageL1
	// 1.0.1.8.0.3 standard activeEnergyImport_b03
	// 7.0.13.2.0.255 standard gasConverterVolumeFwdBase
	// activeEnergyImport
}
