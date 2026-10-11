// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package is15959_test

import (
	"fmt"

	"github.com/cB-Sigma/dlms/is15959"
)

// The IS 15959 Part 2 single-phase smart meter profile: its size, the
// meter reader association and one object's point name.
func ExampleGet() {
	sp, ok := is15959.Get("part2-1ph")
	if !ok {
		panic("no profile")
	}
	objects, profiles, logs, codes, push, methods := sp.Count()
	fmt.Println(sp.ID, objects > 0, profiles, logs, codes > 0, push, methods > 0)
	a, _ := sp.Association(is15959.MR)
	fmt.Println(a.Client, a.OBIS, a.Auth)
	fmt.Println(is15959.NameOf("1.0.1.8.0.255", is15959.ClassRegister, 2))
	fmt.Println(is15959.CodeName(201))
	// Output:
	// part2-1ph true 10 7 true 5 true
	// 32 0.0.40.0.2.255 low
	// activeEnergyImport
	// magnetic influence
}
