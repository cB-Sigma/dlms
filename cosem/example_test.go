// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/wrapper"
	"github.com/cB-Sigma/iotsec"
)

// A client with HLS-GMAC (mechanism 5) and authenticated and encrypted
// APDUs under a dedicated key reads a voltage register from a meter over
// the wrapper on TCP. The meter's frame counter for the client is read
// first through the public client, so the association starts past it.
// (It needs a meter, so it is compiled but not run; the dlms-sim module
// runs the same steps against its simulated meter.)
func ExampleClient() {
	key := []byte("0123456789ABCDEF")
	ak := []byte("FEDCBA9876543210")
	addr := "192.0.2.10:4059"

	sec := cosem.SecurityConfig{Name: "M1", Authentication: "hls-gmac", Security: "authenticated-encrypted",
		BlockCipherKey: fmt.Sprintf("%X", key), AuthenticationKey: fmt.Sprintf("%X", ak), DedicatedKey: true}
	hls, _, err := sec.Build()
	if err != nil {
		panic(err)
	}
	c := cosem.NewClient(cosem.ClientConfig{
		Transport: func(client int) (gdlms.Transport, error) {
			return wrapper.New("tcp", addr, client, 1, 5*time.Second)
		},
		ClientAddress:     cosem.DefaultClientAddress(cosem.MechGMAC), // 48
		HLS:               hls,
		InvocationCounter: &cosem.FrameCounterObject{OBIS: "0.0.43.1.3.255"},
		Name:              "M1", Where: addr,
	})
	if err := c.Connect(); err != nil {
		panic(err)
	}
	defer c.Close()
	v, err := c.Get(3, "1.0.32.7.0.255", 2)
	if err != nil {
		panic(err)
	}
	s, err := cosem.ReadScaler(c.Association().Client, 3, "1.0.32.7.0.255")
	if err != nil {
		panic(err)
	}
	n, _ := cosem.Number(v)
	fmt.Println(cosem.Scaled(n, s.Exponent), s.Unit)
}

// The security suite 0 example of the DLMS UA Green Book: a GET request
// authenticated and encrypted with AES-GCM-128 under system title
// 4D4D4D0000BC614E and invocation counter 01234567.
func ExampleProtect() {
	hexb := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}
	p, err := cosem.Protect(0, cosem.SecAuthentication|cosem.SecEncryption,
		hexb("000102030405060708090A0B0C0D0E0F"), hexb("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
		hexb("4D4D4D0000BC614E"), 0x01234567, hexb("C0010000080000010000FF0200"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%X\n", p)
	// Output: 3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B
}

// memStore is an iotsec.Store in memory (an application keeps it in a
// database, a file or the cloud).
type memStore struct{ b []byte }

func (m *memStore) Load(_ context.Context, v any) error {
	if m.b == nil {
		return iotsec.ErrNotStored
	}
	return json.Unmarshal(m.b, v)
}

func (m *memStore) Save(_ context.Context, v any) error {
	b, err := json.Marshal(v)
	m.b = b
	return err
}

// Invocation counters across a restart: the reservation is stored ahead
// of the counters used, and the first association after a restart starts
// at the stored reservation.
func ExampleICReservation() {
	store := &memStore{}
	ctx := context.Background()
	r := &cosem.ICReservation{Store: store, Window: 1000, Name: "M1"}
	ic, _ := r.Reserve(ctx, 1, true)
	fmt.Println("first association starts at", ic, "stored", string(store.b))
	// The process restarts: a new reservation reads the stored one.
	r = &cosem.ICReservation{Store: store, Window: 1000, Name: "M1"}
	ic, _ = r.Reserve(ctx, 1, true)
	fmt.Println("after the restart it starts at", ic)
	// Output:
	// first association starts at 1 stored {"next":1001}
	// after the restart it starts at 1001
}
