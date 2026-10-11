// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

import (
	"bytes"
	"log"
	"sync"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// silentLink takes what is sent and never answers.
type silentLink struct {
	mu   sync.Mutex
	sent [][]byte
}

func (l *silentLink) Close()                         {}
func (l *silentLink) Connect() error                 { return nil }
func (l *silentLink) Disconnect() error              { return nil }
func (l *silentLink) IsConnected() bool              { return true }
func (l *silentLink) SetAddress(int, int)            {}
func (l *silentLink) SetReception(gdlms.DataChannel) {}
func (l *silentLink) SetLogger(*log.Logger)          {}
func (l *silentLink) Send(b []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent = append(l.sent, append([]byte(nil), b...))
	return nil
}

// ctosLength is the length of the calling-authentication-value of an AARQ
// (AC len 80 len CtoS).
func ctosLength(aarq []byte) int {
	i := bytes.Index(aarq, []byte{0xAC})
	if i < 0 || i+3 >= len(aarq) || aarq[i+2] != 0x80 {
		return -1
	}
	return int(aarq[i+3])
}

// Mechanism 2 is manufacturer-specific: we encrypt the challenge with AES
// in ECB mode, Gurux in CBC mode with a zero IV, and the two agree only on
// a one-block challenge. Interop against Gurux's server failed with our
// 32-octet challenge; the other mechanisms keep 32 octets.
func TestMechanism2ChallengeIsOneBlock(t *testing.T) {
	for _, tc := range []struct {
		mech byte
		want int
	}{{MechHLS, 16}, {MechMD5, 32}, {MechSHA256, 32}} {
		l := &silentLink{}
		_, _ = Associate(AssociationConfig{Transport: l, Mechanism: tc.mech,
			HLS: &HLS{Mechanism: tc.mech, Secret: []byte("0123456789ABCDEF")}, Timeout: 50 * time.Millisecond})
		l.mu.Lock()
		if len(l.sent) == 0 {
			l.mu.Unlock()
			t.Fatalf("mechanism %d: no AARQ sent", tc.mech)
		}
		got := ctosLength(l.sent[0])
		l.mu.Unlock()
		if got != tc.want {
			t.Errorf("mechanism %d: challenge of %d octets, want %d", tc.mech, got, tc.want)
		}
	}
}
