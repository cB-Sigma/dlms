// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"errors"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Every trigger from every state in control modes 0 to 7. The grouping is
// the one Gurux's control mode lists give (Gurux.DLMS.Python
// gurux_dlms/objects/enums/ControlMode.py, Gurux.DLMS.Net
// Development/Objects/Enums/ControlMode.cs): remote reconnect arms the
// switch in modes 1, 3, 5 and 6 and closes it in 2, 4 and 7 (mode 7 also
// from ready); manual disconnect only in 1, 2 and 5; local reconnect in 5,
// 6 and 7. Mode 6 was grouped with 2 and 4 before.
//
// Covers: SIG-IPE-6466
func TestDisconnectControlModes(t *testing.T) {
	const (
		D, C, R = Disconnected, Connected, ReadyForReconnection
		denied  = 0xFE // the mode forbids the trigger
		stay    = 0xFF // the trigger does not apply from this state
	)
	type trig struct {
		name string
		do   func(*DisconnectControl) error
	}
	trigs := []trig{
		{"remote disconnect", func(d *DisconnectControl) error { _, err := d.Action(1, axdr.CreateAxdrInteger(0)); return err }},
		{"remote reconnect", func(d *DisconnectControl) error { _, err := d.Action(2, axdr.CreateAxdrInteger(0)); return err }},
		{"manual disconnect", (*DisconnectControl).ManualDisconnect},
		{"manual reconnect", (*DisconnectControl).ManualReconnect},
		{"local disconnect", (*DisconnectControl).LocalDisconnect},
		{"local reconnect", (*DisconnectControl).LocalReconnect},
	}
	// want[mode][trigger][from state] = resulting state.
	all := func(x uint8) [3]uint8 { return [3]uint8{x, x, x} }
	remoteOff := [3]uint8{D, D, D}
	arm := [3]uint8{R, stay, R}       // from D: ready; from C: already on; from R: already there
	closeIt := [3]uint8{C, C, stay}   // from D: connected; from R: not applicable
	close7 := [3]uint8{C, C, C}       // mode 7 closes from ready too
	manualOff := [3]uint8{stay, R, R} // C -> R
	manualOn := [3]uint8{stay, C, C}  // R -> C
	want := map[uint8][6][3]uint8{
		0: {all(denied), all(denied), all(denied), all(denied), all(denied), all(denied)},
		1: {remoteOff, arm, manualOff, manualOn, manualOff, all(denied)},
		2: {remoteOff, closeIt, manualOff, manualOn, manualOff, all(denied)},
		3: {remoteOff, arm, all(denied), manualOn, manualOff, all(denied)},
		4: {remoteOff, closeIt, all(denied), manualOn, manualOff, all(denied)},
		5: {remoteOff, arm, manualOff, manualOn, manualOff, manualOn},
		6: {remoteOff, arm, all(denied), manualOn, manualOff, manualOn},
		7: {remoteOff, close7, all(denied), manualOn, manualOff, manualOn},
	}
	for mode := uint8(0); mode <= 7; mode++ {
		for ti, tr := range trigs {
			for from := uint8(0); from <= 2; from++ {
				d := &DisconnectControl{LN: "0.0.96.3.10.255", ControlState: from, OutputState: from == C}
				if err := d.Set(4, axdr.CreateAxdrEnum(mode), nil); err != nil {
					t.Fatalf("mode %d: %v", mode, err)
				}
				err := tr.do(d)
				w := want[mode][ti][from]
				switch w {
				case denied:
					if !errors.Is(err, ReadWriteDenied) {
						t.Errorf("mode %d %s from %d: %v, want denied", mode, tr.name, from, err)
					}
				case stay:
					if d.ControlState != from && err == nil {
						t.Errorf("mode %d %s from %d moved to %d", mode, tr.name, from, d.ControlState)
					}
				default:
					if err != nil || d.ControlState != w || d.OutputState != (w == C) {
						t.Errorf("mode %d %s from %d: state %d output %v (%v), want %d", mode, tr.name, from, d.ControlState, d.OutputState, err, w)
					}
				}
			}
		}
	}
	if err := (&DisconnectControl{}).Set(4, axdr.CreateAxdrEnum(8), nil); err == nil {
		t.Error("control mode 8 accepted")
	}
}
