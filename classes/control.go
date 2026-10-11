// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// SecuritySetup is class 64 (version 1). Its methods hand their parameters
// to the func fields, which hold the keys and certificates; a method whose
// func is nil is refused (read-write denied). Certificates is kept as
// A-XDR data and is the meter's to fill.
type SecuritySetup struct {
	sync.Mutex
	LN                string
	SecurityPolicy    uint8
	SecuritySuite     uint8
	ClientSystemTitle []byte
	ServerSystemTitle []byte
	Certificates      *axdr.DlmsData

	// OnActivate approves a new security policy (security_activate, 1);
	// nil accepts it.
	OnActivate func(policy uint8) error
	// OnKeyTransfer receives the wrapped keys of key_transfer (2).
	OnKeyTransfer func(param *axdr.DlmsData) error
	// OnKeyAgreement runs key_agreement (3) and returns its answer.
	OnKeyAgreement func(param *axdr.DlmsData) (*axdr.DlmsData, error)
	// OnCertificate runs methods 4 to 8 (key pair generation, certificate
	// request, import, export, removal).
	OnCertificate func(method int8, param *axdr.DlmsData) (*axdr.DlmsData, error)
}

func (o *SecuritySetup) ClassID() uint16     { return 64 }
func (o *SecuritySetup) Version() uint8      { return 1 }
func (o *SecuritySetup) LogicalName() string { return o.LN }

func (o *SecuritySetup) attrs() map[int8]attr {
	return map[int8]attr{2: readOnly(fEnum(&o.SecurityPolicy)), 3: readOnly(fEnum(&o.SecuritySuite)),
		4: fOctets(&o.ClientSystemTitle), 5: readOnly(fOctets(&o.ServerSystemTitle)),
		6: readOnly(fArray(&o.Certificates))}
}

func (o *SecuritySetup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *SecuritySetup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *SecuritySetup) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	act, kt, ka, cert := o.OnActivate, o.OnKeyTransfer, o.OnKeyAgreement, o.OnCertificate
	o.Unlock()
	switch {
	case m == 1:
		policy, err := enumOf(p)
		if err != nil {
			return nil, err
		}
		if act != nil {
			if err := act(policy); err != nil {
				return nil, err
			}
		}
		o.Lock()
		o.SecurityPolicy = policy
		o.Unlock()
		return nil, nil
	case m == 2:
		if kt == nil {
			return nil, ReadWriteDenied
		}
		return nil, kt(p)
	case m == 3:
		if ka == nil {
			return nil, ReadWriteDenied
		}
		return ka(p)
	case m >= 4 && m <= 8:
		if cert == nil {
			return nil, ReadWriteDenied
		}
		return cert(m, p)
	}
	return nil, ObjectUndefined
}

// Disconnect control states (attribute 3 of class 70).
const (
	Disconnected         uint8 = 0
	Connected            uint8 = 1
	ReadyForReconnection uint8 = 2
)

// DisconnectControl is class 70: the supply switch. ControlMode (0 to 6)
// says which transitions are allowed; mode 0 keeps the switch connected
// and refuses the remote methods. OutputState follows the state
// (connected means the supply is on). OnChange, when set, is told the new
// output state after each change, and may refuse it (the state is then
// restored and the method answers with the error).
//
// Our reading of the modes: remote disconnect works from connected and
// from ready in modes 1 to 6; remote reconnect leads to ready in modes 1,
// 3 and 5 and straight to connected in 2, 4 and 6; manual reconnect (ready
// to connected) works in 1 to 6, manual disconnect in 1, 2 and 5, local
// disconnect in 1 to 6 and local reconnect in 5 and 6.
type DisconnectControl struct {
	sync.Mutex
	LN           string
	OutputState  bool
	ControlState uint8
	ControlMode  uint8
	OnChange     func(output bool) error
}

func (o *DisconnectControl) ClassID() uint16     { return 70 }
func (o *DisconnectControl) Version() uint8      { return 0 }
func (o *DisconnectControl) LogicalName() string { return o.LN }

func (o *DisconnectControl) attrs() map[int8]attr {
	return map[int8]attr{2: readOnly(fBool(&o.OutputState)), 3: readOnly(fEnum(&o.ControlState)),
		4: fEnum(&o.ControlMode)}
}

func (o *DisconnectControl) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *DisconnectControl) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	if a == 4 {
		mode, err := enumOf(v)
		if err != nil {
			return err
		}
		if mode > 6 {
			return OtherReason
		}
	}
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs remote_disconnect (1) and remote_reconnect (2).
func (o *DisconnectControl) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	switch m {
	case 1:
		return nil, o.RemoteDisconnect()
	case 2:
		return nil, o.RemoteReconnect()
	}
	return nil, ObjectUndefined
}

func modeIn(mode uint8, modes ...uint8) bool {
	for _, x := range modes {
		if x == mode {
			return true
		}
	}
	return false
}

// move changes the state when the mode allows it and the state is one of
// from; being in to already is a success with no change.
func (o *DisconnectControl) move(allowed []uint8, to uint8, from ...uint8) error {
	o.Lock()
	if !modeIn(o.ControlMode, allowed...) {
		o.Unlock()
		return ReadWriteDenied
	}
	if o.ControlState == to {
		o.Unlock()
		return nil
	}
	if !modeIn(o.ControlState, from...) {
		o.Unlock()
		return TemporaryFailure
	}
	prevState, prevOut := o.ControlState, o.OutputState
	o.ControlState, o.OutputState = to, to == Connected
	f, out, changed := o.OnChange, o.OutputState, o.OutputState != prevOut
	o.Unlock()
	if f != nil && changed {
		if err := f(out); err != nil {
			o.Lock()
			o.ControlState, o.OutputState = prevState, prevOut
			o.Unlock()
			return err
		}
	}
	return nil
}

// RemoteDisconnect opens the switch from connected or ready.
func (o *DisconnectControl) RemoteDisconnect() error {
	return o.move([]uint8{1, 2, 3, 4, 5, 6}, Disconnected, Connected, ReadyForReconnection)
}

// RemoteReconnect arms (modes 1, 3, 5) or closes (modes 2, 4, 6) the switch.
func (o *DisconnectControl) RemoteReconnect() error {
	o.Lock()
	mode := o.ControlMode
	o.Unlock()
	if modeIn(mode, 2, 4, 6) {
		return o.move([]uint8{2, 4, 6}, Connected, Disconnected)
	}
	return o.move([]uint8{1, 3, 5}, ReadyForReconnection, Disconnected)
}

// ManualReconnect is the customer closing an armed switch.
func (o *DisconnectControl) ManualReconnect() error {
	return o.move([]uint8{1, 2, 3, 4, 5, 6}, Connected, ReadyForReconnection)
}

// ManualDisconnect is the customer opening the switch.
func (o *DisconnectControl) ManualDisconnect() error {
	return o.move([]uint8{1, 2, 5}, ReadyForReconnection, Connected)
}

// LocalDisconnect is the meter opening the switch itself (a limiter, say).
func (o *DisconnectControl) LocalDisconnect() error {
	return o.move([]uint8{1, 2, 3, 4, 5, 6}, ReadyForReconnection, Connected)
}

// LocalReconnect is the meter closing the switch itself.
func (o *DisconnectControl) LocalReconnect() error {
	return o.move([]uint8{5, 6}, Connected, ReadyForReconnection)
}
