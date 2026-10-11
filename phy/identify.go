// Package phy is our physical layer for the IEC 62056-7-6 profile, after
// IEC 62056-42 (Ed 1.0, 2002): the PH-CONNECT, PH-ABORT and PH-DATA
// services over a byte stream (a serial-to-Ethernet converter, a direct
// line or a Hayes modem on the PSTN), the Hayes procedures of its annex A
// for dialling, answering and hanging up, and the optional identification
// service of 6.3.3 on both sides. Clause numbers are those of
// IEC 62056-42 unless stated.
package phy

import (
	"errors"
	"fmt"
)

// Identification message values (6.3.3.2).
const (
	IdentifyRequestID    = 0x20 // IDENTIFY-Request-ID
	IdentifyRequestIDAlt = 0x49 // 'I', accepted for existing implementations (footnote 1)
)

// Identity is an IDENTIFY.response: success code, then the identifier,
// version and revision of the protocol stack.
type Identity struct {
	Success, Protocol, Version, Revision byte
}

// COSEM is the answer 6.3.3.2 prescribes for this stack (the NEMA C12.21
// codes): success 0x00, protocol 0x04, version 0x01, revision 0x00.
var COSEM = Identity{Success: 0x00, Protocol: 0x04, Version: 0x01, Revision: 0x00}

// String describes the identification answer.
func (id Identity) String() string {
	return fmt.Sprintf("success %#02x, protocol %#02x version %d revision %d", id.Success, id.Protocol, id.Version, id.Revision)
}

// Bytes is the response as sent: four octets, not A-XDR.
func (id Identity) Bytes() []byte { return []byte{id.Success, id.Protocol, id.Version, id.Revision} }

// ParseIdentity reads a four-octet response.
func ParseIdentity(b []byte) (Identity, error) {
	if len(b) != 4 {
		return Identity{}, fmt.Errorf("an identification response is 4 octets, not %d", len(b))
	}
	return Identity{b[0], b[1], b[2], b[3]}, nil
}

// IdentifyRequest is the IDENTIFY.request: one octet, or three with the
// multidrop device ID of one physical device (F-1138: we send the device's
// lower HDLC address as a 16-bit number, most significant octet first).
func IdentifyRequest(device *uint16) []byte {
	if device == nil {
		return []byte{IdentifyRequestID}
	}
	return []byte{IdentifyRequestID, byte(*device >> 8), byte(*device)}
}

// ErrNotIdentify is returned for bytes that are not an IDENTIFY.request.
var ErrNotIdentify = errors.New("not an identification request")

// ParseIdentifyRequest reads a request of one or three octets and returns
// its multidrop device ID, if any.
func ParseIdentifyRequest(b []byte) (device *uint16, err error) {
	if len(b) != 1 && len(b) != 3 {
		return nil, ErrNotIdentify
	}
	if b[0] != IdentifyRequestID && b[0] != IdentifyRequestIDAlt {
		return nil, ErrNotIdentify
	}
	if len(b) == 3 {
		d := uint16(b[1])<<8 | uint16(b[2])
		return &d, nil
	}
	return nil, nil
}
