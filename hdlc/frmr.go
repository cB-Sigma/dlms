package hdlc

import (
	"errors"
	"fmt"
	"strings"
)

// FrameReject is the information field of an FRMR response (IEC 62056-46
// 6.4.3.10 refers to ISO/IEC 13239 5.5.3.4.2). Bit numbers below are the
// transmission order of 13239 Figures 18a and 18b: bit 1 is the first bit
// sent, the lowest order bit of the first octet.
//
// Modulo 8 (Figure 18a, 20 bits padded with zeros to three octets):
//
//	octet 1          bits 1-8    the rejected control field
//	octet 2 bit 0    bit 9       0
//	octet 2 bits 1-3 bits 10-12  V(S) of the sender, bit 10 lowest
//	octet 2 bit 4    bit 13      C/R: 1 when the rejected frame was a response
//	octet 2 bits 5-7 bits 14-16  V(R) of the sender, bit 14 lowest
//	octet 3 bits 0-3 bits 17-20  W, X, Y, Z
//
// Modulo 128 (Figure 18b, 36 bits padded to five octets): the rejected
// control field in octets 1 and 2 (an unnumbered one in octet 1, octet 2
// zero), octet 3 bit 0 zero and bits 1-7 V(S), octet 4 bit 0 C/R and bits
// 1-7 V(R), octet 5 bits 0-3 W, X, Y, Z. The 2002 edition has no V bit.
type FrameReject struct {
	Modulo   int    // 8 or 128
	Control  uint16 // the rejected control field (second octet in the high byte, modulo 128)
	VS, VR   int    // the sender's send and receive state variables
	Response bool   // C/R: the rejected frame was a response
	// W: control field undefined or not implemented; X: an information
	// field the frame may not carry (W is set with it); Y: information
	// field longer than the sender takes; Z: invalid N(R).
	W, X, Y, Z bool
}

// Reason bits of the last FRMR octet.
const (
	frmrW = 0x01
	frmrX = 0x02
	frmrY = 0x04
	frmrZ = 0x08
)

func (r FrameReject) reasons() byte {
	var b byte
	for _, x := range []struct {
		on  bool
		bit byte
	}{{r.W, frmrW}, {r.X, frmrX}, {r.Y, frmrY}, {r.Z, frmrZ}} {
		if x.on {
			b |= x.bit
		}
	}
	return b
}

// Encode is the information field: three octets modulo 8, five modulo 128.
func (r FrameReject) Encode() []byte {
	cr := byte(0)
	if r.Response {
		cr = 1
	}
	if r.Modulo == 128 {
		return []byte{byte(r.Control), byte(r.Control >> 8), byte(r.VS&0x7F) << 1, byte(r.VR&0x7F)<<1 | cr, r.reasons()}
	}
	return []byte{byte(r.Control), byte(r.VS&7)<<1 | cr<<4 | byte(r.VR&7)<<5, r.reasons()}
}

// ErrFRMRField is returned for an FRMR information field too short for
// its modulo.
var ErrFRMRField = errors.New("the FRMR information field is too short")

// DecodeFrameReject reads an FRMR information field of the given modulo (8
// or 128). Octets past the layout are padding (5.5.3.4.2) and are ignored.
func DecodeFrameReject(info []byte, modulo int) (FrameReject, error) {
	r := FrameReject{Modulo: modulo}
	var reasons byte
	switch modulo {
	case 8:
		if len(info) < 3 {
			return r, fmt.Errorf("%w: %d octets, modulo 8 needs 3", ErrFRMRField, len(info))
		}
		r.Control = uint16(info[0])
		r.VS = int(info[1]>>1) & 7
		r.Response = info[1]&0x10 != 0
		r.VR = int(info[1] >> 5)
		reasons = info[2]
	case 128:
		if len(info) < 5 {
			return r, fmt.Errorf("%w: %d octets, modulo 128 needs 5", ErrFRMRField, len(info))
		}
		r.Control = uint16(info[0]) | uint16(info[1])<<8
		r.VS = int(info[2] >> 1)
		r.Response = info[3]&0x01 != 0
		r.VR = int(info[3] >> 1)
		reasons = info[4]
	default:
		return r, fmt.Errorf("modulo %d is not 8 or 128", modulo)
	}
	r.W, r.X, r.Y, r.Z = reasons&frmrW != 0, reasons&frmrX != 0, reasons&frmrY != 0, reasons&frmrZ != 0
	return r, nil
}

// Reason names the conditions reported, or says the rejection is
// unspecified when no reason bit is set (5.5.3.4.2).
func (r FrameReject) Reason() string {
	var out []string
	if r.W && !r.X {
		out = append(out, "control field undefined or not implemented")
	}
	if r.X {
		out = append(out, "information field not permitted with this frame")
	}
	if r.Y {
		out = append(out, "information field too long")
	}
	if r.Z {
		out = append(out, "invalid N(R)")
	}
	if len(out) == 0 {
		return "unspecified"
	}
	return strings.Join(out, ", ")
}

// String gives the reason and the rejected frame's control field and counts.
func (r FrameReject) String() string {
	kind := "command"
	if r.Response {
		kind = "response"
	}
	return fmt.Sprintf("%s (rejected %s control %#02x, V(S) %d, V(R) %d)", r.Reason(), kind, r.Control, r.VS, r.VR)
}

// RejectError is the error for an FRMR from the server: it names the
// reason and matches ErrRejected.
type RejectError struct {
	FrameReject
	Raw []byte // the information field as received
}

// Error names the rejection.
func (e *RejectError) Error() string {
	return fmt.Sprintf("%v: %s", ErrRejected, e.FrameReject)
}

// Unwrap returns ErrRejected.
func (e *RejectError) Unwrap() error { return ErrRejected }

// rejectError builds the error for a received FRMR information field. A
// field too short to read still ends the link, reported as unreadable.
func rejectError(info []byte) error { return rejectErrorModulo(info, Modulo8) }

// rejectErrorModulo is rejectError for a link numbered modulo 8 or 128.
func rejectErrorModulo(info []byte, modulo int) error {
	r, err := DecodeFrameReject(info, modulo)
	if err != nil {
		return fmt.Errorf("%w: reason unreadable (% X): %v", ErrRejected, info, err)
	}
	return &RejectError{FrameReject: r, Raw: append([]byte(nil), info...)}
}
