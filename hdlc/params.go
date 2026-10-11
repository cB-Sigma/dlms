package hdlc

import (
	"errors"
	"fmt"
)

// Params are the negotiable HDLC parameters (6.4.4.4.3.2), each from the
// point of view of the station that sends them: MaxInfoTX is the longest
// information field it sends, MaxInfoRX the longest it receives, WindowTX
// and WindowRX the frames it sends or takes before an acknowledgement.
type Params struct {
	MaxInfoTX, MaxInfoRX int
	WindowTX, WindowRX   int
}

// Defaults are the values when nothing is negotiated.
func Defaults() Params {
	return Params{MaxInfoTX: DefaultMaxInfo, MaxInfoRX: DefaultMaxInfo, WindowTX: DefaultWindow, WindowRX: DefaultWindow}
}

// Check reports values outside the protocol's range: information fields of
// 1 to 2030 octets, windows of 1 to 7 frames.
func (p Params) Check() error { return p.CheckModulo(Modulo8) }

// CheckModulo is Check for a link numbered modulo 8 or 128: under modulo
// 128 windows may be up to 127 frames.
func (p Params) CheckModulo(modulo int) error {
	if err := checkModulo(modulo); err != nil {
		return err
	}
	for _, v := range []int{p.MaxInfoTX, p.MaxInfoRX} {
		if v < 1 || v > MaxInfo {
			return fmt.Errorf("a maximum information field length of %d is not 1 to %d", v, MaxInfo)
		}
	}
	mw := maxWindowFor(modulo)
	for _, v := range []int{p.WindowTX, p.WindowRX} {
		if v < 1 || v > mw {
			return fmt.Errorf("a window size of %d is not 1 to %d", v, mw)
		}
	}
	return nil
}

// capWindows keeps both windows within the modulus.
func (p Params) capWindows(modulo int) Params {
	mw := maxWindowFor(modulo)
	p.WindowTX, p.WindowRX = max(1, min(p.WindowTX, mw)), max(1, min(p.WindowRX, mw))
	return p
}

// Negotiation information field identifiers (6.4.4.4.3.2; ISO/IEC 13239
// 5.5.3.2.1 Figure 11 and 5.5.3.2.2 Figure 12, whose bit strings are drawn
// first bit sent, that is lowest order, first).
const (
	formatID     = 0x81 // general purpose mode-setting format identifier
	groupParams  = 0x80 // HDLC parameters
	userDataID   = 0xFF // user data subfield (13239 5.5.3.2.3.1 Figure 14)
	pidMaxInfoTX = 0x05
	pidMaxInfoRX = 0x06
	pidWindowTX  = 0x07
	pidWindowRX  = 0x08
)

// Encode is the information field of an SNRM or UA carrying all four
// parameters: the information field lengths on one octet when both fit,
// on two otherwise (the two layouts of 6.4.4.4.3.2), the windows on four.
// userData, when given, follows as the user data subfield (IEC 62056-7-6
// 9.3): the identifier 0xFF and the data, with no length octet, always the
// last subfield (ISO/IEC 13239 5.5.3.1.3, 5.5.3.2, 5.5.3.2.3).
func (p Params) Encode(userData []byte) []byte {
	two := p.MaxInfoTX > 0xFF || p.MaxInfoRX > 0xFF
	var g []byte
	info := func(id byte, v int) {
		if two {
			g = append(g, id, 2, byte(v>>8), byte(v))
		} else {
			g = append(g, id, 1, byte(v))
		}
	}
	info(pidMaxInfoTX, p.MaxInfoTX)
	info(pidMaxInfoRX, p.MaxInfoRX)
	g = append(g, pidWindowTX, 4, 0, 0, 0, byte(p.WindowTX))
	g = append(g, pidWindowRX, 4, 0, 0, 0, byte(p.WindowRX))
	out := append([]byte{formatID, groupParams, byte(len(g))}, g...)
	return appendUserData(out, userData)
}

// EncodeUserData is an information field of the format identifier and the
// user data subfield only, as a DISC carries it (ISO/IEC 13239 5.5.3.1.4
// Table 9: DISC has no data link layer subfield); nil without user data.
func EncodeUserData(userData []byte) []byte {
	if len(userData) == 0 {
		return nil
	}
	return appendUserData([]byte{formatID}, userData)
}

func appendUserData(out, userData []byte) []byte {
	if len(userData) == 0 {
		return out
	}
	out = append(out, userDataID)
	return append(out, userData...)
}

// ErrParams is returned for an information field that is not a parameter
// list this profile allows; an SNRM carrying one is answered with DM
// (6.4.4.4.3.2).
var ErrParams = errors.New("incorrect parameter list in the information field")

// DecodeParams reads an SNRM, UA or DISC information field. An empty
// field, an absent parameter or a parameter of value 0 means the default.
// Parameters other than 05 to 08 and groups other than the HDLC parameters
// are refused (F-1491). The user data subfield (identifier 0xFF, running to
// the end of the field) is returned; a field of the format identifier and
// user data only is accepted, the parameters then being the defaults
// (ISO/IEC 13239 5.5.3.2).
func DecodeParams(info []byte) (p Params, userData []byte, err error) {
	p = Defaults()
	if len(info) == 0 {
		return p, nil, nil
	}
	if len(info) < 2 || info[0] != formatID {
		return p, nil, fmt.Errorf("%w: no format identifier 0x81", ErrParams)
	}
	if info[1] != groupParams && info[1] != userDataID {
		return p, nil, fmt.Errorf("%w: no group identifier 0x80", ErrParams)
	}
	b := info[1:]
	for len(b) > 0 {
		if b[0] == userDataID {
			userData = append([]byte{}, b[1:]...)
			break
		}
		if len(b) < 2 || int(b[1]) > len(b)-2 {
			return p, nil, fmt.Errorf("%w: a group is cut short", ErrParams)
		}
		gi, g := b[0], b[2:2+int(b[1])]
		b = b[2+int(b[1]):]
		switch gi {
		case groupParams:
		default:
			return p, nil, fmt.Errorf("%w: group %#02x", ErrParams, gi)
		}
		for len(g) > 0 {
			if len(g) < 2 || int(g[1]) > len(g)-2 || g[1] > 4 {
				return p, nil, fmt.Errorf("%w: a parameter is cut short", ErrParams)
			}
			id, v := g[0], 0
			for _, x := range g[2 : 2+int(g[1])] {
				v = v<<8 | int(x)
			}
			g = g[2+int(g[1]):]
			var dst *int
			switch id {
			case pidMaxInfoTX:
				dst = &p.MaxInfoTX
			case pidMaxInfoRX:
				dst = &p.MaxInfoRX
			case pidWindowTX:
				dst = &p.WindowTX
			case pidWindowRX:
				dst = &p.WindowRX
			default:
				return p, nil, fmt.Errorf("%w: parameter %#02x", ErrParams, id)
			}
			if v != 0 {
				*dst = v
			}
		}
	}
	return p, userData, nil
}

// Negotiate is the secondary station's result (6.4.4.4.3.2, Table 8):
// proposed are the primary's values from the SNRM, own the secondary's
// capabilities. Each result is the smaller of the proposal and the
// secondary's value for the opposite direction, from the secondary's point
// of view, as the UA carries it.
func Negotiate(proposed, own Params) Params {
	return Params{
		MaxInfoTX: min(proposed.MaxInfoRX, own.MaxInfoTX),
		MaxInfoRX: min(proposed.MaxInfoTX, own.MaxInfoRX),
		WindowTX:  min(proposed.WindowRX, own.WindowTX),
		WindowRX:  min(proposed.WindowTX, own.WindowRX),
	}
}

// Mirror turns the secondary's view (the UA) into the primary's.
func (p Params) Mirror() Params {
	return Params{MaxInfoTX: p.MaxInfoRX, MaxInfoRX: p.MaxInfoTX, WindowTX: p.WindowRX, WindowRX: p.WindowTX}
}

// bounded keeps values from a peer inside the protocol's range (windows
// within the modulus) and never above what we proposed.
func bounded(got, proposed Params, modulo int) Params {
	c := func(v, lo, hi, want int) int { return max(lo, min(v, hi, want)) }
	mw := maxWindowFor(modulo)
	return Params{
		MaxInfoTX: c(got.MaxInfoTX, 1, MaxInfo, proposed.MaxInfoTX),
		MaxInfoRX: c(got.MaxInfoRX, 1, MaxInfo, proposed.MaxInfoRX),
		WindowTX:  c(got.WindowTX, 1, mw, proposed.WindowTX),
		WindowRX:  c(got.WindowRX, 1, mw, proposed.WindowRX),
	}
}
