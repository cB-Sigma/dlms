// Package hdlc is our IEC 62056-46 (Ed 1.1, 2002+A1:2006) data link layer
// for DLMS/COSEM, the 3-layer connection-oriented profile of IEC 62056-7-6
// (Ed 1.0, 2013): HDLC frame format type 3, extended addressing with upper
// (logical device) and lower (physical device) server addresses, the UNC
// repertoire with UI frames, SNRM/UA parameter negotiation, segmentation,
// windows of up to seven frames, and the 8802-2 LLC header COSEM uses.
// Outside that profile, for ISO/IEC 13239 peers, a link can be numbered
// modulo 128 (SNRME, two-octet control fields, windows up to 127), and UI
// frames can be sent segmented; both are off unless configured.
//
// Client is a gosem transport (gdlms.Transport) for the DLMS client; Station
// is the secondary station the meter simulator runs. Both are built from
// the clauses, not from another implementation; clause numbers are those of
// IEC 62056-46 unless stated.
package hdlc

import (
	"errors"
	"fmt"
)

// Flag opens and closes every frame (6.4.1.2).
const Flag = 0x7E

// formatType3 is the format type sub-field, 1010 binary (6.4.1.3), in the
// high nibble of the first frame format octet.
const formatType3 = 0xA0

// segmentBit is the segmentation bit of the frame format field (6.4.1.3,
// 6.4.4.4.3.6): set on every frame of an MSDU but its last.
const segmentBit = 0x08

// MaxFrameLength is the largest value of the 11-bit frame length sub-field.
const MaxFrameLength = 0x7FF

// MaxInfo is the largest information field (6.4.3.3 NOTE 2).
const MaxInfo = 2030

// DefaultMaxInfo and DefaultWindow are the parameter defaults
// (6.4.4.4.3.2, 6.4.4.10.5, 6.4.4.10.6).
const (
	DefaultMaxInfo = 128
	DefaultWindow  = 1
	MaxWindow      = 7 // modulo 8 numbering (6.4.4.4.3.5)
)

// Reserved addresses (Tables 3 and 4), without the extension bit. One-byte
// values apply to one-octet address parts, two-byte values to the two-octet
// parts of a four-octet server address.
const (
	NoStation         = 0x00 // client, upper and lower
	ClientManagement  = 0x01 // client management process (Table 3)
	PublicClient      = 0x10 // public client, lowest security (Table 3)
	ManagementDevice  = 0x01 // management logical device, upper (Table 4)
	AllStation        = 0x7F // one-byte all-station (broadcast)
	AllStation2       = 0x3FFF
	Calling           = 0x7E // CALLING physical device, lower (Table 4, 6.4.2.4)
	Calling2          = 0x3FFE
	firstIndividual   = 0x10 // 0x01..0x0F (upper 0x02..0x0F) are reserved
	reservedUpperLow  = 0x02
	reservedUpperHigh = 0x0F
)

// AllStationFor is the all-station value of an address part in an address
// field of size octets (1, 2 or 4).
func AllStationFor(size int) int {
	if size == 4 {
		return AllStation2
	}
	return AllStation
}

// CallingFor is the CALLING physical device address for the size.
func CallingFor(size int) int {
	if size == 4 {
		return Calling2
	}
	return Calling
}

// Address is an HDLC address field (6.4.2.2): a client address is one
// octet (Upper only); a server address is one octet (upper only), two
// (upper and lower, seven bits each) or four (upper and lower, fourteen bits
// each).
type Address struct {
	Upper int
	Lower int
	Size  int // octets: 1, 2 or 4
}

// ClientAddress is a one-octet client address.
func ClientAddress(a int) Address { return Address{Upper: a, Size: 1} }

// ServerAddress is a server address of the given size.
func ServerAddress(upper, lower, size int) Address {
	if size == 1 {
		lower = 0
	}
	return Address{Upper: upper, Lower: lower, Size: size}
}

// String is the address in hex, upper/lower when it has a lower part.
func (a Address) String() string {
	if a.Size == 1 {
		return fmt.Sprintf("%#x", a.Upper)
	}
	return fmt.Sprintf("%#x/%#x", a.Upper, a.Lower)
}

// limit is the largest value of one part.
func (a Address) limit() int {
	if a.Size == 4 {
		return 0x3FFF
	}
	return 0x7F
}

// Check reports an address that does not fit its size.
func (a Address) Check() error {
	switch a.Size {
	case 1, 2, 4:
	default:
		return fmt.Errorf("an HDLC address is 1, 2 or 4 octets, not %d", a.Size)
	}
	if a.Upper < 0 || a.Upper > a.limit() || a.Lower < 0 || a.Lower > a.limit() {
		return fmt.Errorf("HDLC address %s does not fit %d octets", a, a.Size)
	}
	return nil
}

// UpperAllStation reports an all-station upper part (6.4.2.3).
func (a Address) UpperAllStation() bool { return a.Upper == a.limit() }

// LowerAllStation reports an all-station lower part (6.4.2.3).
func (a Address) LowerAllStation() bool { return a.Size > 1 && a.Lower == a.limit() }

// Broadcast reports an all-station upper or lower part.
func (a Address) Broadcast() bool { return a.UpperAllStation() || a.LowerAllStation() }

// NoStationPart reports the NO_STATION address in either part.
func (a Address) NoStationPart() bool {
	return a.Upper == NoStation || (a.Size > 1 && a.Lower == NoStation)
}

// Encode is the address field (6.4.2.1): seven bits per octet, most
// significant octet first, the low-order bit 0 on every octet but the
// last, which has it set.
func (a Address) Encode() ([]byte, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	var out []byte
	switch a.Size {
	case 1:
		out = []byte{byte(a.Upper) << 1}
	case 2:
		out = []byte{byte(a.Upper) << 1, byte(a.Lower) << 1}
	case 4:
		out = []byte{byte(a.Upper>>7) << 1, byte(a.Upper&0x7F) << 1, byte(a.Lower>>7) << 1, byte(a.Lower&0x7F) << 1}
	}
	out[len(out)-1] |= 0x01
	return out, nil
}

// DecodeAddress reads an address field from b and returns it with the
// octets it took. Only 1, 2 and 4 octet fields are valid (6.4.2.2); a
// longer or unterminated one is refused.
func DecodeAddress(b []byte) (Address, int, error) {
	n := 0
	for n < len(b) && n < 5 {
		n++
		if b[n-1]&0x01 != 0 {
			break
		}
	}
	if n == 0 || b[n-1]&0x01 == 0 {
		return Address{}, 0, errors.New("the HDLC address field does not end")
	}
	v := func(i int) int { return int(b[i] >> 1) }
	switch n {
	case 1:
		return Address{Upper: v(0), Size: 1}, 1, nil
	case 2:
		return Address{Upper: v(0), Lower: v(1), Size: 2}, 2, nil
	case 4:
		return Address{Upper: v(0)<<7 | v(1), Lower: v(2)<<7 | v(3), Size: 4}, 4, nil
	}
	return Address{}, 0, fmt.Errorf("an HDLC address field of %d octets is not allowed", n)
}

// Frame is an HDLC frame of format type 3 (6.4.1).
type Frame struct {
	Segmented bool // segmentation bit: more of the MSDU follows
	Dest, Src Address
	Control   byte
	Info      []byte // nil: no information field (only an FCS)
	// Extended marks a two-octet control field (an I or S frame under
	// modulo 128 numbering); Control2 is its second octet.
	Extended bool
	Control2 byte
}

// ControlField decodes the frame's control field (one octet, or two when
// Extended).
func (f Frame) ControlField() Control {
	if f.Extended {
		return ParseControlModulo([]byte{f.Control, f.Control2}, Modulo128)
	}
	return ParseControl(f.Control)
}

// rejectedControl is the control field as an FRMR reports it: the second
// octet, if any, in the high byte (ISO/IEC 13239 Figure 18b).
func (f Frame) rejectedControl() uint16 {
	if f.Extended {
		return uint16(f.Control) | uint16(f.Control2)<<8
	}
	return uint16(f.Control)
}

// Encode builds the frame between its flags: format and length, addresses,
// control, HCS, information, FCS (6.4.1.1). A frame without information
// has one check sequence only (6.4.1.6).
func (f Frame) Encode() ([]byte, error) {
	d, err := f.Dest.Encode()
	if err != nil {
		return nil, err
	}
	s, err := f.Src.Encode()
	if err != nil {
		return nil, err
	}
	ctl := []byte{f.Control}
	if f.Extended {
		ctl = append(ctl, f.Control2)
	}
	n := 2 + len(d) + len(s) + len(ctl) + 2
	if len(f.Info) > 0 {
		n += len(f.Info) + 2
	}
	if n > MaxFrameLength {
		return nil, fmt.Errorf("an HDLC frame of %d octets does not fit the 11-bit length", n)
	}
	format := byte(formatType3) | byte(n>>8)&0x07
	if f.Segmented {
		format |= segmentBit
	}
	out := make([]byte, 0, n+2)
	out = append(out, Flag, format, byte(n))
	out = append(out, d...)
	out = append(out, s...)
	out = append(out, ctl...)
	c := FCS(out[1:])
	out = append(out, byte(c), byte(c>>8))
	if len(f.Info) > 0 {
		out = append(out, f.Info...)
		c = FCS(out[1:])
		out = append(out, byte(c), byte(c>>8))
	}
	return append(out, Flag), nil
}

// Errors of Decode. ErrHCS tells the reader to drop what follows the frame
// (6.4.4.9.2: its length cannot be trusted).
var (
	ErrHCS     = errors.New("the HDLC header check sequence is wrong")
	ErrFCS     = errors.New("the HDLC frame check sequence is wrong")
	ErrInvalid = errors.New("not a valid HDLC frame")
)

// Decode reads a frame from flag to flag. It checks the format type, the
// length, the address fields, the HCS and FCS, and refuses a frame whose
// source is the all-station or no-station address (6.4.2.4, 6.4.4.2.3).
// The control field is one octet (modulo 8 numbering).
func Decode(b []byte) (Frame, error) { return DecodeModulo(b, Modulo8) }

// DecodeModulo is Decode for a link numbered modulo 8 or 128; under modulo
// 128 an I or S frame has a two-octet control field (Frame.Extended).
func DecodeModulo(b []byte, modulo int) (Frame, error) {
	var f Frame
	// Shortest: format (2), destination and source (1 each), control, FCS.
	if len(b) < 9 || b[0] != Flag || b[len(b)-1] != Flag {
		return f, fmt.Errorf("%w: not bounded by flags or shorter than seven octets", ErrInvalid)
	}
	if b[1]&0xF0 != formatType3 {
		return f, fmt.Errorf("%w: the format type is not 3", ErrInvalid)
	}
	if n := int(b[1]&0x07)<<8 | int(b[2]); n != len(b)-2 {
		return f, fmt.Errorf("%w: the frame length %d does not match %d octets", ErrInvalid, n, len(b)-2)
	}
	f.Segmented = b[1]&segmentBit != 0
	i := 3
	var err error
	var k int
	if f.Dest, k, err = DecodeAddress(b[i : len(b)-1]); err != nil {
		return f, fmt.Errorf("%w: destination: %v", ErrInvalid, err)
	}
	i += k
	if f.Src, k, err = DecodeAddress(b[i : len(b)-1]); err != nil {
		return f, fmt.Errorf("%w: source: %v", ErrInvalid, err)
	}
	i += k
	if f.Src.UpperAllStation() || f.Src.LowerAllStation() || f.Src.NoStationPart() {
		return f, fmt.Errorf("%w: the source is the all-station or no-station address", ErrInvalid)
	}
	end := len(b) - 1 // the closing flag
	if i+3 > end {
		return f, fmt.Errorf("%w: no control field and check sequence", ErrInvalid)
	}
	f.Control = b[i]
	i++
	if modulo == Modulo128 && extended(f.Control) {
		if i+3 > end {
			return f, fmt.Errorf("%w: no second control octet and check sequence", ErrInvalid)
		}
		f.Extended, f.Control2 = true, b[i]
		i++
	}
	hcs := uint16(b[i]) | uint16(b[i+1])<<8
	if end == i+2 { // no information: the one check sequence is the FCS
		if hcs != FCS(b[1:i]) {
			return f, ErrFCS
		}
		return f, nil
	}
	if hcs != FCS(b[1:i]) {
		return f, ErrHCS
	}
	if end < i+2+1+2 {
		return f, fmt.Errorf("%w: an information field needs an FCS", ErrInvalid)
	}
	fcs := uint16(b[end-2]) | uint16(b[end-1])<<8
	if fcs != FCS(b[1:end-2]) {
		return f, ErrFCS
	}
	f.Info = append([]byte(nil), b[i+2:end-2]...)
	return f, nil
}

// fcsTable is the table of annex A.3, built as A.4 describes (reflected
// polynomial 0x8408 of x^16 + x^12 + x^5 + 1).
var fcsTable = func() (t [256]uint16) {
	for b := range 256 {
		v := uint16(b)
		for range 8 {
			if v&1 != 0 {
				v = v>>1 ^ 0x8408
			} else {
				v >>= 1
			}
		}
		t[b] = v
	}
	return t
}()

// fcsRun runs the check over b from an initial value (annex A.3).
func fcsRun(fcs uint16, b []byte) uint16 {
	for _, c := range b {
		fcs = fcs>>8 ^ fcsTable[byte(fcs)^c]
	}
	return fcs
}

// FCS is the 16-bit frame (and header) check sequence of b: initial value
// 0xFFFF, complemented at the end, sent least significant octet first
// (annex A).
func FCS(b []byte) uint16 { return fcsRun(0xFFFF, b) ^ 0xFFFF }

// GoodFCS reports whether b ends with a correct check sequence: running
// the check over data and FCS leaves 0xF0B8 (annex A.3).
func GoodFCS(b []byte) bool { return fcsRun(0xFFFF, b) == 0xF0B8 }
