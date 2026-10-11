package hdlc

import "fmt"

// Kind is a frame type of the UNC repertoire extended with UI (6.4.3.1,
// Table 6).
type Kind int

// Frame kinds.
const (
	KindUnknown Kind = iota
	KindI
	KindRR
	KindRNR
	KindSNRM
	KindDISC
	KindUA
	KindDM
	KindFRMR
	KindUI
	// KindSNRME sets normal response mode with modulo 128 numbering
	// (ISO/IEC 13239 extended mode). IEC 62056-46 does not use it.
	KindSNRME
)

// String is the frame kind's short name.
func (k Kind) String() string {
	return [...]string{"unknown", "I", "RR", "RNR", "SNRM", "DISC", "UA", "DM", "FRMR", "UI", "SNRME"}[k]
}

// Sequence numbering moduli. DLMS (IEC 62056-46) numbers I frames modulo 8
// and so does everything here by default; modulo 128 (ISO/IEC 13239's
// extended numbering, a two-octet control field on I and S frames) is for
// ISO/IEC 13239 peers outside the DLMS profile, set up with SNRME.
const (
	Modulo8   = 8
	Modulo128 = 128
	// MaxWindow128 is the largest window under modulo 128 numbering.
	MaxWindow128 = 127
)

// maxWindowFor is the largest window of a modulus (0 means 8).
func maxWindowFor(modulo int) int {
	if modulo == Modulo128 {
		return MaxWindow128
	}
	return MaxWindow
}

// checkModulo reports a modulus other than 0, 8 and 128.
func checkModulo(m int) error {
	switch m {
	case 0, Modulo8, Modulo128:
		return nil
	}
	return fmt.Errorf("HDLC numbering is modulo 8 or 128, not %d", m)
}

// pfBit is the poll/final bit (Table 7).
const pfBit = 0x10

// Control field values without the P/F bit (Table 7, modulo 8).
const (
	ctrlRR   = 0x01 // RRR P/F 0001
	ctrlRNR  = 0x05 // RRR P/F 0101
	ctrlSNRM = 0x83 // 100 P 0011
	ctrlDISC = 0x43 // 010 P 0011
	ctrlUA   = 0x63 // 011 F 0011
	ctrlDM   = 0x0F // 000 F 1111
	ctrlFRMR = 0x87 // 100 F 0111
	ctrlUI   = 0x03 // 000 P/F 0011
	// SNRME, ISO/IEC 13239 bits 1 to 8 "1111 P 011".
	ctrlSNRME = 0xCF
)

// Control is a decoded control field.
type Control struct {
	Kind   Kind
	NR, NS int // N(R) for I, RR and RNR; N(S) for I
	PF     bool
}

// ParseControl decodes a control field (Table 7).
func ParseControl(c byte) Control {
	pf := c&pfBit != 0
	if c&0x01 == 0 {
		return Control{Kind: KindI, NR: int(c >> 5), NS: int(c>>1) & 7, PF: pf}
	}
	switch c & 0x0F {
	case ctrlRR:
		return Control{Kind: KindRR, NR: int(c >> 5), PF: pf}
	case ctrlRNR:
		return Control{Kind: KindRNR, NR: int(c >> 5), PF: pf}
	}
	switch c &^ pfBit {
	case ctrlSNRM:
		return Control{Kind: KindSNRM, PF: pf}
	case ctrlDISC:
		return Control{Kind: KindDISC, PF: pf}
	case ctrlUA:
		return Control{Kind: KindUA, PF: pf}
	case ctrlDM:
		return Control{Kind: KindDM, PF: pf}
	case ctrlFRMR:
		return Control{Kind: KindFRMR, PF: pf}
	case ctrlUI:
		return Control{Kind: KindUI, PF: pf}
	case ctrlSNRME:
		return Control{Kind: KindSNRME, PF: pf}
	}
	return Control{Kind: KindUnknown, PF: pf}
}

// extended reports a first control octet that starts a two-octet field
// under modulo 128: I and S frames (bits 1 and 2 not both 1).
func extended(first byte) bool { return first&0x03 != 0x03 }

// ParseControlModulo decodes a control field under the numbering of
// modulo (8 or 128). Under modulo 128 an I or S frame has two octets
// (ISO/IEC 13239 extended control field): the first holds N(S), or the S
// bits, from bit 2; the second holds P/F in bit 1 and N(R) in bits 2 to
// 8. Unnumbered frames have one octet in either mode.
func ParseControlModulo(b []byte, modulo int) Control {
	if len(b) == 0 {
		return Control{Kind: KindUnknown}
	}
	if modulo != Modulo128 || !extended(b[0]) {
		return ParseControl(b[0])
	}
	if len(b) < 2 {
		return Control{Kind: KindUnknown}
	}
	nr, pf := int(b[1]>>1), b[1]&0x01 != 0
	if b[0]&0x01 == 0 {
		return Control{Kind: KindI, NS: int(b[0] >> 1), NR: nr, PF: pf}
	}
	switch b[0] {
	case ctrlRR:
		return Control{Kind: KindRR, NR: nr, PF: pf}
	case ctrlRNR:
		return Control{Kind: KindRNR, NR: nr, PF: pf}
	}
	return Control{Kind: KindUnknown, PF: pf}
}

// Encode is the control field under the numbering of modulo: one octet,
// or two for an I or S frame under modulo 128.
func (c Control) Encode(modulo int) []byte {
	if modulo != Modulo128 {
		return []byte{c.Byte()}
	}
	second := byte(c.NR&0x7F) << 1
	if c.PF {
		second |= 0x01
	}
	switch c.Kind {
	case KindI:
		return []byte{byte(c.NS&0x7F) << 1, second}
	case KindRR:
		return []byte{ctrlRR, second}
	case KindRNR:
		return []byte{ctrlRNR, second}
	}
	return []byte{c.Byte()}
}

// set puts the control field into a frame under the numbering of modulo.
func (c Control) set(f *Frame, modulo int) {
	b := c.Encode(modulo)
	f.Control = b[0]
	f.Extended = len(b) == 2
	if f.Extended {
		f.Control2 = b[1]
	} else {
		f.Control2 = 0
	}
}

// Byte encodes the control field.
func (c Control) Byte() byte {
	var b byte
	switch c.Kind {
	case KindI:
		b = byte(c.NR&7)<<5 | byte(c.NS&7)<<1
	case KindRR:
		b = byte(c.NR&7)<<5 | ctrlRR
	case KindRNR:
		b = byte(c.NR&7)<<5 | ctrlRNR
	case KindSNRM:
		b = ctrlSNRM
	case KindDISC:
		b = ctrlDISC
	case KindUA:
		b = ctrlUA
	case KindDM:
		b = ctrlDM
	case KindFRMR:
		b = ctrlFRMR
	case KindUI:
		b = ctrlUI
	case KindSNRME:
		b = ctrlSNRME
	default:
		panic(fmt.Sprintf("hdlc: no control field for %v", c.Kind))
	}
	if c.PF {
		b |= pfBit
	}
	return b
}

// Shorthands for the frames the stations send.
func ctlI(nr, ns int, pf bool) byte { return Control{Kind: KindI, NR: nr, NS: ns, PF: pf}.Byte() }
func ctlRR(nr int, pf bool) byte    { return Control{Kind: KindRR, NR: nr, PF: pf}.Byte() }
func ctl(k Kind, pf bool) byte      { return Control{Kind: k, PF: pf}.Byte() }

// The same as Control values, for either numbering.
func cI(nr, ns int, pf bool) Control { return Control{Kind: KindI, NR: nr, NS: ns, PF: pf} }
func cRR(nr int, pf bool) Control    { return Control{Kind: KindRR, NR: nr, PF: pf} }
func cU(k Kind, pf bool) Control     { return Control{Kind: k, PF: pf} }
func cRNR(nr int) Control            { return Control{Kind: KindRNR, NR: nr, PF: true} }

// LLC headers (5.3.2, Figure 5): destination LSAP 0xE6, source LSAP 0xE6
// for a command (client to server) or 0xE7 for a response, quality 0x00.
// Destination LSAP 0xFF is the broadcast LSAP, never sent but accepted.
var (
	LLCCommand  = []byte{0xE6, 0xE6, 0x00}
	LLCResponse = []byte{0xE6, 0xE7, 0x00}
)

// splitLLC checks and removes the LLC header of an MSDU: a command from a
// client (response false) or a response from a server. ok is false when
// the header is not there, and the MSDU is then discarded (Tables 1 and 2).
func splitLLC(msdu []byte, response bool) (apdu []byte, ok bool) {
	if len(msdu) < 3 || msdu[2] != 0x00 {
		return nil, false
	}
	src := byte(0xE6)
	if response {
		src = 0xE7
	}
	if (msdu[0] != 0xE6 && msdu[0] != 0xFF) || msdu[1] != src {
		return nil, false
	}
	return msdu[3:], true
}
