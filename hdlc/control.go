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
)

// String is the frame kind's short name.
func (k Kind) String() string {
	return [...]string{"unknown", "I", "RR", "RNR", "SNRM", "DISC", "UA", "DM", "FRMR", "UI"}[k]
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
	}
	return Control{Kind: KindUnknown, PF: pf}
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
func ctl2(k Kind, nr int) byte      { return Control{Kind: k, NR: nr, PF: true}.Byte() }

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
