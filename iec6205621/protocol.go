package iec6205621

import (
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strconv"
	"strings"
)

// IEC 62056-21 messages (clause 6.3): request, identification,
// acknowledgement/option select, data message with its block check
// character, and the programming-mode command messages.

// Control characters.
const (
	SOH = 0x01
	STX = 0x02
	ETX = 0x03
	EOT = 0x04
	ACK = 0x06
	NAK = 0x15
	CR  = 0x0D
	LF  = 0x0A
)

// SignOn is the request message "/?<address>!" CR LF.
func SignOn(address string) []byte { return []byte("/?" + address + "!\r\n") }

// BCC is the block check character: the XOR of every character after the
// first SOH or STX up to and including ETX or EOT.
func BCC(b []byte) byte {
	var x byte
	for _, c := range b {
		x ^= c
	}
	return x & 0x7f
}

// Mode is a protocol mode.
type Mode byte

// Protocol modes (6.4).
const (
	ModeA Mode = 'A'
	ModeB Mode = 'B'
	ModeC Mode = 'C'
	ModeD Mode = 'D' // unidirectional push at 2400 baud (6.4.4)
	ModeE Mode = 'E'
)

// Identification is the meter's identification message (6.3.2).
type Identification struct {
	Manufacturer string // three characters
	// FastReaction: a lower-case third manufacturer letter says the meter
	// answers after 20 ms instead of 200 ms.
	FastReaction bool
	BaudChar     byte
	Mode         Mode
	Baud         int      // the rate the meter proposes (300 when it cannot switch)
	Escapes      []string // the W of each "\W" pair: "2" offers mode E (HDLC), other letters are manufacturer-specific
	ID           string   // model/type identification
}

var modeCBaud = map[byte]int{'0': 300, '1': 600, '2': 1200, '3': 2400, '4': 4800, '5': 9600, '6': 19200}
var modeBBaud = map[byte]int{'A': 600, 'B': 1200, 'C': 2400, 'D': 4800, 'E': 9600, 'F': 19200}

// BaudChar returns the mode C/E character for a rate.
func BaudChar(baud int) (byte, bool) {
	for c, b := range modeCBaud {
		if b == baud {
			return c, true
		}
	}
	return 0, false
}

// ModeDBaud is the fixed rate of mode D (6.4.4), and ModeDBaudChar the
// baud rate character a mode D identification always carries (item 13 d).
const (
	ModeDBaud     = 2400
	ModeDBaudChar = '3'
)

func upper(c byte) bool     { return c >= 'A' && c <= 'Z' }
func printable(c byte) bool { return c >= 0x20 && c <= 0x7e }

// ParseIdentification reads "/XXXZ[\W…]Ident" (CR LF may be present):
// three manufacturer letters (the third may be lower case), the baud
// rate character, optional escape pairs and the identification. The
// characters G, H and I (mode B) and 7, 8 and 9 (modes C and E) are
// reserved and refused; any other printable character but / and ! is
// mode A (item 13). "\" appears only as the start of an escape pair
// (item 14), and only W = 2 selects mode E (6.4.5.1). The identification
// may be longer than the 16 characters of item 14: meters in the field
// exceed it and nothing depends on the length.
func ParseIdentification(s string) (Identification, error) {
	s = strings.TrimRight(s, "\r\n")
	if len(s) < 5 || s[0] != '/' {
		return Identification{}, fmt.Errorf("identification %q does not start with / and a manufacturer and baud character", s)
	}
	if !upper(s[1]) || !upper(s[2]) || !(upper(s[3]) || s[3] >= 'a' && s[3] <= 'z') {
		return Identification{}, fmt.Errorf("identification %q: the manufacturer is not three letters", s)
	}
	id := Identification{Manufacturer: s[1:4], BaudChar: s[4], Baud: 300}
	id.FastReaction = s[3] >= 'a' && s[3] <= 'z'
	rest := s[5:]
	for len(rest) >= 2 && rest[0] == '\\' {
		if w := rest[1]; w == '/' || w == '\\' || w == '!' || !printable(w) {
			return id, fmt.Errorf("identification %q has an invalid escape character", s)
		}
		id.Escapes = append(id.Escapes, rest[1:2])
		rest = rest[2:]
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c == '/' || c == '!' || c == '\\' || !printable(c) {
			return id, fmt.Errorf("identification %q holds %q outside an escape pair", s, c)
		}
	}
	id.ID = rest
	switch z := id.BaudChar; {
	case modeCBaud[z] != 0:
		id.Mode, id.Baud = ModeC, modeCBaud[z]
		for _, e := range id.Escapes {
			if e == "2" {
				id.Mode = ModeE
			}
		}
	case modeBBaud[z] != 0:
		id.Mode, id.Baud = ModeB, modeBBaud[z]
	case z == 'G' || z == 'H' || z == 'I' || z == '7' || z == '8' || z == '9':
		return id, fmt.Errorf("identification %q has the reserved baud rate character %c", s, z)
	case z == '/' || z == '!' || z == '\\' || !printable(z):
		return id, fmt.Errorf("identification %q has an invalid baud rate character", s)
	default:
		id.Mode = ModeA
	}
	return id, nil
}

// ModeEConfirm is the meter's switch confirm for mode E (annex E): ACK 2
// Z 2 CR LF at the new rate, still 7E1, before both ends change to 8N1.
func ModeEConfirm(z byte) []byte { return OptionSelect('2', z, '2') }

// WithParity sets bit 7 of each character to its even parity bit: the
// bytes a 7E1 character sequence gives when read as 8N1 (annex E, Figure
// E.4).
func WithParity(b []byte) []byte {
	out := make([]byte, len(b))
	for i, x := range b {
		x &= 0x7f
		if bits.OnesCount8(x)%2 == 1 {
			x |= 0x80
		}
		out[i] = x
	}
	return out
}

// ValidAddress reports whether a device address fits item 22: up to 32
// digits, letters or spaces.
func ValidAddress(a string) bool {
	if len(a) > 32 {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if !(c >= '0' && c <= '9' || upper(c) || c >= 'a' && c <= 'z' || c == ' ') {
			return false
		}
	}
	return true
}

// SameAddress compares device addresses the way a meter does (item 22):
// leading zeros are ignored, so two all-zero addresses are equal; an
// empty request address is the general address and matches any meter.
func SameAddress(request, meter string) bool {
	if request == "" {
		return true
	}
	return strings.TrimLeft(request, "0") == strings.TrimLeft(meter, "0")
}

// ValidDataField reports whether s may be a data set field: printable,
// at most max characters, none of ( ) / ! and, for values and units, no
// * (6.6).
func ValidDataField(s string, max int, star bool) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !printable(c) || c == '(' || c == ')' || c == '/' || c == '!' || star && c == '*' {
			return false
		}
	}
	return true
}

// Data set limits (6.6): address 16, value 32 (128 in programming mode),
// unit 16 characters.
const (
	MaxAddress          = 16
	MaxValue            = 32
	MaxProgrammingValue = 128
	MaxUnit             = 16
)

// OptionSelect is the acknowledgement/option select message of modes C
// and E: ACK V Z Y CR LF (V protocol control, Z baud character, Y mode
// control: '0' data readout, '1' programming, '2' binary/HDLC).
func OptionSelect(v, z, y byte) []byte { return []byte{ACK, v, z, y, CR, LF} }

// Message is a received message.
type Message struct {
	Kind    byte   // ACK, NAK, STX (data) or SOH (command/operand)
	Command string // SOH messages: "P0", "B0", …
	Data    string // between STX and ETX/EOT
	Partial bool   // ended with EOT: another block follows
	NoBCC   bool   // a readout sent without STX, ETX and BCC
}

// ErrBCC is returned when a block's check character does not match.
var ErrBCC = errors.New("block check character mismatch")

// readLine reads up to and including LF.
func readLine(r io.ByteReader, max int) (string, error) {
	var b strings.Builder
	for b.Len() < max {
		c, err := r.ReadByte()
		if err != nil {
			return b.String(), err
		}
		if c == LF {
			return strings.TrimRight(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
	return b.String(), fmt.Errorf("no line end within %d characters", max)
}

// ReadMessage reads a single ACK or NAK, or a data or command block
// (checking its BCC). withBCC false accepts a block without BCC (some
// mode A meters).
func ReadMessage(r io.ByteReader, withBCC bool) (Message, error) {
	var c byte
	var err error
	for {
		if c, err = r.ReadByte(); err != nil {
			return Message{}, err
		}
		if c == ACK || c == NAK || c == STX || c == SOH {
			break
		}
	}
	if c == ACK || c == NAK {
		return Message{Kind: c}, nil
	}
	return readBlock(r, c, withBCC)
}

// readBlock reads a block after its SOH or STX. The block check
// character covers every character after that first SOH or STX up to
// and including ETX or EOT (6.2, Figure 7).
func readBlock(r io.ByteReader, c byte, withBCC bool) (Message, error) {
	m := Message{Kind: c}
	var body []byte // for the BCC, after the first SOH/STX
	var data strings.Builder
	inData := c == STX
	if c == SOH {
		// Command: two characters, then STX data or ETX.
		for i := 0; i < 2; i++ {
			x, err := r.ReadByte()
			if err != nil {
				return m, err
			}
			body = append(body, x)
			m.Command += string(x)
		}
	}
	for {
		x, err := r.ReadByte()
		if err != nil {
			return m, err
		}
		body = append(body, x)
		switch {
		case x == ETX || x == EOT:
			m.Partial = x == EOT
			m.Data = data.String()
			if !withBCC {
				m.NoBCC = true
				return m, nil
			}
			bcc, err := r.ReadByte()
			if err != nil {
				return m, err
			}
			if bcc != BCC(body) {
				return m, fmt.Errorf("%w: got %02X, want %02X", ErrBCC, bcc, BCC(body))
			}
			return m, nil
		case x == STX && !inData:
			inData = true
		default:
			if data.Len() > 64*1024 {
				return m, errors.New("data block longer than 64 KiB")
			}
			data.WriteByte(x)
		}
	}
}

// readToEnd reads data up to the end character "!" and the CR LF after
// it (the data message without STX, ETX and BCC, 6.5.1).
func readToEnd(r io.ByteReader, first []byte) (string, error) {
	var data strings.Builder
	data.Write(first)
	for {
		c, err := r.ReadByte()
		if err != nil {
			return data.String(), err
		}
		if c == '!' {
			break
		}
		if data.Len() > 64*1024 {
			return data.String(), errors.New("data message longer than 64 KiB")
		}
		data.WriteByte(c)
	}
	for _, want := range []byte{CR, LF} {
		c, err := r.ReadByte()
		if err != nil {
			return data.String(), err
		}
		if c != want {
			return data.String(), fmt.Errorf("data message end %q is not ! CR LF", c)
		}
	}
	return data.String(), nil
}

// ReadDataMessage reads the readout data message after an
// identification (6.3.4, 6.5.1): STX data ! CR LF ETX BCC, or, from a
// meter that sends no block check character, the data block and ! CR LF
// alone. NoBCC tells which came.
func ReadDataMessage(r io.ByteReader) (Message, error) {
	for {
		c, err := r.ReadByte()
		if err != nil {
			return Message{}, err
		}
		switch {
		case c == STX:
			return readBlock(r, STX, true)
		case c == CR || c == LF || c == 0:
			continue // idle line characters before the message
		case c == '!':
			d, err := readToEnd(r, nil)
			return Message{Kind: STX, Data: d, NoBCC: true}, err
		case printable(c):
			d, err := readToEnd(r, []byte{c})
			return Message{Kind: STX, Data: d, NoBCC: true}, err
		default:
			return Message{}, fmt.Errorf("data message starts with %q", c)
		}
	}
}

// Push is a mode D data message (6.4.4): identification, an empty line,
// the data block and ! CR LF, sent at 2400 baud without BCC.
type Push struct {
	Identification Identification
	Data           string
}

// ReadPush waits for the start character "/" and reads one mode D
// message. The identification must carry the mode D baud character "3".
func ReadPush(r io.ByteReader) (Push, error) {
	for {
		c, err := r.ReadByte()
		if err != nil {
			return Push{}, err
		}
		if c == '/' {
			break
		}
	}
	line, err := readLine(r, 64)
	if err != nil {
		return Push{}, fmt.Errorf("reading the identification: %w", err)
	}
	id, err := ParseIdentification("/" + line)
	if err != nil {
		return Push{}, err
	}
	if id.BaudChar != ModeDBaudChar {
		return Push{}, fmt.Errorf("mode D identification has baud character %c, not 3", id.BaudChar)
	}
	id.Mode, id.Baud = ModeD, ModeDBaud
	d, err := readToEnd(r, nil)
	if err != nil {
		return Push{}, fmt.Errorf("reading the mode D data: %w", err)
	}
	return Push{Identification: id, Data: strings.TrimPrefix(d, "\r\n")}, nil
}

// PushMessage builds a mode D message.
func PushMessage(manufacturer, ident, data string) []byte {
	return []byte("/" + manufacturer + string(rune(ModeDBaudChar)) + ident + "\r\n\r\n" + data + "!\r\n")
}

// WakeUpNULs is the number of NUL characters of the annex B.1 wake-up
// message at a rate: 2.2 s of characters (the middle of 2.1 s to 2.3 s),
// ten bits each.
func WakeUpNULs(baud int) int { return baud * 22 / 100 }

// Block builds a data or command block with its BCC: SOH C D STX data
// ETX BCC (command) or STX data ETX BCC (cmd empty).
func Block(cmd string, data string, withSTX bool, end byte) []byte {
	var body []byte
	var out []byte
	if cmd != "" {
		out = append(out, SOH)
		body = append(body, cmd...)
		if withSTX {
			body = append(body, STX)
		}
	} else {
		out = append(out, STX)
	}
	body = append(body, data...)
	body = append(body, end)
	out = append(out, body...)
	return append(out, BCC(body))
}

// DataSet is one "address(value*unit)" item.
type DataSet struct {
	Address string
	Value   string
	Unit    string
	// Extra holds further parenthesised values of the same address (for
	// example the time stamp of a maximum demand).
	Extra []string
}

// ParseDataSets splits a data block into data sets. Lines are CR LF
// separated; a line may hold several data sets; the final "!" line ends
// a readout.
func ParseDataSets(block string) ([]DataSet, error) {
	var out []DataSet
	s := strings.ReplaceAll(block, "\r", "")
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\n' || c == ' ' {
			i++
			continue
		}
		if c == '!' {
			break
		}
		j := strings.IndexByte(s[i:], '(')
		if j < 0 {
			return out, fmt.Errorf("data set %q has no value in parentheses", truncate(s[i:]))
		}
		ds := DataSet{Address: strings.TrimSpace(s[i : i+j])}
		i += j
		first := true
		for i < len(s) && s[i] == '(' {
			k := strings.IndexByte(s[i:], ')')
			if k < 0 {
				return out, fmt.Errorf("data set %q is not closed", truncate(s[i:]))
			}
			v := s[i+1 : i+k]
			i += k + 1
			if first {
				if star := strings.LastIndexByte(v, '*'); star >= 0 {
					ds.Value, ds.Unit = v[:star], v[star+1:]
				} else {
					ds.Value = v
				}
				first = false
			} else {
				ds.Extra = append(ds.Extra, v)
			}
		}
		out = append(out, ds)
	}
	return out, nil
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}

// Number parses a data set value as a number; ok is false for text.
func Number(v string) (float64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	return f, err == nil
}

// ErrorValue reports a meter error message "(ERxx)".
func ErrorValue(ds []DataSet) (string, bool) {
	if len(ds) == 1 && ds[0].Address == "" && strings.HasPrefix(ds[0].Value, "ER") {
		return ds[0].Value, true
	}
	return "", false
}
