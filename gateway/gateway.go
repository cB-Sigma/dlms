// Package gateway is the DLMS/COSEM gateway protocol of IEC 62056-5-3:2023
// annex C: a COSEM APDU exchanged with an end device behind a gateway (a
// data concentrator unit, DCU) is prefixed with a header octet, the network
// ID of the gateway's local network, the length of the physical device
// address and that address (C.2, Figure C.2). The client and server SAPs
// are not in the prefix; they travel in the supporting layer (the wrapper
// wPorts) as for a directly connected meter (C.3). The prefix is outside
// the application layer's protection: security stays end to end (C.5).
package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Header octets (C.2). The ASN.1 of clause 8 reserves tags 230 and 231 for
// the gateway without defining an APDU there.
const (
	// Request is a client's request to an end device, or an end device's
	// request to a client (a data-notification pushed through the gateway).
	Request = 0xE6
	// Response is an end device's response to a client.
	Response = 0xE7
)

// MaxAddress is the longest physical device address: its length is one
// octet (C.2).
const MaxAddress = 255

// Prefix is the gateway prefix of one APDU.
type Prefix struct {
	Header  byte   // Request or Response
	Network byte   // network ID; 0 when the gateway has one network
	Address []byte // physical device address, as the local network's protocol writes it
}

// String names the prefix for messages: network and address in hex.
func (p Prefix) String() string {
	return fmt.Sprintf("network %d address %s", p.Network, FormatAddress(p.Address))
}

// Encode puts the prefix in front of an APDU.
func Encode(p Prefix, apdu []byte) ([]byte, error) {
	if p.Header != Request && p.Header != Response {
		return nil, fmt.Errorf("gateway header %#02x is not E6 or E7", p.Header)
	}
	if len(p.Address) > MaxAddress {
		return nil, fmt.Errorf("a physical device address of %d octets does not fit its one-octet length", len(p.Address))
	}
	out := make([]byte, 0, 3+len(p.Address)+len(apdu))
	out = append(out, p.Header, p.Network, byte(len(p.Address)))
	out = append(out, p.Address...)
	return append(out, apdu...), nil
}

// ErrShort is a prefixed APDU that ends inside its prefix.
var ErrShort = errors.New("gateway prefix: the APDU ends inside the prefix")

// Parse splits a prefixed APDU. ok is false for an APDU without a prefix
// (a plain COSEM APDU); err is set when the header says prefix but the
// octets do not hold one.
func Parse(b []byte) (p Prefix, apdu []byte, ok bool, err error) {
	if len(b) == 0 || (b[0] != Request && b[0] != Response) {
		return Prefix{}, b, false, nil
	}
	if len(b) < 3 || len(b) < 3+int(b[2]) {
		return Prefix{}, nil, true, ErrShort
	}
	n := int(b[2])
	p = Prefix{Header: b[0], Network: b[1], Address: append([]byte(nil), b[3:3+n]...)}
	return p, b[3+n:], true, nil
}

// ParseAddress reads a physical device address written in hex, with or
// without separators (":", "-", "." or spaces) and an optional 0x.
func ParseAddress(s string) ([]byte, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	t = strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(t)
	if t == "" {
		return nil, errors.New("an empty physical device address")
	}
	if len(t)%2 == 1 {
		t = "0" + t
	}
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("physical device address %q is not hex", s)
	}
	if len(b) > MaxAddress {
		return nil, fmt.Errorf("physical device address %q is longer than %d octets", s, MaxAddress)
	}
	return b, nil
}

// FormatAddress writes an address in upper-case hex.
func FormatAddress(a []byte) string { return strings.ToUpper(hex.EncodeToString(a)) }
