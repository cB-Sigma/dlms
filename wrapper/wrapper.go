// Package wrapper is our DLMS/COSEM transport layer for IP networks
// (IEC 62056-4-7:2015, profile IEC 62056-9-7:2013): the wrapper protocol
// data unit (version, source and destination wPort, length) over TCP,
// where a WPDU may arrive in any number of TCP packets, and over UDP,
// where it fills one datagram. Transport is a gosem transport for the DLMS
// client; ReadWPDU and ParseDatagram serve the push listener and the meter
// simulator. Clause numbers are those of IEC 62056-4-7 unless stated.
package wrapper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the wrapper version (5.3.2).
const Version = 0x0001

// HeaderLen is the wrapper header: four 16-bit fields (5.3.2, Figure 4).
const HeaderLen = 8

// Port is the IANA port of DLMS/COSEM, TCP and UDP (IEC 62056-9-7 clause 6
// NOTE 1).
const Port = 4059

// MaxAPDU is the most the 16-bit length field can carry (TCP).
const MaxAPDU = 0xFFFF

// MaxUDPAPDU is the longest APDU in one UDP datagram over IPv4 (65 507
// octets of UDP data less the wrapper header; 5.2.1, Figure 4 NOTE).
const MaxUDPAPDU = 65507 - HeaderLen

// Reserved wPorts (Table 1).
const (
	NoStation        = 0x0000 // client and server
	ClientManagement = 0x0001 // client management process
	PublicClient     = 0x0010 // public client
	ManagementDevice = 0x0001 // management logical device
	AllStation       = 0x007F // server all-station (broadcast)
	firstServerSAP   = 0x0010 // 0x0002..0x000F are reserved
	lastServerSAP    = 0x007E
	lastClientSAP    = 0x00FF
)

// CheckClient reports a client wPort Table 1 does not open: 1 (client
// management), 0x10 (public) and 0x02 to 0xFF.
func CheckClient(p int) error {
	if p < ClientManagement || p > lastClientSAP {
		return fmt.Errorf("client wPort %d is not 1 to 255 (IEC 62056-4-7 Table 1)", p)
	}
	return nil
}

// CheckServer reports a server wPort that does not name one logical
// device: 1 (management logical device) or 0x10 to 0x7E (Table 1).
func CheckServer(p int) error {
	if p == ManagementDevice || (p >= firstServerSAP && p <= lastServerSAP) {
		return nil
	}
	return fmt.Errorf("server wPort %d is not 1 or 16 to 126 (0 is no-station, 2 to 15 reserved, 127 all-station; IEC 62056-4-7 Table 1)", p)
}

// Header is a wrapper header.
type Header struct {
	Version, Src, Dst, Length uint16
}

// Encode prefixes an APDU with the wrapper header.
func Encode(src, dst uint16, apdu []byte) ([]byte, error) {
	if len(apdu) > MaxAPDU {
		return nil, fmt.Errorf("an APDU of %d octets does not fit the wrapper length field", len(apdu))
	}
	out := make([]byte, HeaderLen, HeaderLen+len(apdu))
	binary.BigEndian.PutUint16(out[0:], Version)
	binary.BigEndian.PutUint16(out[2:], src)
	binary.BigEndian.PutUint16(out[4:], dst)
	binary.BigEndian.PutUint16(out[6:], uint16(len(apdu)))
	return append(out, apdu...), nil
}

func parseHeader(b []byte) Header {
	return Header{
		Version: binary.BigEndian.Uint16(b[0:]),
		Src:     binary.BigEndian.Uint16(b[2:]),
		Dst:     binary.BigEndian.Uint16(b[4:]),
		Length:  binary.BigEndian.Uint16(b[6:]),
	}
}

// ErrVersion is returned for a WPDU of another wrapper version, whose
// header may have another layout (5.3.2).
var ErrVersion = errors.New("not a wrapper version 1 header")

// ReadWPDU reads one WPDU from a TCP stream, however the octets arrive:
// the header, then as many reads as the length needs (6.3.5.4, A.4). A
// WPDU of another version is read past (its length field is trusted) and
// returned with ErrVersion.
func ReadWPDU(r io.Reader) (Header, []byte, error) {
	var hb [HeaderLen]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return Header{}, nil, err
	}
	h := parseHeader(hb[:])
	apdu := make([]byte, h.Length)
	if _, err := io.ReadFull(r, apdu); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return h, nil, err
	}
	if h.Version != Version {
		return h, nil, ErrVersion
	}
	return h, apdu, nil
}

// ParseDatagram reads the WPDU a UDP datagram carries; the APDU fills the
// rest of the datagram exactly (5.2.1, 5.3.3).
func ParseDatagram(b []byte) (Header, []byte, error) {
	if len(b) < HeaderLen {
		return Header{}, nil, errors.New("a datagram shorter than the wrapper header")
	}
	h := parseHeader(b)
	if h.Version != Version {
		return h, nil, ErrVersion
	}
	if int(h.Length) != len(b)-HeaderLen {
		return h, nil, fmt.Errorf("the wrapper length %d does not match the %d octets of the datagram", h.Length, len(b)-HeaderLen)
	}
	return h, b[HeaderLen:], nil
}
