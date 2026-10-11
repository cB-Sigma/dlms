package cosem

import (
	"encoding/hex"
	"errors"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// M-Bus frames carried by DLMS/COSEM (EN 13757-1:2021 9.2.2.2): a Data
// object (class 1) whose value is structure {rx_type enum, rx_length
// unsigned (long-unsigned for rx_type 32 to 35), rx_data octet-string}.
// For rx_type 0 to 31 rx_data starts with the M-Bus CI field.

// MBusTunnel is one tunnelled M-Bus frame.
type MBusTunnel struct {
	Type byte   // rx_type
	Data []byte // rx_data
}

// TypeName names rx_type.
func (m MBusTunnel) TypeName() string {
	switch t := m.Type; {
	case t == 0:
		return "mbus_standard_frame"
	case t == 1:
		return "mbus_installation_frame"
	case t <= 9:
		return "mbus_reserved"
	case t <= 31:
		return "reserved"
	case t == 32:
		return "encrypted_datagram_ack"
	case t == 33:
		return "encrypted_datagram"
	case t == 34:
		return "plaintext_datagram_ack"
	case t == 35:
		return "plaintext_datagram"
	}
	return "reserved"
}

// IsMBusFrame reports rx_types whose data is an M-Bus frame from its CI
// field on (0 to 31).
func (m MBusTunnel) IsMBusFrame() bool { return m.Type <= 31 }

// DecodeMBusTunnel reads the value of a tunnelling Data object.
func DecodeMBusTunnel(d axdr.DlmsData) (MBusTunnel, error) {
	var m MBusTunnel
	items, ok := d.Value.([]*axdr.DlmsData)
	if d.Tag != axdr.TagStructure || !ok || len(items) != 3 || items[0] == nil || items[1] == nil || items[2] == nil {
		return m, errors.New("an M-Bus tunnel value is a structure of rx_type, rx_length and rx_data")
	}
	t, ok := Number(*items[0])
	if items[0].Tag != axdr.TagEnum || !ok {
		return m, errors.New("rx_type is not an enum")
	}
	m.Type = byte(t)
	n, ok := Number(*items[1])
	wantTag := axdr.TagUnsigned
	if m.Type >= 32 && m.Type <= 35 {
		wantTag = axdr.TagLongUnsigned
	}
	if !ok || items[1].Tag != wantTag {
		return m, fmt.Errorf("rx_length of rx_type %d is not %v", m.Type, wantTag)
	}
	s, ok := items[2].Value.(string)
	if items[2].Tag != axdr.TagOctetString || !ok {
		return m, errors.New("rx_data is not an octet-string")
	}
	b, err := hex.DecodeString(s) // octet strings decode as hex text
	if err != nil {
		return m, errors.New("rx_data is not an octet-string")
	}
	m.Data = b
	if int(n) != len(m.Data) {
		return m, fmt.Errorf("rx_length %d but rx_data has %d bytes", int(n), len(m.Data))
	}
	return m, nil
}

// TunnelRecord is one data record of a tunnelled M-Bus frame, as the
// M-Bus decoder names it.
type TunnelRecord struct {
	Name    string
	Unit    string
	Value   any
	Quality string
	Labels  []string
}
