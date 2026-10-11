package cosem

import (
	"bytes"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

func decodeAXDR(t *testing.T, b []byte) axdr.DlmsData {
	t.Helper()
	src := b
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		t.Fatalf("% X: %v", b, err)
	}
	return d
}

// Covers: SIG-IPE-2232
func TestMBusTunnelValue(t *testing.T) {
	// EN 13757-1:2021 9.2.2.2: {rx_type 0 (standard frame), rx_length 7,
	// rx_data: CI 7Ah, short header, one record 03 13 ...}.
	frame := []byte{0x7A, 0x01, 0x00, 0x00, 0x00, 0x03, 0x13}
	d := decodeAXDR(t, append([]byte{0x02, 0x03, 0x16, 0x00, 0x11, byte(len(frame)), 0x09, byte(len(frame))}, frame...))
	m, err := DecodeMBusTunnel(d)
	if err != nil || m.Type != 0 || !bytes.Equal(m.Data, frame) || !m.IsMBusFrame() || m.TypeName() != "mbus_standard_frame" {
		t.Fatalf("%+v %v", m, err)
	}
	// rx_type 33 (encrypted generic datagram, no ack) takes a long-unsigned length.
	d = decodeAXDR(t, []byte{0x02, 0x03, 0x16, 33, 0x12, 0x00, 0x02, 0x09, 0x02, 0xAB, 0xCD})
	if m, err := DecodeMBusTunnel(d); err != nil || m.IsMBusFrame() || m.TypeName() != "encrypted_datagram" || len(m.Data) != 2 {
		t.Errorf("rx_type 33: %+v %v", m, err)
	}
	for _, bad := range [][]byte{
		{0x02, 0x03, 0x16, 33, 0x11, 0x02, 0x09, 0x02, 0xAB, 0xCD},   // unsigned length for 33
		{0x02, 0x03, 0x16, 0x00, 0x11, 0x03, 0x09, 0x02, 0xAB, 0xCD}, // length 3, 2 bytes
		{0x02, 0x02, 0x16, 0x00, 0x11, 0x00},                         // two elements
		{0x02, 0x03, 0x11, 0x00, 0x11, 0x00, 0x09, 0x00},             // rx_type not an enum
	} {
		if m, err := DecodeMBusTunnel(decodeAXDR(t, bad)); err == nil {
			t.Errorf("% X accepted: %+v", bad, m)
		}
	}
}
