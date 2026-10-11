package cosem

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// Covers: SIG-IPE-2230
func TestOpenNotificationForMBus(t *testing.T) {
	// A data-notification: invoke-id 1, no date-time, body structure
	// {double-long-unsigned 12345, structure {long -5, visible-string "AB"}}.
	plain := []byte{0x0F, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x02, 0x02, 0x06, 0x00, 0x00, 0x30, 0x39, 0x02, 0x02, 0x10, 0xFF, 0xFB, 0x0A, 0x02, 'A', 'B'}
	want := []NotificationValue{{"1", float64(12345)}, {"2.1", float64(-5)}, {"2.2", "AB"}}
	n, err := OpenNotification(plain, nil, nil)
	if err != nil || n.InvokeID != 1 {
		t.Fatalf("plain: %+v %v", n, err)
	}
	if got := n.Values(nil); !reflect.DeepEqual(got, want) {
		t.Errorf("values %#v, want %#v", got, want)
	}
	// The same APDU under general-glo-ciphering, authenticated and
	// encrypted with the meter's global key (suite 0).
	key := bytes.Repeat([]byte{0x11}, 16)
	ak := bytes.Repeat([]byte{0x22}, 16)
	st := []byte("MMM\x00\x00\x00\x00\x01")
	p, err := Protect(0, SecAuthentication|SecEncryption, key, ak, st, 7, plain)
	if err != nil {
		t.Fatal(err)
	}
	glo := encodeGeneralGloDed(TagGeneralGlo, st, p)
	n, err = OpenNotification(glo, &Keys{Key: key, AuthKey: ak}, nil)
	if err != nil || n.IC != 7 || !bytes.Equal(n.SystemTitle, st) || !reflect.DeepEqual(n.Values(nil), want) {
		t.Fatalf("ciphered: %+v %v", n, err)
	}
	if _, err := OpenNotification(glo, nil, nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("without keys: %v", err)
	}
	if _, err := OpenNotification(glo, &Keys{Key: ak, AuthKey: ak}, nil); err == nil {
		t.Error("opened with the wrong key")
	}
	if _, err := OpenNotification([]byte{0xC4, 0x01}, nil, nil); err == nil {
		t.Error("a get-response taken for a notification")
	}
}
