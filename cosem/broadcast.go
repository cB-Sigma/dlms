package cosem

// Broadcast requests (DLMS UA Green Book, security control key set bit):
// an unconfirmed request protected with the global broadcast key, so one
// APDU can be accepted by every meter that shares that key. We send it on
// the meter's open association (a multicast or broadcast link address is
// the transport's business and not built); the meter answers nothing.

import (
	"errors"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// InvokeUnconfirmed is invoke-id-and-priority for an unconfirmed request:
// invoke id 1, service class (bit 6) 0, normal priority.
const InvokeUnconfirmed byte = 0x01

// EncodeUnconfirmedSet encodes a set-request-normal for one attribute
// that asks for no answer (invoke-id-and-priority with service class 0),
// as a broadcast set sends it.
func EncodeUnconfirmedSet(class uint16, obis string, attr int8, data *axdr.DlmsData) ([]byte, error) {
	req := gdlms.CreateSetRequestNormal(InvokeUnconfirmed, *gdlms.CreateAttributeDescriptor(class, obis, attr), nil, *data)
	return req.Encode()
}

// Broadcaster runs an unconfirmed application association with a group
// of meters or all meters (IEC 62056-5-3:2023 4.1.5, 7.2.4.3, 7.3.2.1):
// the AARQ proposes response-allowed FALSE and nothing is ever answered,
// so only the client can authenticate (none or low-level security), only
// the client's system title is sent (4.1.3.4), and only unconfirmed
// services are used. Everything is protected with the global broadcast
// key: the initiate request and service-specific or general-glo APDUs
// with the key-set bit, general-ciphering with identified-key 1 (the key-
// set bit 0) and an empty recipient-system-title (6.x, Recipient_System_
// Title). Where the APDUs go (a group or the all-station address) is the
// supporting layer's business: send delivers one APDU there.
type Broadcaster struct {
	Send     func(apdu []byte) error
	Security Security // suite, policy, systemTitle, ak, broadcastKey, ciphering
	Password []byte   // low-level security; nil: no authentication
	IC       uint32   // next invocation counter under the broadcast key
	initReq  []byte
	open     bool
}

// broadcastConformance is the conformance block we propose: get, set,
// action, selective access and block transfer (as gosem proposes).
var broadcastConformance = []byte{0x00, 0x7E, 0x1F}

func (b *Broadcaster) protect(plain, extra []byte, keySet bool) ([]byte, error) {
	policy := b.Security.Policy
	if keySet {
		policy |= SecBroadcastKey
	}
	ic := b.IC
	b.IC++
	return protectAAD(b.Security.Suite, policy, b.Security.BroadcastKey, b.Security.AuthKey, b.Security.SystemTitle, ic, plain, extra)
}

// Associate sends the AARQ of the unconfirmed AA; no AARE is awaited.
func (b *Broadcaster) Associate() error {
	if b.Security.Policy == 0 || b.Security.BroadcastKey == nil || len(b.Security.SystemTitle) != 8 {
		return errors.New("a broadcast association needs protected APDUs, the global broadcast key and our system title")
	}
	// initiateRequest: no dedicated key, response-allowed FALSE, no
	// quality of service, DLMS version 6, conformance, max PDU 1200.
	b.initReq = concat([]byte{0x01, 0x00, 0x01, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00}, broadcastConformance, []byte{0x04, 0xB0})
	p, err := b.protect(b.initReq, nil, true)
	if err != nil {
		return err
	}
	glo := concat([]byte{0x21}, putLen(len(p)), p)
	items := []tlv{
		{0xA1, []byte{0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x03}}, // LN referencing with ciphering
		{0xA6, concat([]byte{0x04, 0x08}, b.Security.SystemTitle)},
	}
	if b.Password != nil {
		items = append(items,
			tlv{0x8A, []byte{0x07, 0x80}},
			tlv{0x8B, []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01}}, // low-level security
			tlv{0xAC, concat([]byte{0x80}, putLen(len(b.Password)), b.Password)})
	}
	items = append(items, tlv{0xBE, concat([]byte{0x04}, putLen(len(glo)), glo)})
	if err := b.Send(encodeTLVs(0x60, items)); err != nil {
		return err
	}
	b.open = true
	return nil
}

// Request sends an unconfirmed set or action request under the broadcast
// key in the configured ciphering form.
func (b *Broadcaster) Request(apdu []byte) error {
	if !b.open {
		return errors.New("no broadcast association")
	}
	tag, ok := gloOf[apdu[0]]
	if !ok || (apdu[0] != 0xC1 && apdu[0] != 0xC3) || len(apdu) < 3 || apdu[2]&0x40 != 0 {
		return errors.New("only unconfirmed set or action requests can be broadcast")
	}
	switch b.Security.Ciphering {
	case CipherGeneralGlo:
		p, err := b.protect(apdu, nil, true)
		if err != nil {
			return err
		}
		return b.Send(encodeGeneralGloDed(TagGeneralGlo, b.Security.SystemTitle, p))
	case CipherGeneral:
		tid, err := newTransactionID()
		if err != nil {
			return err
		}
		h := generalHeader{transactionID: tid, originator: b.Security.SystemTitle, dateTime: cosemNow()} // recipient empty: broadcast
		p, err := b.protect(apdu, h.encode(), false)
		if err != nil {
			return err
		}
		return b.Send((&generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoIdentified, keyID: KeyGlobalBroadcast}, content: p}).encode())
	case CipherGeneralDed:
		return errors.New("a broadcast association has no dedicated key")
	}
	p, err := b.protect(apdu, nil, true)
	if err != nil {
		return err
	}
	return b.Send(concat([]byte{tag}, putLen(len(p)), p))
}

// Release sends the RLRQ, carrying the initiate request protected as in
// the AARQ; an unconfirmed AA's release is not answered.
func (b *Broadcaster) Release() error {
	if !b.open {
		return nil
	}
	b.open = false
	p, err := b.protect(b.initReq, nil, true)
	if err != nil {
		return err
	}
	glo := concat([]byte{0x21}, putLen(len(p)), p)
	return b.Send(encodeTLVs(0x62, []tlv{{0x80, []byte{0x00}}, {0xBE, concat([]byte{0x04}, putLen(len(glo)), glo)}}))
}
