package cosem

// General ciphering and general signing APDUs (DLMS UA Green Book, xDLMS
// APDUs; IEC 62056-5-3 security clauses). Field order, A-XDR encoded:
//
//	general-glo-ciphering  [219]  system-title, ciphered-content
//	general-ded-ciphering  [220]  system-title, ciphered-content
//	general-ciphering      [221]  transaction-id, originator-system-title,
//	                              recipient-system-title, date-time,
//	                              other-information, key-info OPTIONAL,
//	                              ciphered-content
//	general-signing        [223]  transaction-id, originator-system-title,
//	                              recipient-system-title, date-time,
//	                              other-information, content, signature
//
// Every field but key-info is an octet string (length ‖ value). key-info
// is a CHOICE (IEC 62056-5-3:2023 Table 11): [0] identified-key (key-id
// enum: 0 global unicast, 1 global broadcast), [1] wrapped-key (kek-id
// enum 0 master key, then the RFC 3394 wrapped key), [2] agreed-key
// (key-parameters: 01 one-pass Diffie–Hellman C(1e, 1s), 02 static unified
// model C(0e, 2s); then the key-ciphered-data: the originator's ephemeral
// public key and its signature over that key for C(1e, 1s), empty for
// C(0e, 2s), where the transaction-id is the nonce).
//
// The ciphered content is SC ‖ IC ‖ body as for service-specific ciphering,
// with the originator's system title in the nonce; its key-set bit is
// always 0, the key being named by key-info (IEC 62056-5-3:2023 Table 29).
// The authenticated data is SC ‖ AK ‖ the five header fields, each with
// its A-XDR length (‖ plaintext when only authenticated), as Table 28 of
// IEC 62056-5-3:2023 lists it. The key derivation, nonce and ciphertext of
// the Table 31 / annex I examples are reproduced exactly (iec6205653_vectors_test.go);
// their tags are not reproduced by this or any nearby reading (finding
// F-171), so the tag layout is still unconfirmed by a published example or
// a meter. The general-signing signature (raw r ‖ s, suite 1 ECDSA
// P-256 with SHA-256, suite 2 P-384 with SHA-384) covers every field from
// transaction-id to content as encoded, and the content may itself be a
// ciphered APDU. A response without key-info uses the key its request's
// transaction established.

import (
	"errors"
	"fmt"
)

// APDU tags.
const (
	TagGeneralGlo       byte = 0xDB
	TagGeneralDed       byte = 0xDC
	TagGeneralCiphering byte = 0xDD
	TagGeneralSigning   byte = 0xDF
)

// Key-info choices and parameters.
const (
	keyInfoIdentified byte = 0
	keyInfoWrapped    byte = 1
	keyInfoAgreed     byte = 2

	agreeOnePass byte = 0x01 // C(1e, 1s ECC CDH)
	agreeStatic  byte = 0x02 // C(0e, 2s ECC CDH)
)

// Key IDs of identified-key and of the security setup key methods.
const (
	KeyGlobalUnicast   byte = 0
	KeyGlobalBroadcast byte = 1
	KeyAuthentication  byte = 2
	KeyMaster          byte = 3
)

// keyInfo is the key-info of a general-ciphering APDU.
type keyInfo struct {
	choice byte
	keyID  byte   // identified-key
	kekID  byte   // wrapped-key (0: master key)
	params []byte // agreed-key key-parameters
	data   []byte // wrapped key, or agreed key-ciphered-data
}

// generalHeader holds the fields general-ciphering and general-signing
// share.
type generalHeader struct {
	transactionID []byte
	originator    []byte
	recipient     []byte
	dateTime      []byte
	other         []byte
}

func (h generalHeader) encode() []byte {
	return concat(octets(h.transactionID), octets(h.originator), octets(h.recipient), octets(h.dateTime), octets(h.other))
}

// generalCiphering is a general-ciphering APDU.
type generalCiphering struct {
	generalHeader
	keyInfo *keyInfo
	content []byte
}

func octets(b []byte) []byte { return concat(putLen(len(b)), b) }

// reader walks an A-XDR encoded APDU.
type reader struct {
	b   []byte
	err error
}

func (r *reader) octets(field string) []byte {
	if r.err != nil {
		return nil
	}
	n, sz, err := getLen(r.b)
	if err != nil || sz+n > len(r.b) {
		r.err = fmt.Errorf("the %s runs past the end of the APDU", field)
		return nil
	}
	v := r.b[sz : sz+n]
	r.b = r.b[sz+n:]
	return v
}

func (r *reader) byte(field string) byte {
	if r.err != nil {
		return 0
	}
	if len(r.b) == 0 {
		r.err = fmt.Errorf("the APDU ends before its %s", field)
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) header() generalHeader {
	return generalHeader{
		transactionID: r.octets("transaction-id"),
		originator:    r.octets("originator-system-title"),
		recipient:     r.octets("recipient-system-title"),
		dateTime:      r.octets("date-time"),
		other:         r.octets("other-information"),
	}
}

func (r *reader) end() error {
	if r.err == nil && len(r.b) != 0 {
		r.err = errors.New("the APDU has bytes after its last field")
	}
	return r.err
}

func (g *generalCiphering) encode() []byte {
	out := concat([]byte{TagGeneralCiphering}, g.generalHeader.encode())
	if k := g.keyInfo; k == nil {
		out = append(out, 0x00)
	} else {
		out = append(out, 0x01, k.choice)
		switch k.choice {
		case keyInfoIdentified:
			out = append(out, k.keyID)
		case keyInfoWrapped:
			out = append(out, k.kekID)
			out = append(out, octets(k.data)...)
		case keyInfoAgreed:
			out = append(out, octets(k.params)...)
			out = append(out, octets(k.data)...)
		}
	}
	return append(out, octets(g.content)...)
}

func decodeGeneralCiphering(apdu []byte) (*generalCiphering, error) {
	if len(apdu) == 0 || apdu[0] != TagGeneralCiphering {
		return nil, errors.New("not a general-ciphering APDU")
	}
	r := &reader{b: apdu[1:]}
	g := &generalCiphering{generalHeader: r.header()}
	switch present := r.byte("key-info"); {
	case r.err != nil, present == 0x00:
	case present != 0x01:
		r.err = errors.New("the key-info presence flag is not 0 or 1")
	default:
		k := &keyInfo{choice: r.byte("key-info choice")}
		switch k.choice {
		case keyInfoIdentified:
			k.keyID = r.byte("key-id")
		case keyInfoWrapped:
			k.kekID = r.byte("kek-id")
			k.data = r.octets("wrapped key")
		case keyInfoAgreed:
			k.params = r.octets("key-parameters")
			k.data = r.octets("key-ciphered-data")
		default:
			if r.err == nil {
				r.err = fmt.Errorf("key-info choice %d is not identified, wrapped or agreed", k.choice)
			}
		}
		g.keyInfo = k
	}
	g.content = r.octets("ciphered-content")
	if err := r.end(); err != nil {
		return nil, err
	}
	return g, nil
}

// encodeGeneralGloDed builds general-glo- or general-ded-ciphering.
func encodeGeneralGloDed(tag byte, systemTitle, content []byte) []byte {
	return concat([]byte{tag}, octets(systemTitle), octets(content))
}

func decodeGeneralGloDed(apdu []byte) (systemTitle, content []byte, err error) {
	if len(apdu) == 0 || (apdu[0] != TagGeneralGlo && apdu[0] != TagGeneralDed) {
		return nil, nil, errors.New("not a general-glo- or general-ded-ciphering APDU")
	}
	r := &reader{b: apdu[1:]}
	systemTitle = r.octets("system-title")
	content = r.octets("ciphered-content")
	return systemTitle, content, r.end()
}

// generalSigning is a general-signing APDU.
type generalSigning struct {
	generalHeader
	content   []byte
	signature []byte
}

// signed is the data the signature covers.
func (g *generalSigning) signed() []byte {
	return concat(g.generalHeader.encode(), octets(g.content))
}

func (g *generalSigning) encode() []byte {
	return concat([]byte{TagGeneralSigning}, g.signed(), octets(g.signature))
}

func decodeGeneralSigning(apdu []byte) (*generalSigning, error) {
	if len(apdu) == 0 || apdu[0] != TagGeneralSigning {
		return nil, errors.New("not a general-signing APDU")
	}
	r := &reader{b: apdu[1:]}
	g := &generalSigning{generalHeader: r.header()}
	g.content = r.octets("content")
	g.signature = r.octets("signature")
	if err := r.end(); err != nil {
		return nil, err
	}
	return g, nil
}
