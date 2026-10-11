package cosem

// DLMS/COSEM application-layer security (DLMS UA Green Book; IEC 62056-5-3
// security clauses), done here rather than in gosem so every combination
// works:
//
//   - security suites 0 (AES-GCM-128), 1 (AES-GCM-128, ECDSA P-256,
//     SHA-256) and 2 (AES-GCM-256, ECDSA P-384, SHA-384);
//   - APDU protection: authentication only, encryption only, or both;
//   - the global unicast key (glo- APDUs) or a dedicated key agreed in the
//     AARQ (ded- APDUs);
//   - service-specific, general-glo-, general-ded- or general ciphering,
//     and general signing on top (general.go).
//
// A protected payload is SC ‖ IC ‖ body. SC is the security control byte
// (0x10 authentication, 0x20 encryption, low nibble the suite), IC the
// invocation counter, and the nonce is the sender's system title ‖ IC.
// Authentication only: body = plaintext ‖ GMAC tag over SC ‖ AK ‖
// plaintext. Encryption only: body = AES-CTR ciphertext (GCM's counter
// stream, no tag). Both: body = GCM ciphertext ‖ tag, with SC ‖ AK as
// additional data. Tags are 12 bytes. These layouts reproduce the worked
// examples of IEC 62056-5-3:2023 (Table 30, annex E), see
// iec6205653_vectors_test.go. An initiate request that carries a dedicated
// key, and the answer to it, are always authenticated and encrypted
// (5.5.1). The key-set bit must be 0 with the dedicated key and in
// general-ciphering (Table 27, Table 29). A ciphered association is
// released with the protected InitiateRequest in the RLRQ and a checked
// InitiateResponse in the RLRE (6.3, annex E.7, E.8); third-party layers
// are in thirdparty.go.
//
// Bit 6 of SC (0x40) says the global broadcast key encrypted the APDU
// instead of the unicast one; such APDUs are opened with the broadcast key
// (configured as broadcastKey, or known once rotated) and sent with it by
// broadcast set commands (unconfirmed, no answer). Bit 7 (0x80) says the
// APDU was compressed (ITU-T V.44, libs/schc/v44) before protection; in
// general-glo, general-ded and general ciphering with suite 1 or 2,
// including a third party's general-ciphering layer (thirdparty.go), it is
// deciphered, then decompressed with the meter's V.44 settings, and our
// requests are compressed before ciphering when configured
// (compression.go). In service-specific ciphering and suite 0 (IEC
// 62056-5-3:2023 Table 26, Table 9) a compressed APDU is refused with
// errCompressed.
//
// gosem is configured without ciphering and only ever sees plain APDUs:
// secureTransport protects what gosem sends and removes the protection
// from what it receives, including the xDLMS initiate exchange inside the
// AARQ and AARE.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Security policy bits of the security control byte.
const (
	SecAuthentication byte = 0x10
	SecEncryption     byte = 0x20
	SecBroadcastKey   byte = 0x40 // key set: the global broadcast key
	SecCompressed     byte = 0x80 // the protected APDU is V.44 compressed
	tagSize                = 12
)

// ErrCompressed refuses APDUs whose security control has the compression
// bit set where no compression can be: IEC 62056-5-3:2023 applies V.44 in
// general-glo, general-ded and general ciphering (5.3.6, Figures 31 and
// 32) and only with suites 1 and 2 (Table 9).
var ErrCompressed = errors.New("the APDU is compressed (security control bit 7, ITU-T V.44) where IEC 62056-5-3:2023 has no compression: only general-glo, general-ded and general ciphering with security suite 1 or 2 carry compressed APDUs (5.3.6, Table 26, Table 9)")

// Suite is a DLMS security suite.
type Suite byte

// KeyLen is the suite's AES key length.
func (s Suite) KeyLen() int {
	if s == 2 {
		return 32
	}
	return 16
}

// Protect applies the security policy to plain, returning SC ‖ IC ‖ body.
func Protect(suite Suite, policy byte, key, ak, systemTitle []byte, ic uint32, plain []byte) ([]byte, error) {
	return protectAAD(suite, policy, key, ak, systemTitle, ic, plain, nil)
}

// protectAAD is protect with more authenticated data after SC ‖ AK (the
// general-ciphering header fields).
func protectAAD(suite Suite, policy byte, key, ak, systemTitle []byte, ic uint32, plain, extra []byte) ([]byte, error) {
	if policy&^(SecAuthentication|SecEncryption|SecBroadcastKey|SecCompressed) != 0 || policy&(SecAuthentication|SecEncryption) == 0 {
		return nil, fmt.Errorf("security policy %#x is not authentication and/or encryption", policy)
	}
	if policy&SecCompressed != 0 && suite == 0 {
		return nil, ErrCompressed
	}
	g, nonce, err := gcmFor(key, systemTitle, ic)
	if err != nil {
		return nil, err
	}
	sc := policy | byte(suite)
	out := make([]byte, 5, 5+len(plain)+tagSize)
	out[0] = sc
	binary.BigEndian.PutUint32(out[1:], ic)
	switch policy &^ (SecBroadcastKey | SecCompressed) {
	case SecAuthentication:
		aad := concat([]byte{sc}, ak, extra, plain)
		out = append(out, plain...)
		return append(out, g.Seal(nil, nonce, nil, aad)...), nil
	case SecEncryption:
		return append(out, ctr(key, nonce, plain)...), nil
	default:
		return append(out, g.Seal(nil, nonce, plain, concat([]byte{sc}, ak, extra))...), nil
	}
}

// Unprotect checks and removes the protection from SC ‖ IC ‖ body sent by
// the holder of systemTitle.
func Unprotect(suite Suite, key, ak, systemTitle, payload []byte) (plain []byte, ic uint32, err error) {
	return unprotectAAD(suite, key, ak, systemTitle, payload, nil)
}

func unprotectAAD(suite Suite, key, ak, systemTitle, payload, extra []byte) (plain []byte, ic uint32, err error) {
	return UnprotectKeys(suite, key, nil, ak, systemTitle, payload, extra)
}

// UnprotectKeys is unprotectAAD that opens APDUs protected with the
// broadcast key (security control bit 6) with bkey. Compressed content is
// refused: callers where compression exists use unprotectGeneral.
func UnprotectKeys(suite Suite, key, bkey, ak, systemTitle, payload, extra []byte) (plain []byte, ic uint32, err error) {
	if len(payload) > 0 && payload[0]&SecCompressed != 0 {
		return nil, 0, ErrCompressed
	}
	return openContent(suite, key, bkey, ak, systemTitle, payload, extra)
}

// unprotectGeneral opens the content of general-glo, general-ded or
// general ciphering: deciphered (and its tag checked) first, then, when
// the compression bit is set, decompressed with the meter's V.44 settings
// (IEC 62056-5-3:2023 Table 28: the protected information is the
// compressed APDU).
func unprotectGeneral(comp *CompressionParams, suite Suite, key, bkey, ak, systemTitle, payload, extra []byte) (plain []byte, ic uint32, err error) {
	compressed := len(payload) > 0 && payload[0]&SecCompressed != 0
	if compressed && suite == 0 {
		return nil, 0, ErrCompressed
	}
	if compressed && comp == nil {
		return nil, 0, ErrCompressionOff
	}
	if plain, ic, err = openContent(suite, key, bkey, ak, systemTitle, payload, extra); err != nil || !compressed {
		return plain, ic, err
	}
	if plain, err = comp.decompress(plain); err != nil {
		return nil, 0, err
	}
	return plain, ic, nil
}

// openContent checks and removes the protection of SC ‖ IC ‖ body; the
// compression bit is left to the caller.
func openContent(suite Suite, key, bkey, ak, systemTitle, payload, extra []byte) (plain []byte, ic uint32, err error) {
	if len(payload) < 5 {
		return nil, 0, errors.New("protected APDU is too short")
	}
	sc := payload[0]
	if sc&0x0F != byte(suite) {
		return nil, 0, fmt.Errorf("the meter used security suite %d, not %d", sc&0x0F, suite)
	}
	if sc&SecBroadcastKey != 0 {
		if bkey == nil {
			return nil, 0, errors.New("the APDU is protected with the global broadcast key, which we do not have (broadcastKey)")
		}
		key = bkey
	}
	ic = binary.BigEndian.Uint32(payload[1:5])
	body := payload[5:]
	g, nonce, err := gcmFor(key, systemTitle, ic)
	if err != nil {
		return nil, 0, err
	}
	switch sc & 0x30 {
	case SecAuthentication:
		if len(body) < tagSize {
			return nil, 0, errors.New("authenticated APDU is too short")
		}
		plain, tag := body[:len(body)-tagSize], body[len(body)-tagSize:]
		// GCM with no plaintext is GMAC: opening the tag alone checks it.
		if _, err := g.Open(nil, nonce, tag, concat([]byte{sc}, ak, extra, plain)); err != nil {
			return nil, 0, errors.New("the APDU's authentication tag does not verify")
		}
		return append([]byte(nil), plain...), ic, nil
	case SecEncryption:
		return ctr(key, nonce, body), ic, nil
	case SecAuthentication | SecEncryption:
		p, err := g.Open(nil, nonce, body, concat([]byte{sc}, ak, extra))
		if err != nil {
			return nil, 0, errors.New("the APDU does not decrypt with our keys")
		}
		return p, ic, nil
	}
	return nil, 0, fmt.Errorf("security control %#x protects nothing", sc)
}

func gcmFor(key, systemTitle []byte, ic uint32) (cipher.AEAD, []byte, error) {
	if len(systemTitle) != 8 {
		return nil, nil, errors.New("system title must be 8 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, systemTitle)
	binary.BigEndian.PutUint32(nonce[8:], ic)
	return g, nonce, nil
}

// ctr is GCM's encryption stream without the tag: AES-CTR starting at
// nonce ‖ 00000002.
func ctr(key, nonce, in []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	copy(iv, nonce)
	iv[15] = 2
	out := make([]byte, len(in))
	cipher.NewCTR(block, iv).XORKeyStream(out, in)
	return out
}

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// APDU tags: plain request/response and their glo- and ded- forms.
var (
	gloOf = map[byte]byte{0xC0: 0xC8, 0xC1: 0xC9, 0xC3: 0xCB, 0x01: 0x21}
	dedOf = map[byte]byte{0xC0: 0xD0, 0xC1: 0xD1, 0xC3: 0xD3}
	// plainOf maps a protected tag the meter sends to its plain tag, and
	// whether it is a ded- APDU.
	plainOf = map[byte]struct {
		tag byte
		ded bool
	}{
		0xCC: {0xC4, false}, 0xCD: {0xC5, false}, 0xCF: {0xC7, false}, 0xCA: {0xC2, false},
		0xD4: {0xC4, true}, 0xD5: {0xC5, true}, 0xD7: {0xC7, true}, 0xD2: {0xC2, true},
		0x28: {0x08, false}, 0x2E: {0x0E, false},
	}
)

// Lengths in AARQ/AARE (BER) and in ciphered APDUs (A-XDR) use the same
// definite form.
func putLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func getLen(b []byte) (n, size int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("missing length")
	}
	switch {
	case b[0] < 0x80:
		return int(b[0]), 1, nil
	case b[0] == 0x81 && len(b) >= 2:
		return int(b[1]), 2, nil
	case b[0] == 0x82 && len(b) >= 3:
		return int(b[1])<<8 | int(b[2]), 3, nil
	}
	return 0, 0, errors.New("unsupported length form")
}

// tlv is one BER element of an AARQ or AARE.
type tlv struct {
	tag byte
	val []byte
}

func parseTLVs(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		n, sz, err := getLen(b[1:])
		if err != nil {
			return nil, err
		}
		if 1+sz+n > len(b) {
			return nil, errors.New("element runs past the end")
		}
		out = append(out, tlv{tag: b[0], val: b[1+sz : 1+sz+n]})
		b = b[1+sz+n:]
	}
	return out, nil
}

func encodeTLVs(tag byte, items []tlv) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it.tag)
		body = append(body, putLen(len(it.val))...)
		body = append(body, it.val...)
	}
	return concat([]byte{tag}, putLen(len(body)), body)
}

// Security is one meter's application-layer security settings.
type Security struct {
	Suite       Suite
	Policy      byte   // 0: APDUs are not protected
	SystemTitle []byte // ours
	Key         []byte // global unicast (block cipher) key
	AuthKey     []byte // authentication key
	Dedicated   bool   // agree a dedicated key per association

	Ciphering  byte   // cipherServiceSpecific, cipherGeneralGlo, cipherGeneralDed or cipherGeneral
	GeneralKey byte   // general-ciphering key-info: genKeyIdentified, genKeyWrapped, genKeyOnePass, genKeyStatic
	MasterKey  []byte // the KEK the meter holds now
	// rootKey is the configured masterKey: it wraps a changed master key
	// in the key store and keys the store's base fingerprint.
	RootKey []byte
	// broadcastKey is the global broadcast key, known once rotated.
	BroadcastKey []byte
	Signing      bool // general-signing on every request and response
	// ECDSA keys: ours and the meter's for signing, ours and the meter's
	// for key agreement.
	SignKey      *ecdsa.PrivateKey
	MeterSignKey *ecdsa.PublicKey
	KAKey        *ecdsa.PrivateKey
	MeterKAKey   *ecdsa.PublicKey
	// tp, when set, signs every request for the meter as a third party
	// inside our own protection (thirdparty.go).
	ThirdParty *ThirdPartyLayer
	// compression, when set, is the meter's V.44 setting (compression.go).
	Compression *CompressionParams
	// Context is the application context the AARQ proposes: ContextAuto
	// (0, the default) names logical name referencing with ciphering
	// whenever our system title is sent (protected APDUs or mechanism 5
	// and above) and without it otherwise; ContextLN and
	// ContextLNCiphering name one or the other whatever is sent.
	Context byte
}

// Application contexts the AARQ can propose (the last arc of the
// application context name, IEC 62056-5-3:2023 7.3.7.1).
const (
	ContextAuto        byte = 0
	ContextLN          byte = 1 // logical name referencing, no ciphering
	ContextLNCiphering byte = 3 // logical name referencing with ciphering
)

// setContext names ctx in an AARQ built by gosem, which always proposes
// the ciphering context when it sends our system title.
func setContext(apdu []byte, ctx byte) ([]byte, error) {
	if len(apdu) < 2 {
		return nil, errors.New("gosem built an AARQ we cannot read")
	}
	n, sz, err := getLen(apdu[1:])
	if err != nil || n < 0 || 1+sz+n > len(apdu) {
		return nil, errors.New("gosem built an AARQ we cannot read")
	}
	items, err := parseTLVs(apdu[1+sz : 1+sz+n])
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		// A1 { 06 07 60 85 74 05 08 01 <ctx> }
		if it.tag == 0xA1 && len(it.val) == 9 && it.val[0] == 0x06 && it.val[1] == 0x07 {
			v := append([]byte(nil), it.val...)
			v[8] = ctx
			items[i].val = v
			return encodeTLVs(0x60, items), nil
		}
	}
	return nil, errors.New("the AARQ carries no application context name")
}

// Ciphering forms.
const (
	CipherServiceSpecific byte = iota
	CipherGeneralGlo
	CipherGeneralDed
	CipherGeneral
)

// General-ciphering key-info choices we send.
const (
	GenKeyIdentified byte = iota
	GenKeyWrapped
	GenKeyOnePass
	GenKeyStatic
)

// SecureTransport protects and unprotects APDUs between gosem and the
// meter, and records what passes 2 and 4 of HLS need.
type SecureTransport struct {
	gdlms.Transport
	sec Security

	mu      sync.Mutex
	nextIC  uint32 // our next global-key invocation counter
	dedKey  []byte // this association's dedicated key
	dedIC   uint32
	meterST []byte
	// expectST, when set, is the system title the device's meter has
	// (configured meterSystemTitle, or the one it named in an earlier
	// association): an AARE naming another is refused, since meters that
	// share keys would otherwise all complete the association.
	expectST    []byte
	stoc        []byte
	lastRecvIC  map[bool]uint32 // per key (dedicated or global) in this association
	lastAction  []byte
	failure     error // why the last incoming APDU was refused
	out         gdlms.DataChannel
	associating bool
	txKeys      map[string][]byte // general-ciphering transaction → content key
	// initReq is the plain xDLMS InitiateRequest of the AARQ, sent again,
	// protected, in the RLRQ; releaseCiphered says it was, and
	// releaseVerified that the RLRE's InitiateResponse deciphered.
	initReq         []byte
	releaseCiphered bool
	releaseVerified bool
}

func newSecureTransport(tr gdlms.Transport, sec Security, firstIC uint32) *SecureTransport {
	return &SecureTransport{Transport: tr, sec: sec, nextIC: firstIC, lastRecvIC: map[bool]uint32{}, txKeys: map[string][]byte{}}
}

// SetLogger passes gosem's logger to the transport below.
func (t *SecureTransport) SetLogger(l *log.Logger) { t.Transport.SetLogger(l) }

// UsedIC is the next invocation counter this transport would have used,
// counting the one a ciphered RLRQ will still take: callers record it
// before the release is sent.
func (t *SecureTransport) UsedIC() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sec.Policy != 0 && t.initReq != nil && !t.releaseCiphered {
		return t.nextIC + 1
	}
	return t.nextIC
}

func (t *SecureTransport) takeIC() uint32 {
	ic := t.nextIC
	t.nextIC++
	return ic
}

// Send protects an outgoing APDU.
func (t *SecureTransport) Send(src []byte) error {
	llc, apdu := splitLLC(src)
	out, err := t.outgoing(apdu)
	if err != nil {
		return err
	}
	return t.Transport.Send(concat(llc, out))
}

func (t *SecureTransport) outgoing(apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return apdu, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch apdu[0] {
	case 0x60:
		return t.aarq(apdu)
	case 0x62:
		return t.rlrq(apdu)
	}
	if _, request := gloOf[apdu[0]]; !request {
		return apdu, nil
	}
	out := apdu
	var err error
	// A third party signs first; our own layers go around its (5.7.3).
	if t.sec.ThirdParty != nil && apdu[0] != 0x01 {
		if out, err = t.tpProtect(apdu); err != nil {
			return nil, err
		}
	}
	if t.sec.Policy != 0 {
		if out, err = t.cipher(out); err != nil {
			return nil, err
		}
	}
	if t.sec.Signing {
		return t.sign(out)
	}
	return out, nil
}

// cipher protects a request in the configured form.
func (t *SecureTransport) cipher(apdu []byte) ([]byte, error) {
	sec := t.sec
	if sec.Ciphering != CipherServiceSpecific {
		// Compress, then cipher (IEC 62056-5-3:2023 Figures 31, 32).
		var bit byte
		apdu, bit = sec.compressRequest(apdu)
		sec.Policy |= bit
	}
	switch sec.Ciphering {
	case CipherGeneralGlo:
		p, err := Protect(sec.Suite, sec.Policy, sec.Key, sec.AuthKey, sec.SystemTitle, t.takeIC(), apdu)
		if err != nil {
			return nil, err
		}
		return encodeGeneralGloDed(TagGeneralGlo, sec.SystemTitle, p), nil
	case CipherGeneralDed:
		if t.dedKey == nil {
			return nil, errors.New("general-ded-ciphering needs a dedicated key, and none was agreed")
		}
		t.dedIC++
		p, err := Protect(sec.Suite, sec.Policy, t.dedKey, sec.AuthKey, sec.SystemTitle, t.dedIC, apdu)
		if err != nil {
			return nil, err
		}
		return encodeGeneralGloDed(TagGeneralDed, sec.SystemTitle, p), nil
	case CipherGeneral:
		return t.generalCipher(apdu, sec.Policy)
	}
	if apdu[0] == TagGeneralSigning {
		return nil, errors.New("service-specific ciphering cannot carry a general-signing APDU; use ciphering general, general-glo or general-ded")
	}
	if t.dedKey != nil {
		if tag, ok := dedOf[apdu[0]]; ok {
			t.dedIC++
			p, err := Protect(sec.Suite, sec.Policy, t.dedKey, sec.AuthKey, sec.SystemTitle, t.dedIC, apdu)
			if err != nil {
				return nil, err
			}
			return concat([]byte{tag}, putLen(len(p)), p), nil
		}
	}
	tag, ok := gloOf[apdu[0]]
	if !ok {
		return apdu, nil
	}
	p, err := Protect(sec.Suite, sec.Policy, sec.Key, sec.AuthKey, sec.SystemTitle, t.takeIC(), apdu)
	if err != nil {
		return nil, err
	}
	return concat([]byte{tag}, putLen(len(p)), p), nil
}

// BroadcastKey is the global broadcast key the transport protects
// broadcasts with (nil: none).
func (t *SecureTransport) BroadcastKey() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sec.BroadcastKey
}

// sendBroadcast protects an unconfirmed request with the global broadcast
// key (glo- form, security control bit 6) and sends it on the open
// association; no answer is expected.
func (t *SecureTransport) sendBroadcast(apdu []byte) error { return t.SendBroadcastIC(apdu, 0) }

// SendBroadcastIC is sendBroadcast with the invocation counter to use
// under the broadcast key (0: the association's next counter).
func (t *SecureTransport) SendBroadcastIC(apdu []byte, ic uint32) error {
	t.mu.Lock()
	sec := t.sec
	if sec.BroadcastKey == nil || sec.Policy == 0 {
		t.mu.Unlock()
		return errors.New("broadcast requests need protected APDUs and the global broadcast key (broadcastKey)")
	}
	tag, ok := gloOf[apdu[0]]
	if !ok || apdu[0] == 0x01 || len(apdu) < 3 || apdu[2]&0x40 != 0 {
		t.mu.Unlock()
		return errors.New("only unconfirmed get, set or action requests can be broadcast")
	}
	if ic == 0 {
		ic = t.takeIC()
	}
	p, err := Protect(sec.Suite, sec.Policy|SecBroadcastKey, sec.BroadcastKey, sec.AuthKey, sec.SystemTitle, ic, apdu)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	out := concat([]byte{tag}, putLen(len(p)), p)
	// Over HDLC an unconfirmed service goes in a UI frame (IEC 62056-7-6
	// 9.1); over the wrapper it is an ordinary WPDU (IEC 62056-9-7 9.1).
	if b, ok := t.Transport.(gdlms.TransportWithBroadcast); ok {
		return b.SendBroadcast(out)
	}
	return t.Transport.Send(out)
}

// newHeader starts a general-ciphering or general-signing header from us
// to the meter.
func (t *SecureTransport) newHeader() (generalHeader, error) {
	tid := make([]byte, 8)
	if _, err := rand.Read(tid); err != nil {
		return generalHeader{}, err
	}
	return generalHeader{transactionID: tid, originator: t.sec.SystemTitle, recipient: t.meterST, dateTime: cosemNow()}, nil
}

// generalCipher protects a request as general-ciphering with the
// configured key-info; policy is the configured one, with the compression
// bit when apdu is compressed.
func (t *SecureTransport) generalCipher(apdu []byte, policy byte) ([]byte, error) {
	sec := t.sec
	h, err := t.newHeader()
	if err != nil {
		return nil, err
	}
	key, ki, err := sec.originatorKey(h)
	if err != nil {
		return nil, err
	}
	p, err := protectAAD(sec.Suite, policy, key, sec.AuthKey, sec.SystemTitle, t.takeIC(), apdu, h.encode())
	if err != nil {
		return nil, err
	}
	t.txKeys[string(h.transactionID)] = key
	return (&generalCiphering{generalHeader: h, keyInfo: ki, content: p}).encode(), nil
}

// originatorKey chooses the content key of a general-ciphering APDU we
// send, and the key-info that tells the recipient how to find it.
func (sec *Security) originatorKey(h generalHeader) ([]byte, *keyInfo, error) {
	switch sec.GeneralKey {
	case GenKeyWrapped:
		key := make([]byte, sec.Suite.KeyLen())
		if _, err := rand.Read(key); err != nil {
			return nil, nil, err
		}
		w, err := WrapKey(sec.MasterKey, key)
		if err != nil {
			return nil, nil, err
		}
		return key, &keyInfo{choice: keyInfoWrapped, kekID: 0, data: w}, nil
	case GenKeyOnePass:
		e, offer, err := ephemeralOffer(sec.SignKey, nil)
		if err != nil {
			return nil, nil, err
		}
		z, err := ecdhZPub(e, sec.MeterKAKey)
		if err != nil {
			return nil, nil, err
		}
		key := kdf(sec.Suite, z, sec.Suite.gcmAlgorithm(), h.originator, h.recipient)
		return key, &keyInfo{choice: keyInfoAgreed, params: []byte{agreeOnePass}, data: offer}, nil
	case GenKeyStatic:
		z, err := ecdhZPub(sec.KAKey, sec.MeterKAKey)
		if err != nil {
			return nil, nil, err
		}
		u, err := staticPartyU(h.originator, h.transactionID)
		if err != nil {
			return nil, nil, err
		}
		key := kdf(sec.Suite, z, sec.Suite.gcmAlgorithm(), u, h.recipient)
		return key, &keyInfo{choice: keyInfoAgreed, params: []byte{agreeStatic}}, nil
	}
	return sec.Key, &keyInfo{choice: keyInfoIdentified, keyID: KeyGlobalUnicast}, nil
}

// recipientKey finds the content key of a general-ciphering APDU sent to
// us; known is the key of the request with the same transaction, for a
// response without key-info.
func (sec *Security) recipientKey(g *generalCiphering, known []byte) ([]byte, error) {
	k := g.keyInfo
	if k == nil {
		if known == nil {
			return nil, errors.New("the general-ciphering APDU has no key-info and answers no transaction of ours")
		}
		return known, nil
	}
	switch k.choice {
	case keyInfoIdentified:
		switch k.keyID {
		case KeyGlobalUnicast:
			return sec.Key, nil
		case KeyGlobalBroadcast:
			// The broadcast key is named by key-info here, not by the
			// security control byte (IEC 62056-5-3:2023 5.5.3).
			if sec.BroadcastKey == nil {
				return nil, errors.New("the general-ciphering APDU names the global broadcast key, which we do not have (broadcastKey)")
			}
			return sec.BroadcastKey, nil
		}
		return nil, fmt.Errorf("identified key %d is neither the global unicast nor the global broadcast key", k.keyID)
	case keyInfoWrapped:
		if k.kekID != 0 || sec.MasterKey == nil {
			return nil, errors.New("the key is wrapped with a master key we do not have")
		}
		return UnwrapKey(sec.MasterKey, k.data)
	case keyInfoAgreed:
		if len(k.params) != 1 || sec.KAKey == nil {
			return nil, errors.New("an agreed key needs our key agreement key")
		}
		switch k.params[0] {
		case agreeOnePass:
			pub, err := openOffer(sec.KAKey.Curve, sec.MeterSignKey, k.data, nil)
			if err != nil {
				return nil, err
			}
			z, err := ecdhZ(sec.KAKey, pub)
			if err != nil {
				return nil, err
			}
			return kdf(sec.Suite, z, sec.Suite.gcmAlgorithm(), g.originator, g.recipient), nil
		case agreeStatic:
			if sec.MeterKAKey == nil {
				return nil, errors.New("an agreed static key needs the meter's key agreement key")
			}
			z, err := ecdhZPub(sec.KAKey, sec.MeterKAKey)
			if err != nil {
				return nil, err
			}
			u, err := staticPartyU(g.originator, g.transactionID)
			if err != nil {
				return nil, err
			}
			return kdf(sec.Suite, z, sec.Suite.gcmAlgorithm(), u, g.recipient), nil
		}
		return nil, fmt.Errorf("key-parameters %X name no agreement scheme we know", k.params)
	}
	return nil, fmt.Errorf("key-info choice %d is unknown", k.choice)
}

// sign wraps an APDU in general-signing with our signing key.
func (t *SecureTransport) sign(apdu []byte) ([]byte, error) {
	h, err := t.newHeader()
	if err != nil {
		return nil, err
	}
	g := &generalSigning{generalHeader: h, content: apdu}
	if g.signature, err = signRaw(t.sec.SignKey, g.signed()); err != nil {
		return nil, err
	}
	return g.encode(), nil
}

// cosemNow is the current time as a COSEM date-time (UTC, deviation 0).
func cosemNow() []byte {
	now := time.Now().UTC()
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, uint16(now.Year()))
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	b[2], b[3], b[4], b[5], b[6], b[7] = byte(now.Month()), byte(now.Day()), byte(wd), byte(now.Hour()), byte(now.Minute()), byte(now.Second())
	b[8] = byte(now.Nanosecond() / 1e7)
	return b // deviation 0000, clock status 00
}

// aarq adds the dedicated key to the xDLMS initiateRequest and protects it
// with the global key (glo-initiateRequest).
func (t *SecureTransport) aarq(apdu []byte) ([]byte, error) {
	t.associating = true
	t.meterST, t.stoc, t.lastAction, t.failure = nil, nil, nil, nil
	t.lastRecvIC = map[bool]uint32{}
	t.dedKey, t.dedIC = nil, 0
	t.initReq, t.releaseCiphered, t.releaseVerified = nil, false, false
	if t.sec.Context != ContextAuto {
		var err error
		if apdu, err = setContext(apdu, t.sec.Context); err != nil {
			return nil, err
		}
	}
	if t.sec.Policy == 0 {
		return apdu, nil
	}
	if len(apdu) < 2 {
		return nil, errors.New("gosem built an AARQ we cannot read")
	}
	n, sz, err := getLen(apdu[1:])
	if err != nil || n < 0 || 1+sz+n > len(apdu) {
		return nil, errors.New("gosem built an AARQ we cannot read")
	}
	items, err := parseTLVs(apdu[1+sz : 1+sz+n])
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		if it.tag != 0xBE || len(it.val) < 2 || it.val[0] != 0x04 {
			continue
		}
		l, s, err := getLen(it.val[1:])
		if err != nil {
			return nil, err
		}
		// The octet string must fit in its element (H-10).
		if l < 0 || 1+s+l > len(it.val) {
			return nil, errors.New("the AARQ carries no xDLMS initiateRequest")
		}
		ir := it.val[1+s : 1+s+l]
		if len(ir) < 2 || ir[0] != 0x01 {
			return nil, errors.New("the AARQ carries no xDLMS initiateRequest")
		}
		if t.sec.Dedicated {
			t.dedKey = make([]byte, t.sec.Suite.KeyLen())
			if _, err := rand.Read(t.dedKey); err != nil {
				return nil, err
			}
			// dedicated-key present, then the rest as gosem built it
			// (ir[1] is its "absent" marker).
			ir = concat([]byte{0x01, 0x01, byte(len(t.dedKey))}, t.dedKey, ir[2:])
		}
		t.initReq = append([]byte(nil), ir...)
		p, err := Protect(t.sec.Suite, initiatePolicy(t.sec.Policy, t.dedKey != nil), t.sec.Key, t.sec.AuthKey, t.sec.SystemTitle, t.takeIC(), ir)
		if err != nil {
			return nil, err
		}
		glo := concat([]byte{0x21}, putLen(len(p)), p)
		items[i].val = concat([]byte{0x04}, putLen(len(glo)), glo)
	}
	return encodeTLVs(0x60, items), nil
}

// initiatePolicy is the protection of the xDLMS initiate request and
// response: authenticated encryption whenever a dedicated key travels in
// it (IEC 62056-5-3:2023 5.5.1), else the configured policy.
func initiatePolicy(policy byte, dedicated bool) byte {
	if dedicated {
		return SecAuthentication | SecEncryption
	}
	return policy
}

// SetReception unprotects incoming APDUs before gosem sees them.
func (t *SecureTransport) SetReception(dc gdlms.DataChannel) {
	t.mu.Lock()
	t.out = dc
	t.mu.Unlock()
	in := make(gdlms.DataChannel, 10)
	t.Transport.SetReception(in)
	go func() {
		for frame := range in {
			llc, apdu := splitLLC(frame)
			t.mu.Lock()
			plain, err := t.incoming(apdu)
			if err != nil {
				t.failure = err
				// Fail closed: gosem gets an APDU it cannot accept.
				plain = []byte{0xD8, 0x01, 0x02}
			}
			out := t.out
			t.mu.Unlock()
			out <- concat(llc, plain)
		}
	}()
}

// responseTags are the plain services the meter answers with.
var responseTags = map[byte]bool{0xC2: true, 0xC4: true, 0xC5: true, 0xC7: true}

func (t *SecureTransport) incoming(apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return apdu, nil
	}
	if apdu[0] == 0x61 {
		return t.aare(apdu)
	}
	if apdu[0] == 0x63 {
		return t.rlre(apdu)
	}
	if apdu[0] == TagGeneralSigning && !t.forThirdParty(apdu) {
		inner, err := t.verifySigned(apdu)
		if err != nil {
			return nil, err
		}
		apdu = inner
	} else if t.sec.Signing && !t.associating && apdu[0] != 0xD8 && apdu[0] != 0x63 {
		return nil, fmt.Errorf("the meter sent an unsigned APDU (tag %#x) where general-signing is required", apdu[0])
	}
	var (
		plain    []byte
		ic       uint32
		ded      bool
		err      error
		ciphered = true // our own layer was removed (it carries the counter)
	)
	switch {
	case t.forThirdParty(apdu):
		// Only the third party's layer: no protection of ours.
		if t.sec.Policy != 0 {
			return nil, errors.New("the meter answered the third party without our protection on a protected association")
		}
		plain, ciphered = apdu, false
	case apdu[0] == TagGeneralGlo, apdu[0] == TagGeneralDed:
		ded = apdu[0] == TagGeneralDed
		st, content, err := decodeGeneralGloDed(apdu)
		if err != nil {
			return nil, err
		}
		if string(st) != string(t.meterST) {
			return nil, errors.New("the general-ciphering APDU names another sender's system title")
		}
		key, bkey := t.sec.Key, t.sec.BroadcastKey
		if ded {
			if t.dedKey == nil {
				return nil, errors.New("the meter used a dedicated key none was agreed for")
			}
			if err := keySetZero(content); err != nil {
				return nil, err
			}
			key, bkey = t.dedKey, nil
		}
		if plain, ic, err = unprotectGeneral(t.sec.Compression, t.sec.Suite, key, bkey, t.sec.AuthKey, st, content, nil); err != nil {
			return nil, err
		}
	case apdu[0] == TagGeneralCiphering:
		if plain, ic, err = t.generalDecipher(apdu); err != nil {
			return nil, err
		}
	default:
		p, protected := plainOf[apdu[0]]
		if !protected {
			if t.sec.Policy != 0 && !t.associating && apdu[0] != 0xD8 && apdu[0] != 0x63 {
				return nil, fmt.Errorf("the meter sent an unprotected APDU (tag %#x) on a protected association", apdu[0])
			}
			if apdu[0] == 0xC7 {
				t.lastAction = append([]byte(nil), apdu...)
			}
			return apdu, nil
		}
		n, sz, err := getLen(apdu[1:])
		if err != nil || 1+sz+n > len(apdu) {
			return nil, errors.New("protected APDU length is wrong")
		}
		key, bkey := t.sec.Key, t.sec.BroadcastKey
		if p.ded {
			if t.dedKey == nil {
				return nil, errors.New("the meter used a dedicated key none was agreed for")
			}
			if err := keySetZero(apdu[1+sz : 1+sz+n]); err != nil {
				return nil, err
			}
			key, bkey = t.dedKey, nil
		}
		if plain, ic, err = UnprotectKeys(t.sec.Suite, key, bkey, t.sec.AuthKey, t.meterST, apdu[1+sz:1+sz+n], nil); err != nil {
			return nil, err
		}
		if len(plain) == 0 || plain[0] != p.tag {
			return nil, errors.New("the protected APDU holds a different service than its tag says")
		}
		ded = p.ded
	}
	if t.sec.ThirdParty != nil {
		if plain, err = t.openThirdParty(plain); err != nil {
			return nil, err
		}
	}
	if len(plain) == 0 || !responseTags[plain[0]] {
		return nil, errors.New("the protected APDU holds no response")
	}
	if ciphered {
		if last, seen := t.lastRecvIC[ded]; seen && ic <= last {
			return nil, fmt.Errorf("the meter repeated invocation counter %d", ic)
		}
		t.lastRecvIC[ded] = ic
	}
	if plain[0] == 0xC7 {
		t.lastAction = append([]byte(nil), plain...)
	}
	return plain, nil
}

// generalDecipher removes general-ciphering from a response.
func (t *SecureTransport) generalDecipher(apdu []byte) ([]byte, uint32, error) {
	g, err := decodeGeneralCiphering(apdu)
	if err != nil {
		return nil, 0, err
	}
	if string(g.originator) != string(t.meterST) || (len(g.recipient) != 0 && string(g.recipient) != string(t.sec.SystemTitle)) {
		return nil, 0, errors.New("the general-ciphering APDU is not from this meter to us")
	}
	known := t.txKeys[string(g.transactionID)]
	delete(t.txKeys, string(g.transactionID))
	key, err := t.sec.recipientKey(g, known)
	if err != nil {
		return nil, 0, err
	}
	if err := keySetZero(g.content); err != nil {
		return nil, 0, err
	}
	plain, ic, err := unprotectGeneral(t.sec.Compression, t.sec.Suite, key, nil, t.sec.AuthKey, g.originator, g.content, g.generalHeader.encode())
	if err != nil {
		return nil, 0, err
	}
	return plain, ic, nil
}

// keySetZero refuses ciphered content whose security control byte has the
// key-set bit set where it must be 0: with the dedicated key and in
// general-ciphering, whose key comes from key-info (IEC 62056-5-3:2023
// Table 27, Table 29 note, 5.5.3).
func keySetZero(content []byte) error {
	if len(content) > 0 && content[0]&SecBroadcastKey != 0 {
		return errors.New("the security control byte names the broadcast key set where the key-set bit must be 0 (dedicated key or general-ciphering)")
	}
	return nil
}

// verifySigned checks a general-signing APDU from the meter and returns
// its content.
func (t *SecureTransport) verifySigned(apdu []byte) ([]byte, error) {
	g, err := decodeGeneralSigning(apdu)
	if err != nil {
		return nil, err
	}
	if t.sec.MeterSignKey == nil {
		return nil, errors.New("the meter signed an APDU and we have no key to check it with")
	}
	if string(g.originator) != string(t.meterST) {
		return nil, errors.New("the general-signing APDU is not from this meter")
	}
	if !verifyRaw(t.sec.MeterSignKey, g.signed(), g.signature) {
		return nil, errors.New("the meter's signature on the APDU does not verify")
	}
	if len(g.content) == 0 {
		return nil, errors.New("the general-signing APDU is empty")
	}
	return g.content, nil
}

// aare records the meter's system title and challenge, removes the
// protection from the initiate response, and lets "authentication
// required" (ACSE service-user diagnostic 14) through as the success it is
// for HLS; pass 3 then completes the authentication.
func (t *SecureTransport) aare(apdu []byte) ([]byte, error) {
	t.associating = false
	n, sz, err := getLen(apdu[1:])
	if err != nil || 1+sz+n > len(apdu) {
		return nil, errors.New("AARE length is wrong")
	}
	items, err := parseTLVs(apdu[1+sz : 1+sz+n])
	if err != nil {
		return nil, err
	}
	accepted := false
	for _, it := range items {
		if it.tag == 0xA2 && len(it.val) == 3 && it.val[2] == 0 {
			accepted = true
		}
	}
	for i, it := range items {
		switch it.tag {
		case 0xA3:
			if accepted && len(it.val) == 5 && it.val[0] == 0xA1 && it.val[4] == 14 {
				items[i].val = []byte{0xA1, 0x03, 0x02, 0x01, 0x00}
			}
		case 0xA4:
			if len(it.val) == 10 && it.val[0] == 0x04 && it.val[1] == 0x08 {
				t.meterST = append([]byte(nil), it.val[2:]...)
				if t.expectST != nil && string(t.meterST) != string(t.expectST) {
					return nil, fmt.Errorf("the meter answering is not this device: its system title is %X, this device's is %X", t.meterST, t.expectST)
				}
			}
		case 0xAA:
			if len(it.val) >= 2 && it.val[0] == 0x80 {
				if l, s, err := getLen(it.val[1:]); err == nil && 1+s+l <= len(it.val) {
					t.stoc = append([]byte(nil), it.val[1+s:1+s+l]...)
				}
			}
		case 0xBE:
			if len(it.val) < 2 || it.val[0] != 0x04 {
				continue
			}
			l, s, err := getLen(it.val[1:])
			if err != nil || 1+s+l > len(it.val) {
				return nil, errors.New("AARE user information length is wrong")
			}
			ui := it.val[1+s : 1+s+l]
			if len(ui) == 0 || (ui[0] != 0x28 && ui[0] != 0x2E) {
				continue
			}
			if t.meterST == nil {
				return nil, errors.New("the AARE is protected but names no meter system title")
			}
			n2, s2, err := getLen(ui[1:])
			if err != nil || 1+s2+n2 > len(ui) {
				return nil, errors.New("protected initiate response length is wrong")
			}
			content := ui[1+s2 : 1+s2+n2]
			if t.dedKey != nil && len(content) > 0 && content[0]&(SecAuthentication|SecEncryption) != SecAuthentication|SecEncryption {
				return nil, errors.New("initiate response: a dedicated key was sent, so the answer must be authenticated and encrypted")
			}
			plain, ic, err := Unprotect(t.sec.Suite, t.sec.Key, t.sec.AuthKey, t.meterST, content)
			if err != nil {
				return nil, fmt.Errorf("initiate response: %w", err)
			}
			t.lastRecvIC[false] = ic
			items[i].val = concat([]byte{0x04}, putLen(len(plain)), plain)
		}
	}
	// gosem reads AARE element lengths as one byte; a plain AARE fits.
	return encodeTLVs(0x61, items), nil
}

// rlrq protects the release (IEC 62056-5-3:2023 6.3, 7.2.5): when the
// association used a ciphered context, the RLRQ carries the InitiateRequest
// of the AARQ again, protected the same way under a fresh invocation
// counter (annex E.7), so the meter can tell the release comes from the
// association's client. Otherwise it goes as gosem built it.
func (t *SecureTransport) rlrq(apdu []byte) ([]byte, error) {
	t.releaseCiphered, t.releaseVerified = false, false
	if t.sec.Policy == 0 || t.initReq == nil {
		return apdu, nil
	}
	p, err := Protect(t.sec.Suite, initiatePolicy(t.sec.Policy, t.dedKey != nil), t.sec.Key, t.sec.AuthKey, t.sec.SystemTitle, t.takeIC(), t.initReq)
	if err != nil {
		return nil, err
	}
	glo := concat([]byte{0x21}, putLen(len(p)), p)
	t.releaseCiphered = true
	return encodeTLVs(0x62, []tlv{
		{tag: 0x80, val: []byte{0x00}}, // reason: normal
		{tag: 0xBE, val: concat([]byte{0x04}, putLen(len(glo)), glo)},
	}), nil
}

// rlre checks the RLRE: a ciphered InitiateResponse in it must decipher
// with the global key under a counter not seen before, or the RLRE is
// discarded (6.3, 7.2.5); gosem gets the RLRE without it. An RLRE with no
// InitiateResponse after a ciphered RLRQ still releases the association,
// but is not counted as verified.
func (t *SecureTransport) rlre(apdu []byte) ([]byte, error) {
	n, sz, err := getLen(apdu[1:])
	if err != nil || 1+sz+n > len(apdu) {
		return nil, errors.New("RLRE length is wrong")
	}
	items, err := parseTLVs(apdu[1+sz : 1+sz+n])
	if err != nil {
		return nil, err
	}
	var keep []tlv
	for _, it := range items {
		if it.tag != 0xBE {
			keep = append(keep, it)
			continue
		}
		if len(it.val) < 2 || it.val[0] != 0x04 {
			return nil, errors.New("RLRE user-information is not an octet string")
		}
		l, s, err := getLen(it.val[1:])
		if err != nil || 1+s+l > len(it.val) {
			return nil, errors.New("RLRE user-information length is wrong")
		}
		ui := it.val[1+s : 1+s+l]
		if len(ui) == 0 || ui[0] != 0x28 {
			return nil, errors.New("the RLRE's user-information is not a ciphered InitiateResponse")
		}
		if !t.releaseCiphered || t.meterST == nil {
			return nil, errors.New("the RLRE carries a ciphered InitiateResponse to a release we did not cipher")
		}
		n2, s2, err := getLen(ui[1:])
		if err != nil || 1+s2+n2 > len(ui) {
			return nil, errors.New("the RLRE's ciphered InitiateResponse length is wrong")
		}
		content := ui[1+s2 : 1+s2+n2]
		if t.dedKey != nil && len(content) > 0 && content[0]&(SecAuthentication|SecEncryption) != SecAuthentication|SecEncryption {
			return nil, errors.New("RLRE: a dedicated key was used, so the InitiateResponse must be authenticated and encrypted")
		}
		plain, ic, err := Unprotect(t.sec.Suite, t.sec.Key, t.sec.AuthKey, t.meterST, content)
		if err != nil {
			return nil, fmt.Errorf("RLRE discarded: %w", err)
		}
		if len(plain) == 0 || plain[0] != 0x08 {
			return nil, errors.New("RLRE discarded: it does not carry an InitiateResponse")
		}
		if last, seen := t.lastRecvIC[false]; seen && ic <= last {
			return nil, fmt.Errorf("RLRE discarded: the meter repeated invocation counter %d", ic)
		}
		t.lastRecvIC[false] = ic
		t.releaseVerified = true
	}
	return encodeTLVs(0x63, keep), nil
}

// Release says whether the last release was ciphered and whether the
// meter's RLRE proved it deciphered it.
func (t *SecureTransport) Release() (ciphered, verified bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.releaseCiphered, t.releaseVerified
}

// Challenge is the system title and the challenge (StoC) of the meter's
// AARE.
func (t *SecureTransport) Challenge() (meterST, stoc []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.meterST, t.stoc
}

// TakeAction returns the last action-response seen, plain, and forgets
// it (gosem does not return an action's data).
func (t *SecureTransport) TakeAction() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.lastAction
	t.lastAction = nil
	return a
}

// LastFailure is why the last incoming APDU was refused (nil: none was).
func (t *SecureTransport) LastFailure() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failure
}

// splitLLC separates the IEC 8802-2 LLC header HDLC frames carry.
func splitLLC(b []byte) (llc, apdu []byte) {
	if len(b) >= 3 && (b[0] == 0xE6 || b[0] == 0xE7) && b[1] == 0xE7 && b[2] == 0x00 {
		return b[:3], b[3:]
	}
	return nil, b
}
