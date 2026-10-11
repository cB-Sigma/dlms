package cosem

// Third-party (TP) protection layers (IEC 62056-5-3:2023 4.1.7, 5.7.3,
// Table 26, annex J). A third party, such as a head-end that owns its own
// keys, protects a request for the meter; the client (this package) then
// protects the result for itself, so the meter removes the client's layer
// first and the TP's layers after it. We hold the TP's identity and keys
// and apply every layer:
//
//	request   general-ciphering (or general-glo/ded) by the client
//	            └ general-ciphering by the TP (optional), recipient the meter
//	              └ general-signing by the TP (optional), recipient the meter
//	                └ the xDLMS request
//	response  the client's layer, as above
//	            └ the meter's layers for the TP, the same kinds the TP
//	              applied (general-ciphering outside, general-signing
//	              inside), or, when the meter's policy asks for no
//	              protection for the TP, general-ciphering with neither
//	              authentication nor encryption (annex J.3)
//	              └ the xDLMS response
//
// The TP signs before it ciphers (5.7.3). Its ciphering is general-ciphering
// with a key agreed for the exchange: One-Pass Diffie-Hellman C(1e, 1s)
// (the default, 5.5.5) or the Static Unified Model C(0e, 2s). Identified
// and wrapped keys are for the client only: the global keys and the master
// key are not disclosed to third parties (5.5.2 note, 5.5.4). The
// authentication key is the global one, established outside the exchange
// (Table 26). As every agreed key is new, the invocation counter under it
// is 0 (Table 29), as in the annex I examples.
//
// The unprotected general-ciphering layer carries SC ‖ APDU: a security
// control byte with the A and E bits clear (only the suite in the low
// nibble) and no invocation counter or tag (Figure 32, "no protection").
// It is accepted only for the TP, and only when signedResponses is off:
// our own layer is always protected when the security policy is not 0.
//
// Compression: Table 26 allows it in general-ciphering between a third
// party and the server (compression column "Yes", controlled by the
// security control byte), and Figure 32 shows it with no protection too;
// general-signing carries none (Table 26 "No"). With the meter's
// compression setting (compression.go), a TP ciphering layer we build is
// compressed before it is ciphered when that makes it smaller, and the
// meter's layers for the TP, ciphered or not, are deciphered then
// decompressed. The V.44 settings are the meter's, since the meter is the
// other end of that layer too.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// ThirdParty is the "thirdParty" setting of a meter: the identity on
// whose behalf requests are protected.
type ThirdParty struct {
	// SystemTitle is the TP's system title, 16 hex digits.
	SystemTitle string `json:"systemTitle"`
	// SigningKey is the TP's ECDSA private key (PEM text or a file path)
	// on the suite's curve; the meter holds its certificate. It signs the
	// requests (unless Sign is false) and the ephemeral key of one-pass
	// agreement.
	SigningKey string `json:"signingKey,omitempty"`
	// Sign applies the TP's general-signing layer (default true).
	Sign *bool `json:"sign,omitempty"`
	// Security is the TP's general-ciphering layer: none (default),
	// authenticated, encrypted or authenticated-encrypted.
	Security string `json:"security,omitempty"`
	// GeneralKey is the key agreement of that layer: agreed-one-pass
	// (default) or agreed-static.
	GeneralKey string `json:"generalKey,omitempty"`
	// KeyAgreementKey is the TP's static key agreement private key (PEM
	// or a file path): needed for agreed-static, and to open the meter's
	// one-pass ciphered answers.
	KeyAgreementKey string `json:"keyAgreementKey,omitempty"`
	// AuthenticationKey is the global authentication key the TP uses
	// (hex), when its layer is authenticated.
	AuthenticationKey string `json:"authenticationKey,omitempty"`
	// SignedResponses asks for the meter's answers to be signed for the
	// TP (default: when the TP signs); CipheredResponses asks for them to
	// be ciphered for the TP (default: when the TP ciphers). With neither,
	// an unprotected layer for the TP is accepted (annex J.3).
	SignedResponses   *bool `json:"signedResponses,omitempty"`
	CipheredResponses *bool `json:"cipheredResponses,omitempty"`
}

// ThirdPartyLayer is a validated ThirdParty.
type ThirdPartyLayer struct {
	systemTitle       []byte
	signKey           *ecdsa.PrivateKey
	sign              bool
	policy            byte // secAuthentication and/or secEncryption; 0: no ciphering layer
	generalKey        byte // genKeyOnePass or genKeyStatic
	kaKey             *ecdsa.PrivateKey
	ak                []byte
	signedResponses   bool
	cipheredResponses bool
}

func boolOr(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// Build checks the setting against the rest of the security settings and
// returns the TP layers.
func (tp *ThirdParty) Build(sec *Security) (*ThirdPartyLayer, error) {
	st, err := hex.DecodeString(tp.SystemTitle)
	if err != nil || len(st) != 8 {
		return nil, errors.New("thirdParty.systemTitle must be 16 hex digits")
	}
	if string(st) == string(sec.SystemTitle) {
		return nil, errors.New("thirdParty.systemTitle must differ from our own system title")
	}
	curve, err := sec.Suite.Curve()
	if err != nil {
		return nil, errors.New("thirdParty needs security suite 1 or 2 (its keys are ECDSA and ECDH)")
	}
	out := &ThirdPartyLayer{systemTitle: st, sign: boolOr(tp.Sign, true)}
	if tp.SigningKey != "" {
		if out.signKey, err = parseSigningKey(tp.SigningKey, curve); err != nil {
			return nil, fmt.Errorf("thirdParty.signingKey: %w", err)
		}
	}
	if tp.KeyAgreementKey != "" {
		if out.kaKey, err = parseSigningKey(tp.KeyAgreementKey, curve); err != nil {
			return nil, fmt.Errorf("thirdParty.keyAgreementKey: %w", err)
		}
	}
	switch tp.Security {
	case "", "none":
	case "authenticated":
		out.policy = SecAuthentication
	case "encrypted":
		out.policy = SecEncryption
	case "authenticated-encrypted":
		out.policy = SecAuthentication | SecEncryption
	default:
		return nil, fmt.Errorf("thirdParty.security %q is not none, authenticated, encrypted or authenticated-encrypted", tp.Security)
	}
	switch tp.GeneralKey {
	case "", "agreed-one-pass":
		out.generalKey = GenKeyOnePass
	case "agreed-static":
		out.generalKey = GenKeyStatic
	default:
		return nil, fmt.Errorf("thirdParty.generalKey %q is not agreed-one-pass or agreed-static (a third party holds no global or master key)", tp.GeneralKey)
	}
	if tp.AuthenticationKey != "" {
		if out.ak, err = hex.DecodeString(tp.AuthenticationKey); err != nil || len(out.ak) != sec.Suite.KeyLen() {
			return nil, fmt.Errorf("thirdParty.authenticationKey must be %d bytes of hex", sec.Suite.KeyLen())
		}
	}
	out.signedResponses = boolOr(tp.SignedResponses, out.sign)
	out.cipheredResponses = boolOr(tp.CipheredResponses, out.policy != 0)
	switch {
	case !out.sign && out.policy == 0:
		return nil, errors.New("thirdParty applies no protection: set sign or security")
	case out.sign && out.signKey == nil:
		return nil, errors.New("thirdParty.sign needs thirdParty.signingKey")
	case out.policy&SecAuthentication != 0 && out.ak == nil:
		return nil, errors.New("an authenticated thirdParty layer needs thirdParty.authenticationKey")
	case out.policy != 0 && sec.MeterKAKey == nil:
		return nil, errors.New("a ciphered thirdParty layer needs meterKeyAgreementKey")
	case out.policy != 0 && out.generalKey == GenKeyOnePass && out.signKey == nil:
		return nil, errors.New("thirdParty agreed-one-pass needs thirdParty.signingKey (it signs the ephemeral key)")
	case (out.policy != 0 && out.generalKey == GenKeyStatic || out.cipheredResponses) && out.kaKey == nil:
		return nil, errors.New("thirdParty needs keyAgreementKey for agreed-static or for ciphered responses")
	case out.cipheredResponses && sec.MeterSignKey == nil && out.generalKey == GenKeyOnePass:
		return nil, errors.New("thirdParty ciphered responses with agreed-one-pass need meterSigningKey (the meter signs its ephemeral key)")
	case out.signedResponses && sec.MeterSignKey == nil:
		return nil, errors.New("thirdParty with signed responses needs meterSigningKey")
	case sec.Policy != 0 && sec.Ciphering == CipherServiceSpecific:
		return nil, errors.New("thirdParty needs ciphering general, general-glo or general-ded: service-specific ciphering cannot carry the third party's layers")
	}
	return out, nil
}

// view is the security the TP's own general-ciphering layer uses: its
// keys towards the meter's.
func (tp *ThirdPartyLayer) view(sec *Security) *Security {
	return &Security{Suite: sec.Suite, Policy: tp.policy, SystemTitle: tp.systemTitle, AuthKey: tp.ak, GeneralKey: tp.generalKey,
		SignKey: tp.signKey, KAKey: tp.kaKey, MeterSignKey: sec.MeterSignKey, MeterKAKey: sec.MeterKAKey}
}

func newTransactionID() ([]byte, error) {
	tid := make([]byte, 8)
	_, err := rand.Read(tid)
	return tid, err
}

// tpProtect applies the TP's layers to a request: signing, then ciphering.
func (t *SecureTransport) tpProtect(apdu []byte) ([]byte, error) {
	tp := t.sec.ThirdParty
	out := apdu
	if tp.sign {
		tid, err := newTransactionID()
		if err != nil {
			return nil, err
		}
		g := &generalSigning{generalHeader: generalHeader{transactionID: tid, originator: tp.systemTitle, recipient: t.meterST, dateTime: cosemNow()}, content: out}
		if g.signature, err = signRaw(tp.signKey, g.signed()); err != nil {
			return nil, err
		}
		out = g.encode()
	}
	if tp.policy != 0 {
		tid, err := newTransactionID()
		if err != nil {
			return nil, err
		}
		h := generalHeader{transactionID: tid, originator: tp.systemTitle, recipient: t.meterST, dateTime: cosemNow()}
		key, ki, err := tp.view(&t.sec).originatorKey(h)
		if err != nil {
			return nil, fmt.Errorf("third party: %w", err)
		}
		body, bit := t.sec.compressRequest(out)
		p, err := protectAAD(t.sec.Suite, tp.policy|bit, key, tp.ak, tp.systemTitle, 0, body, h.encode())
		if err != nil {
			return nil, err
		}
		out = (&generalCiphering{generalHeader: h, keyInfo: ki, content: p}).encode()
	}
	return out, nil
}

// forThirdParty says whether apdu is a general-signing or general-ciphering
// layer addressed to our third party.
func (t *SecureTransport) forThirdParty(apdu []byte) bool {
	if t.sec.ThirdParty == nil || len(apdu) == 0 {
		return false
	}
	var recipient []byte
	switch apdu[0] {
	case TagGeneralSigning:
		g, err := decodeGeneralSigning(apdu)
		if err != nil {
			return false
		}
		recipient = g.recipient
	case TagGeneralCiphering:
		g, err := decodeGeneralCiphering(apdu)
		if err != nil {
			return false
		}
		recipient = g.recipient
	default:
		return false
	}
	return string(recipient) == string(t.sec.ThirdParty.systemTitle)
}

// openThirdParty removes the meter's layers for the TP from a response
// and checks they are the kinds asked for.
func (t *SecureTransport) openThirdParty(apdu []byte) ([]byte, error) {
	tp := t.sec.ThirdParty
	if !t.forThirdParty(apdu) {
		return nil, errors.New("the response carries no layer for the third party")
	}
	var signed, ciphered, unprotected bool
	for layer := 0; t.forThirdParty(apdu); layer++ {
		if layer == 2 || unprotected {
			return nil, errors.New("the response has more layers for the third party than it can carry")
		}
		switch apdu[0] {
		case TagGeneralSigning:
			if signed {
				return nil, errors.New("the response is signed twice for the third party")
			}
			g, _ := decodeGeneralSigning(apdu)
			if string(g.originator) != string(t.meterST) {
				return nil, errors.New("the third party's general-signing layer is not from this meter")
			}
			if t.sec.MeterSignKey == nil || !verifyRaw(t.sec.MeterSignKey, g.signed(), g.signature) {
				return nil, errors.New("the meter's signature for the third party does not verify")
			}
			apdu, signed = g.content, true
		default: // general-ciphering
			if ciphered || signed {
				return nil, errors.New("the third party's layers are not in the order signing inside ciphering")
			}
			g, _ := decodeGeneralCiphering(apdu)
			if string(g.originator) != string(t.meterST) {
				return nil, errors.New("the third party's general-ciphering layer is not from this meter")
			}
			if len(g.content) > 0 && g.content[0]&(SecAuthentication|SecEncryption) == 0 {
				plain, err := openNone(t.sec.Suite, t.sec.Compression, g.content)
				if err != nil {
					return nil, fmt.Errorf("the third party's layer: %w", err)
				}
				apdu, unprotected = plain, true
				continue
			}
			if tp.kaKey == nil {
				return nil, errors.New("the meter ciphered its response for the third party, whose key agreement key we do not hold")
			}
			if err := keySetZero(g.content); err != nil {
				return nil, err
			}
			view := tp.view(&t.sec)
			if g.keyInfo == nil || g.keyInfo.choice != keyInfoAgreed {
				return nil, errors.New("the meter's layer for the third party does not agree its key")
			}
			key, err := view.recipientKey(g, nil)
			if err != nil {
				return nil, fmt.Errorf("the third party's layer: %w", err)
			}
			if g.content[0]&(SecAuthentication|SecEncryption) != tp.policy && tp.cipheredResponses {
				return nil, errors.New("the meter protected its response for the third party differently from the request")
			}
			if g.content[0]&SecAuthentication != 0 && tp.ak == nil {
				return nil, errors.New("the meter authenticated its response for the third party, whose authentication key we do not hold")
			}
			plain, _, err := unprotectGeneral(t.sec.Compression, t.sec.Suite, key, nil, tp.ak, g.originator, g.content, g.generalHeader.encode())
			if err != nil {
				return nil, fmt.Errorf("the third party's layer: %w", err)
			}
			apdu, ciphered = plain, true
		}
	}
	switch {
	case tp.signedResponses && !signed:
		return nil, errors.New("the meter did not sign its response for the third party, which the security policy asks for")
	case tp.cipheredResponses && !ciphered:
		return nil, errors.New("the meter did not cipher its response for the third party, which the security policy asks for")
	}
	return apdu, nil
}

// protectNone is the ciphered-content of a general-ciphering APDU that
// applies no protection: SC (A and E clear) ‖ APDU (Figure 32).
func protectNone(suite Suite, plain []byte) []byte {
	return concat([]byte{byte(suite)}, plain)
}

// openNone reads the content protectNone makes; content that is
// authenticated or encrypted is refused, since its key is not ours.
// Compressed content (Figure 32, "compression and no protection") is
// decompressed with comp, and refused when compression is off.
func openNone(suite Suite, comp *CompressionParams, content []byte) ([]byte, error) {
	if len(content) < 2 {
		return nil, errors.New("the unprotected content is empty")
	}
	sc := content[0]
	switch {
	case sc&(SecAuthentication|SecEncryption) != 0:
		return nil, errors.New("it is authenticated or encrypted with a key the third party does not share with us")
	case sc&SecBroadcastKey != 0:
		return nil, errors.New("the key-set bit is set in a general-ciphering APDU")
	case sc&0x0F != byte(suite):
		return nil, fmt.Errorf("the meter used security suite %d, not %d", sc&0x0F, suite)
	case sc&SecCompressed != 0 && suite == 0:
		return nil, ErrCompressed
	case sc&SecCompressed != 0:
		return comp.decompress(content[1:])
	}
	return append([]byte(nil), content[1:]...), nil
}
