package cosem

// High-level security (HLS) authentication: passes 3 and 4 of the
// four-pass exchange, for authentication mechanisms 2 to 7.
//
//	pass 1  AARQ: mechanism name and our challenge CtoS
//	pass 2  AARE: "authentication required" and the meter's challenge StoC
//	pass 3  we invoke reply_to_HLS_authentication (class 15 method 1,
//	        0.0.40.0.0.255) with f(StoC)
//	pass 4  the meter returns f(CtoS) and we check it
//
// f by mechanism (secret = the HLS secret; ST = system title):
//
//	2 HLS (manufacturer specific): AES-128-ECB of the challenge, zero
//	  padded, with the secret as the key (the common reading; confirm per
//	  make)
//	3 HLS-MD5:     MD5(challenge ‖ secret)
//	4 HLS-SHA1:    SHA-1(challenge ‖ secret)
//	5 HLS-GMAC:    SC ‖ IC ‖ GMAC(SC ‖ AK ‖ challenge), nonce = sender ST ‖ IC
//	6 HLS-SHA256:  SHA-256(secret ‖ sender ST ‖ receiver ST ‖ challenge
//	               answered ‖ own challenge)
//	7 HLS-ECDSA:   ECDSA signature (raw r ‖ s) with the sender's key over
//	               sender ST ‖ receiver ST ‖ challenge answered ‖ own
//	               challenge; P-256/SHA-256 in suite 1, P-384/SHA-384 in
//	               suite 2
//
// MD5 and SHA-1 are weak and are offered only for meters that know
// nothing better.

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/iotsec"
)

// Authentication mechanism IDs (the last arc of the mechanism name).
const (
	MechNone   = 0
	MechLow    = 1
	MechHLS    = 2
	MechMD5    = 3
	MechSHA1   = 4
	MechGMAC   = 5
	MechSHA256 = 6
	MechECDSA  = 7
)

// MechanismNames maps the names of authentication mechanisms (as
// SecurityConfig.Authentication takes them) to their IDs.
var MechanismNames = map[string]byte{
	"": MechNone, "none": MechNone, "low": MechLow,
	"hls": MechHLS, "hls-aes": MechHLS,
	"hls-md5": MechMD5, "hls-sha1": MechSHA1,
	"high": MechGMAC, "hls-gmac": MechGMAC, "gmac": MechGMAC,
	"hls-sha256": MechSHA256, "hls-ecdsa": MechECDSA, "ecdsa": MechECDSA,
}

// MechanismAlgorithm describes the cryptography of an authentication
// mechanism for a crypto policy (iotsec.CryptoPolicy): mechanism 2 is
// AES-128 in ECB mode, 3 MD5, 4 SHA-1, 5 AES-GMAC, 6 SHA-256 and 7 ECDSA.
// none and low use none (ok is false).
func MechanismAlgorithm(mech byte) (alg iotsec.Algorithm, ok bool) {
	switch mech {
	case MechHLS:
		return iotsec.Algorithm{Kind: iotsec.AlgCipher, Name: "AES-128-ECB", KeyBits: 128}, true
	case MechMD5:
		return iotsec.Algorithm{Kind: iotsec.AlgHash, Name: "MD5"}, true
	case MechSHA1:
		return iotsec.Algorithm{Kind: iotsec.AlgHash, Name: "SHA-1"}, true
	case MechGMAC:
		return iotsec.Algorithm{Kind: iotsec.AlgMAC, Name: "AES-GMAC", TagBits: 8 * tagSize}, true
	case MechSHA256:
		return iotsec.Algorithm{Kind: iotsec.AlgHash, Name: "SHA-256"}, true
	case MechECDSA:
		return iotsec.Algorithm{Kind: iotsec.AlgPublicKey, Name: "ECDSA"}, true
	}
	return iotsec.Algorithm{}, false
}

// HLS is everything passes 3 and 4 need.
type HLS struct {
	Mechanism byte
	Secret    []byte
	Security  Security
	SignKey   *ecdsa.PrivateKey // ours (mechanism 7)
	MeterKey  *ecdsa.PublicKey  // the meter's (mechanism 7)
}

// Answer is f(challenge), the HLS pass 3 or 4 answer of the party whose
// system title is systemTitle to the challenge of the party peerST, which
// answers ownChallenge (the challenge this party issued); ic is the
// invocation counter of a mechanism 5 answer. Either side uses it: a
// client answering the meter's StoC, a server answering the client's
// CtoS.
func (h *HLS) Answer(systemTitle, peerST, challenge, ownChallenge []byte, ic uint32) ([]byte, error) {
	return h.answer(systemTitle, peerST, challenge, ownChallenge, ic)
}

// Check verifies got, the peer's answer to our challenge ourChallenge
// (the peer's own challenge was peerChallenge). For mechanism 7, MeterKey
// is the peer's public key whichever side the peer is.
func (h *HLS) Check(ourST, peerST, ourChallenge, peerChallenge, got []byte) error {
	return h.check(ourST, peerST, ourChallenge, peerChallenge, got)
}

// answer computes f(challenge) as the party with systemTitle, towards
// peerST, who issued ownChallenge.
func (h *HLS) answer(systemTitle, peerST, challenge, ownChallenge []byte, ic uint32) ([]byte, error) {
	switch h.Mechanism {
	case MechHLS:
		return aesECB(h.Secret, challenge)
	case MechMD5:
		s := md5.Sum(concat(challenge, h.Secret))
		return s[:], nil
	case MechSHA1:
		s := sha1.Sum(concat(challenge, h.Secret))
		return s[:], nil
	case MechGMAC:
		sc := SecAuthentication | byte(h.Security.Suite)
		g, nonce, err := gcmFor(h.Security.Key, systemTitle, ic)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 5)
		out[0] = sc
		binary.BigEndian.PutUint32(out[1:], ic)
		return append(out, g.Seal(nil, nonce, nil, concat([]byte{sc}, h.Security.AuthKey, challenge))...), nil
	case MechSHA256:
		s := sha256.Sum256(concat(h.Secret, systemTitle, peerST, challenge, ownChallenge))
		return s[:], nil
	case MechECDSA:
		digest := h.digest(concat(systemTitle, peerST, challenge, ownChallenge))
		r, s, err := ecdsa.Sign(rand.Reader, h.SignKey, digest)
		if err != nil {
			return nil, err
		}
		n := (h.SignKey.Curve.Params().BitSize + 7) / 8
		return concat(fixed(r, n), fixed(s, n)), nil
	}
	return nil, fmt.Errorf("mechanism %d has no challenge answer", h.Mechanism)
}

// check verifies the meter's f(CtoS).
func (h *HLS) check(ourST, meterST, ctos, stoc, got []byte) error {
	bad := errors.New("the meter's answer to our challenge does not verify; it does not hold the same secret or keys")
	switch h.Mechanism {
	case MechGMAC:
		if len(got) != 5+tagSize || got[0] != SecAuthentication|byte(h.Security.Suite) {
			return errors.New("the meter's answer to our challenge is not an HLS-GMAC answer")
		}
		want, err := h.answer(meterST, ourST, ctos, stoc, binary.BigEndian.Uint32(got[1:5]))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(want, got) != 1 {
			return bad
		}
		return nil
	case MechECDSA:
		n := (h.MeterKey.Curve.Params().BitSize + 7) / 8
		if len(got) != 2*n {
			return errors.New("the meter's signature has the wrong length for its curve")
		}
		digest := h.digest(concat(meterST, ourST, ctos, stoc))
		if !ecdsa.Verify(h.MeterKey, digest, new(big.Int).SetBytes(got[:n]), new(big.Int).SetBytes(got[n:])) {
			return bad
		}
		return nil
	}
	want, err := h.answer(meterST, ourST, ctos, stoc, 0)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return bad
	}
	return nil
}

func (h *HLS) digest(b []byte) []byte {
	if h.Security.Suite == 2 {
		s := sha512.Sum384(b)
		return s[:]
	}
	s := sha256.Sum256(b)
	return s[:]
}

func fixed(v *big.Int, n int) []byte {
	out := make([]byte, n)
	v.FillBytes(out)
	return out
}

func aesECB(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("the HLS secret must be an AES key (16, 24 or 32 bytes): %w", err)
	}
	padded := make([]byte, (len(data)+15)/16*16)
	copy(padded, data)
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(padded[i:i+16], padded[i:i+16])
	}
	return padded, nil
}

// completeHLS runs passes 3 and 4 over an association gosem has opened.
func completeHLS(c gdlms.Client, t *SecureTransport, h *HLS, ctos []byte) error {
	meterST, stoc := t.Challenge()
	if len(stoc) == 0 {
		return errors.New("the meter's AARE carried no challenge; it does not offer this mechanism on this client address")
	}
	if err := checkStoC(h.Mechanism, stoc, ctos); err != nil {
		return err
	}
	if (h.Mechanism >= MechGMAC) && len(meterST) != 8 {
		return errors.New("the meter's AARE carried no system title, which this mechanism needs")
	}
	var ic uint32
	if h.Mechanism == MechGMAC {
		t.mu.Lock()
		ic = t.takeIC()
		t.mu.Unlock()
	}
	ans, err := h.answer(h.Security.SystemTitle, meterST, stoc, ctos, ic)
	if err != nil {
		return err
	}
	_ = t.TakeAction()
	t.setEstablishing(true)
	defer t.setEstablishing(false)
	mth := gdlms.CreateMethodDescriptor(15, "0.0.40.0.0.255", 1)
	// gosem encodes octet strings from hex text.
	if err := c.ActionRequest(mth, axdr.CreateAxdrOctetString(hex.EncodeToString(ans))); err != nil {
		if f := t.LastFailure(); f != nil {
			return f
		}
		return fmt.Errorf("the meter refused our answer to its challenge: %w", err)
	}
	back, err := actionReturnOctets(t.TakeAction())
	if err != nil {
		return err
	}
	return h.check(h.Security.SystemTitle, meterST, ctos, stoc, back)
}

// checkStoC refuses a server challenge equal to ours (IEC 62056-5-3:2023
// 5.2.2.2.4) or of a length the mechanism does not allow (Table 32: 8 to
// 64 octets for mechanisms 3 to 6, 32 to 64 for mechanism 7; mechanism 2
// is manufacturer specific).
func checkStoC(mechanism byte, stoc, ctos []byte) error {
	if subtle.ConstantTimeCompare(stoc, ctos) == 1 {
		return errors.New("the meter's challenge is the same as ours; the association is aborted")
	}
	low := 8
	switch mechanism {
	case MechHLS:
		return nil
	case MechECDSA:
		low = 32
	}
	if len(stoc) < low || len(stoc) > 64 {
		return fmt.Errorf("the meter's challenge is %d octets; mechanism %d needs %d to 64", len(stoc), mechanism, low)
	}
	return nil
}

// actionReturnOctets reads the octet-string return parameter of an
// action-response-normal: C7 01 invoke result 01 (present) 00 (data) 09 len v.
func actionReturnOctets(apdu []byte) ([]byte, error) {
	if len(apdu) < 8 || apdu[0] != 0xC7 || apdu[1] != 0x01 {
		return nil, errors.New("no reply_to_HLS_authentication response was seen")
	}
	if apdu[3] != 0x00 {
		return nil, fmt.Errorf("the meter answered reply_to_HLS_authentication with result %d", apdu[3])
	}
	if apdu[4] != 0x01 || apdu[5] != 0x00 || apdu[6] != 0x09 {
		return nil, errors.New("the meter's reply carries no answer to our challenge")
	}
	n, sz, err := getLen(apdu[7:])
	if err != nil || 7+sz+n > len(apdu) {
		return nil, errors.New("the meter's answer is truncated")
	}
	return apdu[7+sz : 7+sz+n], nil
}

// newChallenge is a random CtoS challenge (the Green Book allows 8 to 64
// bytes; ECDSA uses 32 to 64).
func newChallenge() ([]byte, error) {
	c := make([]byte, 32)
	_, err := rand.Read(c)
	return c, err
}

// pemText reads PEM text given inline or as a file path.
func pemText(v string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	return os.ReadFile(v)
}

// PEMBlock reads the first PEM block of v (inline or a file path).
func PEMBlock(v string) (*pem.Block, error) { return firstPEM(v, false) }

// firstPEM reads the first PEM block of v; with skipCerts, the first
// that is not a certificate (a key given with its certificates).
func firstPEM(v string, skipCerts bool) (*pem.Block, error) {
	raw, err := pemText(v)
	if err != nil {
		return nil, err
	}
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return nil, errors.New("not PEM")
		}
		if !skipCerts || b.Type != "CERTIFICATE" {
			return b, nil
		}
	}
}

// PEMCertificates are the certificates in v (inline or a file path), in
// order; blocks of other types are skipped.
func PEMCertificates(v string) []*x509.Certificate {
	raw, err := pemText(v)
	if err != nil {
		return nil
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				out = append(out, c)
			}
		}
	}
}

func parseSigningKey(v string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	b, err := firstPEM(v, true)
	if err != nil {
		return nil, err
	}
	var key any
	switch b.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	}
	if err != nil {
		return nil, err
	}
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok || k.Curve != curve {
		return nil, fmt.Errorf("an ECDSA %s private key is required", curve.Params().Name)
	}
	return k, nil
}

func parseMeterKey(v string, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	b, err := PEMBlock(v)
	if err != nil {
		return nil, err
	}
	var key any
	switch b.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		key = cert.PublicKey
	default:
		key, err = x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
	}
	k, ok := key.(*ecdsa.PublicKey)
	if !ok || k.Curve != curve {
		return nil, fmt.Errorf("an ECDSA %s public key or certificate is required", curve.Params().Name)
	}
	return k, nil
}
