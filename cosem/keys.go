package cosem

// Key handling for DLMS/COSEM security (DLMS UA Green Book, key
// management; IEC 62056-5-3 security clauses):
//
//   - AES key wrap (RFC 3394) with the master key (KEK), used by the
//     security setup object's key_transfer and by general-ciphering's
//     wrapped-key key-info;
//   - elliptic curve Diffie–Hellman on the suite's curve (P-256 in suite 1,
//     P-384 in suite 2) with the NIST SP 800-56A concatenation KDF (hash of
//     counter 00000001 ‖ Z ‖ OtherInfo; IEC 62056-5-3:2023 5.3.4.6.5,
//     Tables 7 and 8), OtherInfo being the algorithm ID of what the key is
//     for ‖ party U info ‖ party V info. Party U info is U's system title,
//     followed for the static unified model C(0e, 2s) by the one-octet
//     length and the value of the transaction-id (Nonce U); party V info is
//     V's system title. Checked against the annex I test vectors;
//   - ECDSA signatures as raw r ‖ s of the curve's size. An ephemeral public
//     key offered with key_agreement (C(2e, 0s)) is signed together with
//     the key_id octet in front of it; one offered in general-ciphering
//     (C(1e, 1s)) is signed alone (annex I.1 and I.2).
//
// Public keys travel as the raw x ‖ y coordinates, without the 04 prefix.

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm IDs used as the KDF's AlgorithmID (DLMS UA object identifiers
// 2.16.756.5.8.3.x, encoded as in the application context names).
var (
	algAESGCM128  = []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x00}
	algAESGCM256  = []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x01}
	algAESWrap128 = []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x02}
	algAESWrap256 = []byte{0x60, 0x85, 0x74, 0x05, 0x08, 0x03, 0x03}
)

// wrapAlgorithm is the AES key wrap algorithm ID of the suite: the KDF
// algorithm ID for an agreed master key (KEK), which is used for key wrap
// (IEC 62056-5-3:2023 7.2.2.4 and Table 8).
func (s Suite) wrapAlgorithm() []byte {
	if s == 2 {
		return algAESWrap256
	}
	return algAESWrap128
}

// algorithmFor is the KDF algorithm ID for a key agreed with key_agreement:
// key wrap for the master key, AES-GCM for the others (our reading, F-174).
func (s Suite) algorithmFor(keyID byte) []byte {
	if keyID == KeyMaster {
		return s.wrapAlgorithm()
	}
	return s.gcmAlgorithm()
}

// gcmAlgorithm is the AES-GCM algorithm ID of the suite.
func (s Suite) gcmAlgorithm() []byte {
	if s == 2 {
		return algAESGCM256
	}
	return algAESGCM128
}

// Curve is the suite's elliptic curve (suites 1 and 2 only).
func (s Suite) Curve() (elliptic.Curve, error) {
	switch s {
	case 1:
		return elliptic.P256(), nil
	case 2:
		return elliptic.P384(), nil
	}
	return nil, fmt.Errorf("security suite %d has no public key algorithms", s)
}

var wrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// WrapKey is RFC 3394 AES key wrap of key (a multiple of 8 bytes, at least
// 16) with kek.
func WrapKey(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("a wrapped key must be a multiple of 8 bytes and at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("the master key must be an AES key: %w", err)
	}
	n := len(key) / 8
	a := append([]byte(nil), wrapIV...)
	r := append([]byte(nil), key...)
	b := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b, a)
			copy(b[8:], r[i*8:i*8+8])
			block.Encrypt(b, b)
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i*8:], b[8:])
		}
	}
	return append(a, r...), nil
}

// UnwrapKey reverses wrapKey and checks the integrity value.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("a wrapped key must be a multiple of 8 bytes and at least 24")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("the master key must be an AES key: %w", err)
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := append([]byte(nil), wrapped[8:]...)
	b := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(b, binary.BigEndian.Uint64(a)^t)
			copy(b[8:], r[i*8:i*8+8])
			block.Decrypt(b, b)
			copy(a, b[:8])
			copy(r[i*8:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, wrapIV) != 1 {
		return nil, errors.New("the wrapped key does not unwrap with this master key")
	}
	return r, nil
}

// kdf is the concatenation KDF with the suite's hash, one round (every
// suite's key fits in one hash output).
func kdf(suite Suite, z, algorithm, partyU, partyV []byte) []byte {
	in := concat([]byte{0, 0, 0, 1}, z, algorithm, partyU, partyV)
	if suite == 2 {
		h := sha512.Sum384(in)
		return h[:suite.KeyLen()]
	}
	h := sha256.Sum256(in)
	return h[:suite.KeyLen()]
}

// staticPartyU is party U info of the static unified model C(0e, 2s):
// U's system title, then Nonce U, which is the transaction-id with its
// one-octet length in front.
func staticPartyU(originator, transactionID []byte) ([]byte, error) {
	if len(transactionID) == 0 || len(transactionID) > 0xFF {
		return nil, errors.New("the static unified model needs a transaction-id of 1 to 255 octets as its nonce")
	}
	return concat(originator, []byte{byte(len(transactionID))}, transactionID), nil
}

// ecdhZ is the shared secret of priv and the raw public key peer.
func ecdhZ(priv *ecdsa.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := rawPublicKey(priv.Curve, peer)
	if err != nil {
		return nil, err
	}
	return ecdhZPub(priv, pub)
}

func ecdhZPub(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if pub.Curve != priv.Curve {
		return nil, errors.New("the keys are on different curves")
	}
	a, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	b, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	return a.ECDH(b)
}

// rawPoint is the x ‖ y encoding of a public key.
func rawPoint(k *ecdsa.PublicKey) []byte {
	b, err := k.Bytes()
	if err != nil || len(b) == 0 {
		return nil
	}
	return b[1:] // uncompressed point without the 04 prefix
}

// rawPublicKey decodes x ‖ y on curve, checking the point is on it.
func rawPublicKey(curve elliptic.Curve, raw []byte) (*ecdsa.PublicKey, error) {
	n := (curve.Params().BitSize + 7) / 8
	if len(raw) != 2*n {
		return nil, fmt.Errorf("a %s public key is %d bytes, not %d", curve.Params().Name, 2*n, len(raw))
	}
	k, err := ecdsa.ParseUncompressedPublicKey(curve, concat([]byte{4}, raw))
	if err != nil {
		return nil, errors.New("the public key is not a point on the curve")
	}
	return k, nil
}

// digestFor hashes with the curve's hash (SHA-256 for P-256, SHA-384 for
// P-384).
func digestFor(curve elliptic.Curve, b []byte) []byte {
	if curve.Params().BitSize == 384 {
		s := sha512.Sum384(b)
		return s[:]
	}
	s := sha256.Sum256(b)
	return s[:]
}

// signRaw signs data (hashing it first) and returns r ‖ s.
func signRaw(k *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digestFor(k.Curve, data))
	if err != nil {
		return nil, err
	}
	n := (k.Curve.Params().BitSize + 7) / 8
	return concat(fixed(r, n), fixed(s, n)), nil
}

// verifyRaw checks an r ‖ s signature over data.
func verifyRaw(k *ecdsa.PublicKey, data, sig []byte) bool {
	return verifyDigest(k, digestFor(k.Curve, data), sig)
}

func verifyDigest(k *ecdsa.PublicKey, digest, sig []byte) bool {
	n := (k.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return false
	}
	return ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
}

// ephemeralOffer is an ephemeral key pair and its signed public key, the
// key data of C(2e, 0s) and C(1e, 1s) agreement. The signature covers
// prefix ‖ public key: the key_id octet for key_agreement, nothing for
// general-ciphering.
func ephemeralOffer(signer *ecdsa.PrivateKey, prefix []byte) (*ecdsa.PrivateKey, []byte, error) {
	e, err := ecdsa.GenerateKey(signer.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := rawPoint(&e.PublicKey)
	sig, err := signRaw(signer, concat(prefix, pub))
	if err != nil {
		return nil, nil, err
	}
	return e, concat(pub, sig), nil
}

// openOffer checks a signed ephemeral public key from the holder of
// signer, signed with prefix in front as in ephemeralOffer, and returns
// the key.
func openOffer(curve elliptic.Curve, signer *ecdsa.PublicKey, data, prefix []byte) ([]byte, error) {
	n := (curve.Params().BitSize + 7) / 8
	if len(data) != 4*n {
		return nil, fmt.Errorf("signed ephemeral key data is %d bytes, not %d", len(data), 4*n)
	}
	pub, sig := data[:2*n], data[2*n:]
	if signer == nil || !verifyRaw(signer, concat(prefix, pub), sig) {
		return nil, errors.New("the ephemeral public key's signature does not verify")
	}
	return pub, nil
}
