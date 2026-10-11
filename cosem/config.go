package cosem

// Security settings as text (the form a configuration file or a console
// gives them in), checked and decoded into what an association uses.

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// SecurityConfig is a meter's authentication and APDU protection as text.
//
//	Authentication     none, low, hls-aes (hls), hls-md5, hls-sha1, hls-gmac, hls-sha256, hls-ecdsa
//	Password           the low-level password, or the HLS secret (aes, md5, sha1, sha256)
//	Security           none, authenticated, encrypted or authenticated-encrypted
//	Suite              security suite 0, 1 or 2 (hls-ecdsa needs 1 or 2)
//	SystemTitle        ours, 8 bytes hex (default 53474D0000000001)
//	BlockCipherKey     the global unicast key, hex (16 bytes; 32 in suite 2)
//	AuthenticationKey  the authentication key, hex
//	DedicatedKey       agree a fresh dedicated key per association
//	SigningKey         our EC private key (PEM text or a file path): hls-ecdsa, signing, one-pass agreement
//	MeterSigningKey    the meter's signing public key or certificate
//	Ciphering          service-specific (default), general-glo, general-ded or general
//	GeneralKey         general: identified (default), wrapped, agreed-one-pass or agreed-static
//	MasterKey          the KEK, hex: wrapped keys and key_transfer
//	BroadcastKey       the global broadcast key, hex
//	Signing            general-signing on every request and response (suite 1 or 2)
//	KeyAgreementKey    our static key agreement key (PEM or path)
//	MeterKAKey         the meter's key agreement public key or certificate
//	ThirdParty         requests protected for a third party inside our layer
//	Compression        V.44 (suite 1 or 2, general ciphering)
//	ApplicationContext auto (default), ln, ln-ciphering, sn or sn-ciphering: the context the AARQ proposes
//	Referencing        ln (default) or sn: logical or short name referencing
//
// Name names the meter in errors.
type SecurityConfig struct {
	Name              string
	Authentication    string
	Password          string
	Security          string
	Suite             int
	SystemTitle       string
	BlockCipherKey    string
	AuthenticationKey string
	DedicatedKey      bool
	SigningKey        string
	MeterSigningKey   string
	Ciphering         string
	GeneralKey        string
	MasterKey         string
	BroadcastKey      string
	Signing           bool
	KeyAgreementKey   string
	MeterKAKey        string
	ThirdParty        *ThirdParty
	Compression       *Compression
	// ApplicationContext is "auto" (or empty: the ciphering context whenever
	// our system title is sent, as with mechanism 5 and protected APDUs),
	// "ln" (logical name referencing without ciphering: HLS-GMAC with
	// unprotected APDUs, as many meters and Gurux expect) or "ln-ciphering".
	ApplicationContext string
	// Referencing is "ln" (logical names, the default) or "sn" (short
	// names: Client.Get reads through base names from the association SN
	// object list); "sn" with ApplicationContext auto picks the short name
	// context with or without ciphering as auto does for logical names.
	// ApplicationContext "sn" and "sn-ciphering" imply it.
	Referencing string
}

// KeyWarning is an optional key that could not be used: the meter runs
// without the feature it serves. Setting names the field.
type KeyWarning struct {
	Setting, Message string
}

// DefaultSystemTitle is the system title SecurityConfig uses when none is
// given ("SGM" and a serial number).
const DefaultSystemTitle = "53474D0000000001"

// Build checks and decodes the settings, filling in their defaults
// (Security "none", SystemTitle). A key a configured feature needs
// (hls-ecdsa, signing, an agreed general key) must be usable; any other
// key that cannot be read or parsed is left out with a KeyWarning.
func (c *SecurityConfig) Build() (*HLS, []KeyWarning, error) {
	mech, ok := MechanismNames[strings.ToLower(c.Authentication)]
	if !ok {
		return nil, nil, fmt.Errorf("meter %s: authentication %q is not none, low, hls-aes, hls-md5, hls-sha1, hls-gmac, hls-sha256 or hls-ecdsa", c.Name, c.Authentication)
	}
	if NeedsPassword(mech) && c.Password == "" {
		return nil, nil, fmt.Errorf("meter %s: authentication %s needs a password (the secret)", c.Name, c.Authentication)
	}
	h := &HLS{Mechanism: mech, Secret: []byte(c.Password)}
	switch c.Security {
	case "", "none":
		c.Security = "none"
	case "authenticated":
		h.Security.Policy = SecAuthentication
	case "encrypted":
		h.Security.Policy = SecEncryption
	case "authenticated-encrypted":
		h.Security.Policy = SecAuthentication | SecEncryption
	default:
		return nil, nil, fmt.Errorf("meter %s: security %q is not none, authenticated, encrypted or authenticated-encrypted", c.Name, c.Security)
	}
	if c.Suite < 0 || c.Suite > 2 {
		return nil, nil, fmt.Errorf("meter %s: suite must be 0, 1 or 2", c.Name)
	}
	h.Security.Suite = Suite(c.Suite)
	if mech == MechECDSA && c.Suite == 0 {
		return nil, nil, fmt.Errorf("meter %s: hls-ecdsa needs security suite 1 or 2", c.Name)
	}
	if c.SystemTitle == "" {
		c.SystemTitle = DefaultSystemTitle
	}
	st, err := hex.DecodeString(c.SystemTitle)
	if err != nil || len(st) != 8 {
		return nil, nil, fmt.Errorf("meter %s: systemTitle must be 8 bytes of hex", c.Name)
	}
	h.Security.SystemTitle = st
	if h.Security.Policy != 0 || mech == MechGMAC {
		n := h.Security.Suite.KeyLen()
		dec := func(name, v string) ([]byte, error) {
			b, err := hex.DecodeString(strings.ReplaceAll(v, " ", ""))
			if err != nil || len(b) != n {
				return nil, fmt.Errorf("meter %s: %s must be %d bytes of hex for suite %d", c.Name, name, n, c.Suite)
			}
			return b, nil
		}
		if h.Security.Key, err = dec("blockCipherKey", c.BlockCipherKey); err != nil {
			return nil, nil, err
		}
		if h.Security.AuthKey, err = dec("authenticationKey", c.AuthenticationKey); err != nil {
			return nil, nil, err
		}
	}
	if c.BroadcastKey != "" {
		if h.Security.Policy == 0 {
			return nil, nil, fmt.Errorf("meter %s: broadcastKey needs protected APDUs (security other than none)", c.Name)
		}
		b, err := hex.DecodeString(strings.ReplaceAll(c.BroadcastKey, " ", ""))
		if err != nil || len(b) != h.Security.Suite.KeyLen() {
			return nil, nil, fmt.Errorf("meter %s: broadcastKey must be %d bytes of hex for suite %d", c.Name, h.Security.Suite.KeyLen(), c.Suite)
		}
		h.Security.BroadcastKey = b
	}
	if c.DedicatedKey {
		if h.Security.Policy == 0 {
			return nil, nil, fmt.Errorf("meter %s: dedicatedKey needs protected APDUs (security other than none)", c.Name)
		}
		h.Security.Dedicated = true
	}
	switch strings.ToLower(c.ApplicationContext) {
	case "", "auto":
	case "ln":
		if h.Security.Policy != 0 {
			return nil, nil, fmt.Errorf("meter %s: applicationContext ln has no ciphering, so it needs security none (protected APDUs need ln-ciphering)", c.Name)
		}
		h.Security.Context = ContextLN
	case "ln-ciphering":
		h.Security.Context = ContextLNCiphering
	case "sn":
		if h.Security.Policy != 0 {
			return nil, nil, fmt.Errorf("meter %s: applicationContext sn has no ciphering, so it needs security none (protected APDUs need sn-ciphering)", c.Name)
		}
		h.Security.Context, h.Security.ShortNames = ContextSN, true
	case "sn-ciphering":
		h.Security.Context, h.Security.ShortNames = ContextSNCiphering, true
	default:
		return nil, nil, fmt.Errorf("meter %s: applicationContext %q is not auto, ln, ln-ciphering, sn or sn-ciphering", c.Name, c.ApplicationContext)
	}
	switch strings.ToLower(c.Referencing) {
	case "", "ln", "logical-name":
		if c.Referencing != "" && h.Security.ShortNames {
			return nil, nil, fmt.Errorf("meter %s: referencing %s contradicts applicationContext %s", c.Name, c.Referencing, c.ApplicationContext)
		}
	case "sn", "short-name":
		if h.Security.Context == ContextLN || h.Security.Context == ContextLNCiphering {
			return nil, nil, fmt.Errorf("meter %s: referencing %s contradicts applicationContext %s", c.Name, c.Referencing, c.ApplicationContext)
		}
		h.Security.ShortNames = true
	default:
		return nil, nil, fmt.Errorf("meter %s: referencing %q is not ln or sn", c.Name, c.Referencing)
	}
	warns, err := c.publicKeySettings(h)
	if err != nil {
		return nil, nil, err
	}
	return h, warns, nil
}

// publicKeySettings checks the ciphering form, general-ciphering key,
// master key, signing and key agreement settings.
func (c *SecurityConfig) publicKeySettings(h *HLS) ([]KeyWarning, error) {
	sec := &h.Security
	mech := h.Mechanism
	var warns []KeyWarning
	switch c.Ciphering {
	case "", "service-specific":
		sec.Ciphering = CipherServiceSpecific
	case "general-glo":
		sec.Ciphering = CipherGeneralGlo
	case "general-ded":
		sec.Ciphering = CipherGeneralDed
		if !sec.Dedicated {
			return nil, fmt.Errorf("meter %s: general-ded ciphering needs dedicatedKey", c.Name)
		}
	case "general":
		sec.Ciphering = CipherGeneral
	default:
		return nil, fmt.Errorf("meter %s: ciphering %q is not service-specific, general-glo, general-ded or general", c.Name, c.Ciphering)
	}
	if sec.Ciphering != CipherServiceSpecific && sec.Policy == 0 {
		return nil, fmt.Errorf("meter %s: ciphering %s needs protected APDUs (security other than none)", c.Name, c.Ciphering)
	}
	switch c.GeneralKey {
	case "", "identified":
		sec.GeneralKey = GenKeyIdentified
	case "wrapped":
		sec.GeneralKey = GenKeyWrapped
	case "agreed-one-pass":
		sec.GeneralKey = GenKeyOnePass
	case "agreed-static":
		sec.GeneralKey = GenKeyStatic
	default:
		return nil, fmt.Errorf("meter %s: generalKey %q is not identified, wrapped, agreed-one-pass or agreed-static", c.Name, c.GeneralKey)
	}
	if c.GeneralKey != "" && sec.Ciphering != CipherGeneral {
		return nil, fmt.Errorf("meter %s: generalKey applies to ciphering general only", c.Name)
	}
	if c.MasterKey != "" {
		b, err := hex.DecodeString(strings.ReplaceAll(c.MasterKey, " ", ""))
		if err != nil || len(b) != sec.Suite.KeyLen() {
			return nil, fmt.Errorf("meter %s: masterKey must be %d bytes of hex for suite %d", c.Name, sec.Suite.KeyLen(), c.Suite)
		}
		sec.MasterKey, sec.RootKey = b, b
	}
	if sec.GeneralKey == GenKeyWrapped && sec.MasterKey == nil {
		return nil, fmt.Errorf("meter %s: generalKey wrapped needs masterKey", c.Name)
	}
	curve, cerr := sec.Suite.Curve()
	var err error
	agreed := sec.GeneralKey == GenKeyOnePass || sec.GeneralKey == GenKeyStatic
	needSign := mech == MechECDSA || c.Signing || sec.GeneralKey == GenKeyOnePass
	keyErr := func(setting string, need bool, err error) error {
		if need {
			return fmt.Errorf("meter %s: %s: %w", c.Name, setting, err)
		}
		warns = append(warns, KeyWarning{Setting: setting,
			Message: fmt.Sprintf("meter %s: %s cannot be used (%v); the meter runs without it. Give a readable PEM key of the suite's curve, or clear %s", c.Name, setting, err, setting)})
		return nil
	}
	if c.SigningKey != "" || mech == MechECDSA {
		if cerr != nil {
			return nil, fmt.Errorf("meter %s: signing keys need security suite 1 or 2", c.Name)
		}
		if h.SignKey, err = parseSigningKey(c.SigningKey, curve); err != nil {
			if err := keyErr("signingKey", needSign, err); err != nil {
				return nil, err
			}
		}
	}
	if c.MeterSigningKey != "" || mech == MechECDSA {
		if cerr != nil {
			return nil, fmt.Errorf("meter %s: signing keys need security suite 1 or 2", c.Name)
		}
		if h.MeterKey, err = parseMeterKey(c.MeterSigningKey, curve); err != nil {
			if err := keyErr("meterSigningKey", needSign, err); err != nil {
				return nil, err
			}
		}
	}
	sec.SignKey, sec.MeterSignKey = h.SignKey, h.MeterKey
	if c.KeyAgreementKey != "" || c.MeterKAKey != "" {
		if cerr != nil {
			return nil, fmt.Errorf("meter %s: key agreement keys need security suite 1 or 2", c.Name)
		}
	}
	if c.KeyAgreementKey != "" {
		if sec.KAKey, err = parseSigningKey(c.KeyAgreementKey, curve); err != nil {
			if err := keyErr("keyAgreementKey", agreed, err); err != nil {
				return nil, err
			}
		}
	}
	if c.MeterKAKey != "" {
		if sec.MeterKAKey, err = parseMeterKey(c.MeterKAKey, curve); err != nil {
			if err := keyErr("meterKeyAgreementKey", agreed, err); err != nil {
				return nil, err
			}
		}
	}
	switch sec.GeneralKey {
	case GenKeyOnePass:
		if sec.SignKey == nil || sec.MeterKAKey == nil || sec.KAKey == nil || sec.MeterSignKey == nil {
			return nil, fmt.Errorf("meter %s: generalKey agreed-one-pass needs signingKey, meterSigningKey, keyAgreementKey and meterKeyAgreementKey", c.Name)
		}
	case GenKeyStatic:
		if sec.KAKey == nil || sec.MeterKAKey == nil {
			return nil, fmt.Errorf("meter %s: generalKey agreed-static needs keyAgreementKey and meterKeyAgreementKey", c.Name)
		}
	}
	if c.Signing {
		if sec.SignKey == nil || sec.MeterSignKey == nil {
			return nil, fmt.Errorf("meter %s: signing needs signingKey and meterSigningKey (suite 1 or 2)", c.Name)
		}
		sec.Signing = true
	}
	if c.ThirdParty != nil {
		tp, err := c.ThirdParty.Build(sec)
		if err != nil {
			return nil, fmt.Errorf("meter %s: %w", c.Name, err)
		}
		sec.ThirdParty = tp
	}
	if err := c.Compression.Apply(c.Name, sec); err != nil {
		return nil, err
	}
	return warns, nil
}

// NeedsPassword reports the mechanisms that need a password or secret:
// low-level security and HLS mechanisms 2, 3, 4 and 6.
func NeedsPassword(mech byte) bool {
	return mech == MechLow || mech == MechHLS || mech == MechMD5 || mech == MechSHA1 || mech == MechSHA256
}

// DefaultClientAddress is the client address of an association by its
// mechanism, as IS 15959 numbers them (table 3 of Part 1, table 2 of
// Part 2): 16 the public client without authentication, 32 the meter
// reader with low-level security, 48 the utility settings client with
// HLS.
func DefaultClientAddress(mech byte) int {
	switch mech {
	case MechNone:
		return 16
	case MechLow:
		return 32
	}
	return 48
}
