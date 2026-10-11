package cosem

// V.44 compression of xDLMS APDUs (IEC 62056-5-3:2023 5.3.6, Table 9,
// Table 27 bit 7, Table 28, Figures 31 and 32).
//
// What the standard fixes: compression is ITU-T V.44:2000 (5.3.6); it is
// available in security suites 1 and 2 only (Table 9); bit 7 of the
// security control byte says it was applied (Table 27); it is applied to
// the whole APDU to be protected before ciphering, so the ciphertext, or in
// authentication-only the authenticated data, is the compressed APDU
// ((C)I in Table 28; the Compression → ciphering flow of Figures 31 and 32);
// it appears in general-glo-, general-ded- and general-ciphering, between
// client and server or a third party and the server, and not in
// service-specific ciphering or general-signing (Table 26 compression
// column; 5.3.6 refers to 5.7.2.4.7 and 5.7.2.4.8; Figure 30 has no
// compression step). Third-party layers: thirdparty.go. So we compress then cipher when
// sending, and decipher (and check the tag) then decompress when receiving.
//
// What it leaves open (finding F-187): the V.44 parameters, which DLMS
// never negotiates. We use the packet method (V.44 annex B.1: dictionaries
// reset for every APDU, FLUSH at its end, whole octets; RFC 3051 reads it
// the same way) with its B.1.2 defaults, and every parameter can be set per
// meter to match what the meter does:
//
//	compression:
//	  enabled: true            # accept compressed APDUs from the meter
//	  compressRequests: true   # compress our requests (when that makes them smaller)
//	  codewords: 1525          # V.44 N2 (256–65535; B.1.2 default 1525)
//	  maxStringLength: 255     # V.44 N7 (32–255; default 255)
//	  history: 0               # V.44 N8 (0: the APDU is the history, B.1.2; else ≥ 512)

import (
	"errors"
	"fmt"

	v44 "github.com/cB-Sigma/schc/v44"
)

// Compression is a meter's V.44 setting.
type Compression struct {
	Enabled          bool `json:"enabled"`
	CompressRequests bool `json:"compressRequests,omitempty"`
	Codewords        int  `json:"codewords,omitempty"`
	MaxStringLength  int  `json:"maxStringLength,omitempty"`
	History          int  `json:"history,omitempty"`
}

// CompressionParams is the checked setting a secure transport uses.
type CompressionParams struct {
	params   v44.Params
	requests bool // compress requests
}

// Apply checks the setting against the security settings and stores it in
// sec. A nil or disabled setting leaves compression off.
func (c *Compression) Apply(meterID string, sec *Security) error {
	if c == nil || (!c.Enabled && !c.CompressRequests && c.Codewords == 0 && c.MaxStringLength == 0 && c.History == 0) {
		return nil
	}
	if !c.Enabled {
		return fmt.Errorf("meter %s: compression settings need compression enabled: true", meterID)
	}
	if sec.Suite != 1 && sec.Suite != 2 {
		return fmt.Errorf("meter %s: compression needs security suite 1 or 2 (IEC 62056-5-3:2023 Table 9: suite 0 has none)", meterID)
	}
	if sec.Policy == 0 || sec.Ciphering == CipherServiceSpecific {
		return fmt.Errorf("meter %s: compression needs protected APDUs in general-glo, general-ded or general ciphering (IEC 62056-5-3:2023 5.3.6)", meterID)
	}
	p := v44.Params{Codewords: c.Codewords, MaxString: c.MaxStringLength, History: c.History}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("meter %s: compression: %w", meterID, err)
	}
	full := v44.DefaultParams()
	if p.Codewords != 0 {
		full.Codewords = p.Codewords
	}
	if p.MaxString != 0 {
		full.MaxString = p.MaxString
	}
	full.History = p.History
	sec.Compression = &CompressionParams{params: full, requests: c.CompressRequests}
	return nil
}

// describe names the settings in errors.
func (c *CompressionParams) describe() string {
	h := "the APDU"
	if c.params.History > 0 {
		h = fmt.Sprint(c.params.History)
	}
	return fmt.Sprintf("codewords %d, maxStringLength %d, history %s", c.params.Codewords, c.params.MaxString, h)
}

// ErrCompressionOff refuses compressed APDUs from a meter whose settings
// do not enable compression.
var ErrCompressionOff = errors.New("the meter sent a V.44 compressed APDU (security control bit 7) and compression is not enabled for it (set compression.enabled, with the meter's V.44 codewords, maxStringLength and history)")

// compressRequest returns the APDU to cipher and the security control bit
// to add: compressed when requests are compressed and it comes out
// smaller, else unchanged.
func (sec *Security) compressRequest(apdu []byte) ([]byte, byte) {
	c := sec.Compression
	if c == nil || !c.requests {
		return apdu, 0
	}
	out, err := v44.Compress(c.params, apdu)
	if err != nil || len(out) >= len(apdu) {
		return apdu, 0
	}
	return out, SecCompressed
}

// decompress expands a deciphered compressed APDU.
func (c *CompressionParams) decompress(b []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrCompressionOff
	}
	out, err := v44.Decompress(c.params, b)
	if err != nil {
		return nil, fmt.Errorf("the meter's compressed APDU does not decode with our V.44 settings (%s); the compression settings probably do not match the meter's: %w", c.describe(), err)
	}
	return out, nil
}
