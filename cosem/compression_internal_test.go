package cosem

import (
	"bytes"
	"errors"
	"testing"

	v44 "github.com/cB-Sigma/schc/v44"
)

// The compressed APDU is what is ciphered and authenticated (Table 28):
// a protected compressed APDU opens and decompresses to the original; a
// suite 0 APDU never carries compression (Table 9); service-specific
// content with the bit is refused (5.3.6); a changed octet of the
// compressed ciphertext fails the tag, not the decompression. (Compressed
// exchanges with a simulated meter are tested in the dlms-sim module.)
//
// Covers: SIG-IPE-664
func TestCompressedProtection(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	apdu := append([]byte{0xC4, 0x01, 0x41, 0x00, 0x09, 0x81, 0xC8}, bytes.Repeat([]byte("ABCD"), 50)...)
	comp := &CompressionParams{params: v44.DefaultParams()}
	packed, err := v44.Compress(comp.params, apdu)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []byte{0x10, 0x20, 0x30} {
		p, err := Protect(1, policy|SecCompressed, key, key, meterST, 9, packed)
		if err != nil {
			t.Fatal(err)
		}
		if p[0] != policy|SecCompressed|1 {
			t.Fatalf("security control %#x", p[0])
		}
		plain, ic, err := unprotectGeneral(comp, 1, key, nil, key, meterST, p, nil)
		if err != nil || ic != 9 || !bytes.Equal(plain, apdu) {
			t.Fatalf("policy %#x: %v", policy, err)
		}
		if _, _, err := UnprotectKeys(1, key, nil, key, meterST, p, nil); !errors.Is(err, ErrCompressed) {
			t.Errorf("service-specific: %v", err)
		}
		if _, _, err := unprotectGeneral(nil, 1, key, nil, key, meterST, p, nil); !errors.Is(err, ErrCompressionOff) {
			t.Errorf("compression off: %v", err)
		}
		if policy&SecAuthentication != 0 {
			bad := append([]byte(nil), p...)
			bad[8] ^= 1
			if _, _, err := unprotectGeneral(comp, 1, key, nil, key, meterST, bad, nil); err == nil || errors.Is(err, v44.ErrCorrupt) {
				t.Errorf("tampered: %v, want a tag failure", err)
			}
		}
	}
	if _, err := Protect(0, SecCompressed|SecEncryption, key, key, meterST, 3, packed); !errors.Is(err, ErrCompressed) {
		t.Errorf("suite 0 protect: %v", err)
	}
	p, _ := Protect(0, SecEncryption, key, key, meterST, 3, packed)
	p[0] |= SecCompressed
	if _, _, err := unprotectGeneral(comp, 0, key, nil, key, meterST, p, nil); !errors.Is(err, ErrCompressed) {
		t.Errorf("suite 0 open: %v", err)
	}
	// Requests are compressed only when that makes them smaller.
	sec := &Security{Compression: &CompressionParams{params: v44.DefaultParams(), requests: true}}
	if out, bit := sec.compressRequest([]byte{0xC0, 0x01, 0x41, 0x00, 0x03}); bit != 0 || len(out) != 5 {
		t.Errorf("short request compressed: %X %#x", out, bit)
	}
	if out, bit := sec.compressRequest(apdu); bit != SecCompressed || len(out) >= len(apdu) {
		t.Errorf("long request not compressed: %d %#x", len(out), bit)
	}
}

// Compression settings: off unless enabled; suites 1 and 2 only; general
// ciphering forms only; V.44 ranges of Table 10; B.1.2 defaults.
//
// Covers: SIG-IPE-664
func TestCompressionSettings(t *testing.T) {
	base := func() Security {
		return Security{Suite: 1, Policy: SecAuthentication | SecEncryption, Ciphering: CipherGeneralGlo}
	}
	sec := base()
	if err := (*Compression)(nil).Apply("M", &sec); err != nil || sec.Compression != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := (&Compression{Enabled: true}).Apply("M", &sec); err != nil {
		t.Fatal(err)
	}
	if p := sec.Compression.params; p.Codewords != 1525 || p.MaxString != 255 || p.History != 0 || sec.Compression.requests {
		t.Errorf("defaults %+v", sec.Compression)
	}
	sec = base()
	if err := (&Compression{Enabled: true, CompressRequests: true, Codewords: 2048, MaxStringLength: 64, History: 4096}).Apply("M", &sec); err != nil {
		t.Fatal(err)
	}
	if p := sec.Compression.params; p.Codewords != 2048 || p.MaxString != 64 || p.History != 4096 || !sec.Compression.requests {
		t.Errorf("set %+v", sec.Compression)
	}
	bad := map[string]func(*Compression, *Security){
		"not enabled":      func(c *Compression, _ *Security) { c.Enabled = false },
		"suite 0":          func(_ *Compression, s *Security) { s.Suite = 0 },
		"service-specific": func(_ *Compression, s *Security) { s.Ciphering = CipherServiceSpecific },
		"unprotected":      func(_ *Compression, s *Security) { s.Policy = 0 },
		"codewords":        func(c *Compression, _ *Security) { c.Codewords = 100 },
		"maxStringLength":  func(c *Compression, _ *Security) { c.MaxStringLength = 300 },
		"history":          func(c *Compression, _ *Security) { c.History = 100 },
	}
	for name, change := range bad {
		c, s := &Compression{Enabled: true, CompressRequests: true}, base()
		change(c, &s)
		if err := c.Apply("M", &s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
