package cosem

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// RFC 3394 section 4 test vectors: 4.1 (128-bit KEK, 128-bit key), 4.3
// (256-bit KEK, 128-bit key) and 4.6 (256-bit KEK, 256-bit key).
//
// Covers: SIG-IPE-069
func TestKeyWrapRFC3394Vectors(t *testing.T) {
	kek256 := "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
	for _, tc := range []struct{ name, kek, key, wrapped string }{
		{"4.1", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"4.3", kek256, "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"4.6", kek256, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	} {
		kek, key, want := mustHex(t, tc.kek), mustHex(t, tc.key), mustHex(t, tc.wrapped)
		got, err := WrapKey(kek, key)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: wrap = %X %v, want %X", tc.name, got, err, want)
		}
		back, err := UnwrapKey(kek, want)
		if err != nil || !bytes.Equal(back, key) {
			t.Errorf("%s: unwrap = %X %v", tc.name, back, err)
		}
		for i := range want {
			bad := bytes.Clone(want)
			bad[i] ^= 0x80
			if _, err := UnwrapKey(kek, bad); err == nil {
				t.Errorf("%s: a change at byte %d unwrapped", tc.name, i)
			}
		}
	}
	if _, err := UnwrapKey(mustHex(t, "000102030405060708090A0B0C0D0E0E"), mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")); err == nil {
		t.Error("a key wrapped with another KEK unwrapped")
	}
}

// NIST CAVS 11.0 ECDSA SigVer vectors (SigVer.rsp as shipped in the Go
// source tree), P-256 with SHA-256 and P-384 with SHA-384: the passing
// ones verify, and those with a changed message, R, S or Q do not.
//
// Covers: SIG-IPE-068
func TestSignatureVerificationNISTVectors(t *testing.T) {
	for i, tc := range []struct {
		curve             elliptic.Curve
		msg, qx, qy, r, s string
		pass              bool
	}{
		{elliptic.P256(),
			"e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
			"e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c", "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
			"bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f", "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c", true},
		{elliptic.P256(),
			"73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08",
			"e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864", "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a",
			"1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407", "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a", true},
		{elliptic.P256(), // S changed
			"e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
			"87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555", "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9",
			"d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0", "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6", false},
		{elliptic.P256(), // R changed
			"069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
			"5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2", "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85",
			"dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693", "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c", false},
		{elliptic.P256(), // Q changed
			"df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
			"2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb", "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64",
			"9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8", "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc", false},
		{elliptic.P384(),
			"9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c33625e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd",
			"cb908b1fd516a57b8ee1e14383579b33cb154fece20c5035e2b3765195d1951d75bd78fb23e00fef37d7d064fd9af144", "cd99c46b5857401ddcff2cf7cf822121faf1cbad9a011bed8c551f6f59b2c360f79bfbe32adbcaa09583bdfdf7c374bb",
			"33f64fb65cd6a8918523f23aea0bbcf56bba1daca7aff817c8791dc92428d605ac629de2e847d43cee55ba9e4a0e83ba", "4428bb478a43ac73ecd6de51ddf7c28ff3c2441625a081714337dd44fea8011bae71959a10947b6ea33f77e128d3c6ae", true},
		{elliptic.P384(), // R changed
			"4132833a525aecc8a1a6dea9f4075f44feefce810c4668423b38580417f7bdca5b21061a45eaa3cbe2a7035ed189523af8002d65c2899e65735e4d93a16503c145059f365c32b3acc6270e29a09131299181c98b3c76769a18faf21f6b4a8f271e6bf908e238afe8002e27c63417bda758f846e1e3b8e62d7f05ebd98f1f9154",
			"1f94eb6f439a3806f8054dd79124847d138d14d4f52bac93b042f2ee3cdb7dc9e09925c2a5fee70d4ce08c61e3b19160", "1c4fd111f6e33303069421deb31e873126be35eeb436fe2034856a3ed1e897f26c846ee3233cd16240989a7990c19d8c",
			"3c15c3cedf2a6fbff2f906e661f5932f2542f0ce68e2a8182e5ed3858f33bd3c5666f17ac39e52cb004b80a0d4ba73cd", "9de879083cbb0a97973c94f1963d84f581e4c6541b7d000f9850deb25154b23a37dd72267bdd72665cc7027f88164fab", false},
		{elliptic.P384(), // S changed
			"9c4479977ed377e75f5cc047edfa689ef232799513a2e70280e9b124b6c8d166e107f5494b406853aec4cff0f2ca00c6f89f0f4a2d4ab0267f44512dfff110d1b1b2e5e78832022c14ac06a493ab789e696f7f0f060877029c27157ce40f81258729caa4d9778bae489d3ab0259f673308ae1ec1b1948ad2845f863b36aedffb",
			"9b3c48d924194146eca4172b6d7d618423682686f43e1dbc54ed909053d075ca53b68ae12f0f16a1633d5d9cb17011ec", "695039f837b68e59330ee95d11d5315a8fb5602a7b60c15142dbba6e93b5e4aba8ae4469eac39fa6436323eccc60dcb6",
			"202da4e4e9632bcb6bf0f6dafb7e348528d0b469d77e46b9f939e2fa946a608dd1f166bcbcde96cfad551701da69f6c2", "db595b49983882c48df8a396884cd98893a469c4d590e56c6a59b6150d9a0acdf142cf92151052644702ed857a5b7981", false},
	} {
		pub, err := rawPublicKey(tc.curve, concat(mustHex(t, tc.qx), mustHex(t, tc.qy)))
		got := err == nil && verifyRaw(pub, mustHex(t, tc.msg), concat(mustHex(t, tc.r), mustHex(t, tc.s)))
		if got != tc.pass {
			t.Errorf("vector %d (%s): verified %v, want %v", i, tc.curve.Params().Name, got, tc.pass)
		}
	}
}

// Our signatures verify with the matching key only, on both curves, and
// a changed byte fails.
//
// Covers: SIG-IPE-068
func TestSignRoundTrip(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		k, _ := ecdsa.GenerateKey(c, rand.Reader)
		other, _ := ecdsa.GenerateKey(c, rand.Reader)
		sig, err := signRaw(k, []byte("apdu"))
		if err != nil || len(sig) != 2*(c.Params().BitSize/8) {
			t.Fatalf("%s: %d-byte signature, %v", c.Params().Name, len(sig), err)
		}
		if !verifyRaw(&k.PublicKey, []byte("apdu"), sig) || verifyRaw(&other.PublicKey, []byte("apdu"), sig) || verifyRaw(&k.PublicKey, []byte("apdv"), sig) {
			t.Errorf("%s: signature checks are wrong", c.Params().Name)
		}
	}
}

// ECDH through the suite's KDF gives both sides the same key of the
// suite's length, the signed ephemeral offer checks its signer, and a key
// not on the curve is refused.
//
// Covers: SIG-IPE-070
func TestKeyAgreementPrimitives(t *testing.T) {
	for _, suite := range []Suite{1, 2} {
		curve, _ := suite.Curve()
		a, _ := ecdsa.GenerateKey(curve, rand.Reader)
		b, _ := ecdsa.GenerateKey(curve, rand.Reader)
		signer, _ := ecdsa.GenerateKey(curve, rand.Reader)
		e, offer, err := ephemeralOffer(signer, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		pub, err := openOffer(curve, &signer.PublicKey, offer, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openOffer(curve, &a.PublicKey, offer, []byte{0}); err == nil {
			t.Errorf("suite %d: an offer signed by another key opened", suite)
		}
		if _, err := openOffer(curve, &signer.PublicKey, offer, []byte{1}); err == nil {
			t.Errorf("suite %d: an offer signed for key_id 0 opened as key_id 1", suite)
		}
		z1, _ := ecdhZ(b, pub)
		z2, _ := ecdhZPub(e, &b.PublicKey)
		u, v := []byte("SGM\x00\x00\x00\x00\x01"), []byte("LNT\x00\x00\x01\x23\x45")
		k1, k2 := kdf(suite, z1, suite.gcmAlgorithm(), u, v), kdf(suite, z2, suite.gcmAlgorithm(), u, v)
		if !bytes.Equal(k1, k2) || len(k1) != suite.KeyLen() {
			t.Errorf("suite %d: agreed keys differ or have the wrong length", suite)
		}
		if bytes.Equal(k1, kdf(suite, z1, suite.gcmAlgorithm(), v, u)) {
			t.Errorf("suite %d: swapping the parties gives the same key", suite)
		}
		off := rawPoint(&a.PublicKey)
		off[len(off)-1] ^= 1
		if _, err := rawPublicKey(curve, off); err == nil {
			t.Errorf("suite %d: a point off the curve was accepted", suite)
		}
	}
}
