package cosem

// Worked examples of IEC 62056-5-3:2023 (Edition 4.0), transcribed as test
// vectors. Only the example bytes are taken over (facts); every
// transcription is cross-checked by computation where the standard gives
// enough to do so (public keys from private keys, shared secrets, KDF
// output, signatures, GCM tags, or two independent ciphertexts that must
// open to the same plaintext).

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Shared security material of the examples.
const (
	vecEK    = "000102030405060708090A0B0C0D0E0F"
	vecAK    = "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
	vecST    = "4D4D4D0000BC614E" // the client in annex I and Table 34
	vecST2   = "4D4D4D0000000001" // the server in annex I and Table 34
	vecIC    = 0x01234567
	vecAlg   = "60857405080300" // AES-GCM-128, Table 8
	vecTxC   = "0102030405060708"
	vecTxS   = "0123456789012345"
	vecPrivC = "418073C239FA6125011DE4D6CD2E645780289F761BB21BFB0835CB5585E8B373" // signing, client
	vecPubC  = "BAAFFDE06A8CB1C9DAE8D94023C601DBBB249254BA22EDD827E820BCA2BCC64362FBB83D86A82B87BB8B7161D2AAB5521911A946B97A284A90F7785CD9047D25"
	vecPrivS = "AE55414FFE079F9FC95649536BD1C2B5653D200813727E07D501A8B550C69207" // signing, server
	vecPubS  = "933ACF15B03A9248E029B2787FB52A0AECAF635F07C42A0019FB3197E38F8F549A125EA36781B0CA96BE89A0E1FE2CF9B7361ED48B3C5E24592B9C0F4EDD31D1"
	vecAKC   = "A51C16FF5C498FCC89323D4A9267CD71BF81FD6F6A891CD240DA7F3D6F283E65" // key agreement, client
	vecAKCp  = "07C56DE2DCAF0FD793EF29F019C89B4A0CC1E001CE94F4FFBE10BC05E7E66F7671A13FBCF9E662B9826FFF6A6938546D524ED6D3405F020296BDE16B04F7A7C2"
	vecAKS   = "AAD3FD0732E991CF52A74C66C1F2827DDC53522A2E0A169D7C4FFCC0FB5D6A4D" // key agreement, server
	vecAKSp  = "A653565B0E06070BAE9FBE140A5D2156812AEE2DD525053E3EFC850BF13BFDFFCB240BC7B77BFF5883344E7275908D2287BEFA3725017295A096989D2338290B"
)

func vh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("test vector %q: %v", s, err)
	}
	return b
}

// vecKey is the P-256 key pair of a private key from the examples; it
// fails the test when the example's public key does not match.
func vecKey(t *testing.T, priv, pub string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().NewPrivateKey(vh(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	raw := k.PublicKey().Bytes()[1:]
	if !bytes.Equal(raw, vh(t, pub)) {
		t.Fatalf("private key %s… does not give the example's public key", priv[:8])
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[:32]), Y: new(big.Int).SetBytes(raw[32:])},
		D:         new(big.Int).SetBytes(vh(t, priv)),
	}
}

// Annex E.1 and E.2 (pages 306-308): the xDLMS InitiateRequest carrying a
// dedicated key, authenticated and encrypted with the global key; E.4 and
// E.5 (pages 310-311): the InitiateResponse, protected the same way.
const (
	vecInitReq  = "01011000112233445566778899AABBCCDDEEFF0000065F1F0400007E1F04B0"
	vecInitReqC = "801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE68" + "41DB204D39EE6FDB8E356855"
	vecInitRes  = "0800065F1F0400007C1F04000007"
	vecInitResC = "891214A0845E475714383F65BC19" + "745CA235906525E4F3E1C893"
)

// Covers: SIG-IPE-049, SIG-IPE-051
func TestIEC6205653AnnexEInitiateProtection(t *testing.T) {
	key, ak, st := vh(t, vecEK), vh(t, vecAK), vh(t, vecST)
	for _, tc := range []struct{ name, plain, want string }{
		{"E.2 InitiateRequest", vecInitReq, "3001234567" + vecInitReqC},
		{"E.5 InitiateResponse", vecInitRes, "3001234567" + vecInitResC},
	} {
		got, err := Protect(0, SecAuthentication|SecEncryption, key, ak, st, vecIC, vh(t, tc.plain))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, vh(t, tc.want)) {
			t.Errorf("%s: %X, want %s", tc.name, got, tc.want)
		}
		back, ic, err := Unprotect(0, key, ak, st, got)
		if err != nil || ic != vecIC || !bytes.Equal(back, vh(t, tc.plain)) {
			t.Errorf("%s: does not open again: %X %v", tc.name, back, err)
		}
	}
}

// Annex E.3 (pages 308-311, Table E.3): the AARQ with a ciphered
// application context, LLS and the glo-initiateRequest of E.2. Our AARQ
// path turns the plain AARQ gosem builds into exactly these bytes.
//
// Covers: SIG-IPE-049, SIG-IPE-051
func TestIEC6205653AnnexEAARQ(t *testing.T) {
	head := "A109060760857405080103" + "A60A04084D4D4D0000BC614E" + "8A020780" + "8B0760857405080201" + "AC0A80083132333435363738"
	plain := vh(t, "6053"+head+"BE21041F"+vecInitReq)
	want := "6066" + head + "BE340432" + "2130" + "3001234567" + vecInitReqC
	tr := &SecureTransport{sec: Security{Suite: 0, Policy: SecAuthentication | SecEncryption, SystemTitle: vh(t, vecST), Key: vh(t, vecEK), AuthKey: vh(t, vecAK)}, nextIC: vecIC}
	got, err := tr.aarq(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, vh(t, want)) {
		t.Errorf("AARQ\n got %X\nwant %s", got, want)
	}
}

// Annex E.6 (pages 312-313, Table E.6): the AARE carrying the ciphered
// InitiateResponse of E.5; E.7 and E.8 (pages 313-314): RLRQ and RLRE
// carrying the same ciphered initiate APDUs.
//
// Covers: SIG-IPE-049
func TestIEC6205653AnnexEAAREAndRelease(t *testing.T) {
	head := "A109060760857405080103" + "A203020100" + "A305A103020100" + "A40A04084D4D4D0000BC614E"
	aare := vh(t, "6148"+head+"BE230421"+"281F"+"3001234567"+vecInitResC)
	tr := &SecureTransport{sec: Security{Suite: 0, Policy: SecAuthentication | SecEncryption, SystemTitle: vh(t, vecST2), Key: vh(t, vecEK), AuthKey: vh(t, vecAK)}, lastRecvIC: map[bool]uint32{}}
	got, err := tr.aare(aare)
	if err != nil {
		t.Fatal(err)
	}
	if want := vh(t, "6135"+head+"BE10040E"+vecInitRes); !bytes.Equal(got, want) {
		t.Errorf("AARE opened to %X, want %X", got, want)
	}
	if !bytes.Equal(tr.meterST, vh(t, vecST)) {
		t.Errorf("responding-AP-title read as %X", tr.meterST)
	}

	// RLRQ and RLRE: reason normal, then the same ciphered initiate APDUs.
	for _, tc := range []struct {
		name, apdu, plain string
	}{
		{"E.7 RLRQ", "6239" + "800100" + "BE340432" + "2130" + "3001234567" + vecInitReqC, vecInitReq},
		{"E.8 RLRE", "6328" + "800100" + "BE230421" + "281F" + "3001234567" + vecInitResC, vecInitRes},
	} {
		b := vh(t, tc.apdu)
		n, sz, err := getLen(b[1:])
		if err != nil || 1+sz+n != len(b) {
			t.Fatalf("%s: length %d does not match %d bytes", tc.name, n, len(b))
		}
		items, err := parseTLVs(b[1+sz:])
		if err != nil || len(items) != 2 || items[1].tag != 0xBE {
			t.Fatalf("%s: %v %v", tc.name, items, err)
		}
		ui := items[1].val[2:] // 04 len
		plain, _, err := Unprotect(0, vh(t, vecEK), vh(t, vecAK), vh(t, vecST), ui[2:])
		if err != nil || !bytes.Equal(plain, vh(t, tc.plain)) {
			t.Errorf("%s: user-information opens to %X (%v)", tc.name, plain, err)
		}
	}
}

// Clause 5.7.2.4.10, Table 30 (pages 120-121): glo-get-request with
// authentication only, encryption only and authenticated encryption, as
// our transport sends them.
//
// Covers: SIG-IPE-049
func TestIEC6205653Table30GloGetRequest(t *testing.T) {
	get := vh(t, "C0010000080000010000FF0200")
	for _, tc := range []struct {
		policy byte
		want   string
	}{
		{SecAuthentication, "C81E10" + "01234567" + "C0010000080000010000FF0200" + "06725D910F9221D263877516"},
		{SecEncryption, "C81220" + "01234567" + "411312FF935A47566827C467BC"},
		{SecAuthentication | SecEncryption, "C81E30" + "01234567" + "411312FF935A47566827C467BC" + "7D825C3BE4A77C3FCC056B6B"},
	} {
		tr := &SecureTransport{sec: Security{Suite: 0, Policy: tc.policy, SystemTitle: vh(t, vecST), Key: vh(t, vecEK), AuthKey: vh(t, vecAK)}, nextIC: vecIC}
		got, err := tr.cipher(get)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, vh(t, tc.want)) {
			t.Errorf("policy %#x: %X, want %s", tc.policy, got, tc.want)
		}
	}
}

// Clause 5.7.4, Table 33 (page 127): HLS mechanism 5 (GMAC); the client
// is 4D4D4D0000000001 (IC 1), the server 4D4D4D0000BC614E (IC 01234567).
//
// Covers: SIG-IPE-046, SIG-IPE-052
func TestIEC6205653Table33HLSGMAC(t *testing.T) {
	client, server := vh(t, "4D4D4D0000000001"), vh(t, "4D4D4D0000BC614E")
	ctos, stoc := []byte("K56iVagY"), []byte("P6wRJ21F")
	if !bytes.Equal(ctos, vh(t, "4B35366956616759")) || !bytes.Equal(stoc, vh(t, "503677524A323146")) {
		t.Fatal("challenge text and hex differ")
	}
	h := &HLS{Mechanism: MechGMAC, Security: Security{Suite: 0, Key: vh(t, vecEK), AuthKey: vh(t, vecAK)}}
	fStoC, err := h.answer(client, server, stoc, ctos, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := vh(t, "10000000011A52FE7DD3E72748973C1E28"); !bytes.Equal(fStoC, want) {
		t.Errorf("f(StoC) %X, want %X", fStoC, want)
	}
	if err := h.check(client, server, ctos, stoc, vh(t, "1001234567FE1466AFB3DBCD4F9389E2B7")); err != nil {
		t.Errorf("the example's f(CtoS) does not verify: %v", err)
	}
}

// Clause 5.7.4, Table 34 (page 128): HLS mechanism 7 (ECDSA P-256). The
// signatures are the example's; ours are random but must verify alike.
//
// Covers: SIG-IPE-052
func TestIEC6205653Table34HLSECDSA(t *testing.T) {
	client, server := vh(t, vecST), vh(t, vecST2)
	kc := vecKey(t, "E9A045346B2057F1820318AB125493E9AB36CE590011C0FF30090858A118DD2E",
		"917DBFECA43307375247989F07CC23F53D4B963AF8026C749DB33852011056DFDBE8327BD69CC149F018A8E446DDA6C55BCD78E596A56D403236233F93CC89B3")
	ks := vecKey(t, "B582D8C910018302BA3131BAB9BB6838108BB9408C30B2E49285985256A59038",
		"E4D07CEB0A5A6DA9D2228B054A1F5E295E1747A963974AF75091A0B0BC2FB92DA7D2ABD9FDD41579F36A1C8171A0CB638221DF1949FD95C8FAE148896920450D")
	ctos := vh(t, "2CA1FC2DE9CD03B5E8E234CEA16F2853F6DC5F54526F4F4995772A50FB7E63B3")
	stoc := vh(t, "18E95FFE3AD0DCABDC5D0D141DC987E270CB0A395948D4231B09DE6579883657")
	fStoC := vh(t, "C5C6D6620BDB1A39FCE50F4D64F0DB712D6FB57A64030B0C297E1250DC859660D3B1FA334AD80411807369F5DD3BC17B59894C9E9C11C59376580D15A2646D16")
	fCtoS := vh(t, "946C2E3E4F18291571F4A45ACB7086100574694A3BAF67D2D147FE8F92481A5AB2186C5CBC3F80E94482D9388B85C6A73E5FD687F09773C1F615AA2A905ED057")

	// We are the client: the meter's f(CtoS) verifies with its key.
	us := &HLS{Mechanism: MechECDSA, Security: Security{Suite: 1}, SignKey: kc, MeterKey: &ks.PublicKey}
	if err := us.check(client, server, ctos, stoc, fCtoS); err != nil {
		t.Errorf("the example's f(CtoS) does not verify: %v", err)
	}
	// The example's f(StoC), checked as the server would.
	meter := &HLS{Mechanism: MechECDSA, Security: Security{Suite: 1}, MeterKey: &kc.PublicKey}
	if err := meter.check(server, client, stoc, ctos, fStoC); err != nil {
		t.Errorf("the example's f(StoC) does not verify: %v", err)
	}
	// Our own f(StoC) is signed over the same data.
	ours, err := us.answer(client, server, stoc, ctos, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := meter.check(server, client, stoc, ctos, ours); err != nil {
		t.Errorf("our f(StoC) does not verify as the example's does: %v", err)
	}
}

// Annex I.1, Table I.1 (pages 358-359): key_agreement with the Ephemeral
// Unified Model C(2e, 0s): the signed offers cover key_id ‖ ephemeral
// key, the KDF gives the global unicast key, and the example's ACTION
// request is what our agreeKeys sends for these values.
//
// Covers: SIG-IPE-070
func TestIEC6205653AnnexI1KeyAgreement(t *testing.T) {
	kc := vecKey(t, vecPrivC, vecPubC)
	ks := vecKey(t, vecPrivS, vecPubS)
	epubC := "2914D60E10AB705F62ED6CC349D7CB99B9AB3F3978E59278C7AF595B3AF987941372DAB6D5AF1FA867E134167E6F23DE664A6693E05F43414611058D1B48F894"
	epubS := "95F41066009B185B074F5FFFF736B71C325FCADB2BC0CF1A4F4B17BBE7AB81D62946506BC8169C7B539B39A5D8463787F449C9BD2583FA67A1075B0DBFC638BA"
	ec := vecKey(t, "1BAC19FC1D52A1E5102622EDFA36584C05E12FA8CDEAA450F2F1E9A7DCCF7628", epubC)
	vecKey(t, "34A8C23A34DBB519D09B245754C85A6CFE05D14A063EFA5AA41545AA8241EFAE", epubS)
	// The signature as the table lists it (the ACTION listing has one
	// digit too many: F-172).
	sigC := "06F0607702AA0E2435A183E2F6B1ECD19629712E389A213610C03F77B2590860EA840AF5C3FA1F2BCDF055D4744E9A01CE9A0E55026BCAA4EEBEB764CED64BB3"
	sigS := "A92995225CEE004ED4376057EEE9536E97EE6F5BAE43E59BDBBD515A89FB2CB83F2A270871A31B09338DCF0D1797466087908BA4A6ED8FD48B9EA067DA67DC4D"

	if _, err := openOffer(elliptic.P256(), &kc.PublicKey, vh(t, epubC+sigC), []byte{KeyGlobalUnicast}); err != nil {
		t.Errorf("client offer: %v", err)
	}
	if _, err := openOffer(elliptic.P256(), &kc.PublicKey, vh(t, epubC+sigC), nil); err == nil {
		t.Error("the client offer verified without the key_id in front")
	}

	// The client's ACTION request (method 3 of security setup 0.0.43.0.0.255).
	param := axdr.CreateAxdrArray([]*axdr.DlmsData{axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(KeyGlobalUnicast), octetParam(vh(t, epubC+sigC))})})
	req, err := gdlms.CreateActionRequestNormal(0x40, *gdlms.CreateMethodDescriptor(ClassSecuritySetup, "0.0.43.0.0.255", 3), param).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := vh(t, "C30140"+"0040"+"00002B0000FF"+"03"+"01"+"0101"+"0202"+"1600"+"098180"+epubC+sigC); !bytes.Equal(req, want) {
		t.Errorf("ACTION request %X\nwant %X", req, want)
	}

	// The server's ACTION response, read as agreeKeys reads it.
	ret, err := actionReturn(vh(t, "C70140"+"00"+"01"+"00"+"0101"+"0202"+"1600"+"098180"+epubS+sigS))
	if err != nil {
		t.Fatal(err)
	}
	f := structItems(structItems(ret)[0])
	id, _ := enumValue(f[0])
	data, err := octetValue(f[1])
	if err != nil || id != KeyGlobalUnicast {
		t.Fatalf("response item %v %X %v", id, data, err)
	}
	pub, err := openOffer(elliptic.P256(), &ks.PublicKey, data, []byte{id})
	if err != nil {
		t.Fatalf("server offer: %v", err)
	}
	z, err := ecdhZ(ec, pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := vh(t, "C1CF8FE7891AEF3617D7190795E61FE6C24EFC3CCA2E08469BAD1A225CE6EA08"); !bytes.Equal(z, want) {
		t.Errorf("Z %X", z)
	}
	if got := kdf(1, z, Suite(1).algorithmFor(id), vh(t, vecST), vh(t, vecST2)); !bytes.Equal(got, vh(t, "C5F4512846EDE51CFB8CCF59F08A694E")) {
		t.Errorf("global unicast key %X", got)
	}
	// Table 8: an agreed master key is derived for AES key wrap.
	if !bytes.Equal(Suite(1).algorithmFor(KeyMaster), vh(t, "60857405080302")) || !bytes.Equal(Suite(2).algorithmFor(KeyMaster), vh(t, "60857405080303")) ||
		!bytes.Equal(Suite(2).algorithmFor(KeyAuthentication), vh(t, "60857405080301")) {
		t.Error("algorithm IDs differ from Table 8")
	}
}

// The ACCESS request of Table F.10 (page 333), which the general-ciphering
// examples protect.
const vecAccessRequest = "D9" + "40000000" + "00" + "04" +
	"01" + "0001" + "0000600100FF" + "02" + "01" + "0008" + "0000010000FF" + "02" +
	"02" + "0014" + "00000D0000FF" + "07" + "02" + "0014" + "00000D0000FF" + "08" +
	"04" + "00" + "00" +
	"0104" + "0203090100090CFFFFFFFFFFFFFF00000000000901FF" + "0203090101090CFFFFFFFFFFFFFF00000000000901FF" +
	"0203090102090CFFFFFFFFFFFFFF00000000000901FF" + "0203090103090CFFFFFFFFFFFFFF00000000000901FF" +
	"0104" + "020809010011FF11FF11FF11FF11FF11FF11FF" + "0208090101" + "1102" + "110111011101110111011101" +
	"0208090102" + "11FF11FF11FF11FF11FF11FF11FF" + "02080901031101110211021102110211021102"

// General-ciphering examples of Table 31 (pages 122-124) and annex I.2
// (One-Pass Diffie-Hellman, pages 360-363) and I.3 (Static Unified Model,
// pages 363-366).
const (
	vecGCHead1 = "DD" + "08" + vecTxC + "08" + vecST + "08" + vecST2 + "00" + "00"
	vecGCHead2 = "DD" + "08" + vecTxS + "08" + vecST2 + "08" + vecST + "00" + "00"
	vecI2ReqKD = "C323C2BD45711DE4688637D919F92E9DB8FB2DFC213A88D21C9DC8DCBA917D8170511DE1BADB360D50058F794B0960AE11FA28D392CFF907A62D13E3357B1DC0" +
		"B51BE089D0B682863B2217201E73A1A9031968A9B4121DCBC3281A69739AF87429F5B3AC5471E7B6A04A2C0F2F8A25FD772A317DF97FC5463FEAC248EB8AB8BE"
	vecI2ResKD = "6439724714B47CD9CB988897D8424AB946DCD083D37A954637616011B9C2378773295F0F850D8DAFD1BBE9FE666E53E4F097CD10B38B69622152724A90987444" +
		"E1FF47974A1F6931A6502F58147463F0E8CC517D47F55B0AC56DD8AC5C9D0E481934F2D90F9893016BD82B6E3FFE21FF1588F3278B4E9D98EB4FB62ADD64B380"
	vecI2ReqCC = "3100000000" + "F435069679270C5BF4425EE5777402A6C8D51C620EED52DBB188378B836E2857D5C053E6DDF27FA87409AEF502CD9618AE47017C010224FD109CC0BEB21E742D44AB40CD11908743EC90EC8C40E221D517F72228E1A26E827F43DC18ED27B5F458D66508B05A2A4CC6FED178C881AFC3BC67064689BE8BB41C80ABB3C114A31F4CB03B8B64C7E0B4CE77B2399C93347858888F92239713B38DF01C4858245827A92EF334172EA636B31CBBDF2A96AD5D035F66AA38F1A2D97D4BBA99622E6B5F18789CECB2DFB3937D9F3E17F8B472098E6563238F37528374809836002AEA6E7012D2ADFAA7"
	vecI2ResCC = "3100000000" + "B3FFCAA594642D8319CEC6B2A233E2BF4621D6991B97E4565B986E8CCBE9A299D8E7869723638FF6BB20E66E175E6F2D762CFD26B3D58733"
	vecI3ReqCC = "3100000000" + "607581D83815281B561904E6A72B83BF3FB0B1F2A0A23A82A804B39911F6CB1B4EF9B6F76C6338ED058014FFBF4A13A162E0EED11EEB8F597757A18215F28E1D3FC2D44586C4B8AFE4500B535B579506CDB925CBEFF7F1CF6BF96C583B9CF588FE8F6B01A574824D7CEC597F057FFA8700AF12AD63A7FA72040439F4392C089B265F9EB1AC308239906DC04E1A8712ABE383CF92349842EBA166EF2E9EB2F53D0DBA025D79875463398BBC3007BC4A6FC12780C21EE1ABF080BF0FA926242834C0AC30D55A1EF8856E7DED48621F17FDF4D5B54EDDADD874119251049B6AEE111C12FBC2FEAF"
	vecI3ResCC = "3100000000" + "3CF971CD09E0B1C5B89E7BB52C1B39923D14C4A160D7DDB3F2DE8AD255C625F407F04031CD95F4F261E23E823B73490CD6CB593A140CD95F"
)

// openCT is the GCM ciphertext of SC ‖ IC ‖ C ‖ T opened without the tag
// (the counter stream), so a key and nonce can be checked where the tag
// cannot (F-171).
func openCT(t *testing.T, key, systemTitle, content []byte) []byte {
	t.Helper()
	_, nonce, err := gcmFor(key, systemTitle, beUint32(content[1:5]))
	if err != nil {
		t.Fatal(err)
	}
	return ctr(key, nonce, content[5:len(content)-tagSize])
}

// Covers: SIG-IPE-067
func TestIEC6205653AnnexI2OnePass(t *testing.T) {
	kc := vecKey(t, vecPrivC, vecPubC)
	ks := vecKey(t, vecPrivS, vecPubS)
	akc := vecKey(t, vecAKC, vecAKCp)
	aks := vecKey(t, vecAKS, vecAKSp)
	vecKey(t, "47DAB03842E5B6E74828EF4F449B378D7DD1A5DAE1FFCA5AE0B0BE0AD18EC57E", vecI2ReqKD[:128])
	vecKey(t, "819B1BEACC955E29139E368BF4119C126FF799EE16BCBA3F45C1EF16749BCB95", vecI2ResKD[:128])
	req := vh(t, vecGCHead1+"01"+"02"+"0101"+"8180"+vecI2ReqKD+"81EB"+vecI2ReqCC)
	res := vh(t, vecGCHead2+"01"+"02"+"0101"+"8180"+vecI2ResKD+"3D"+vecI2ResCC)
	if len(req) != 401 || len(res) != 226 {
		t.Fatalf("APDU lengths %d and %d, the example says 401 and 226", len(req), len(res))
	}

	// Decode and re-encode both APDUs byte for byte.
	for _, b := range [][]byte{req, res} {
		g, err := decodeGeneralCiphering(b)
		if err != nil {
			t.Fatal(err)
		}
		if g.keyInfo == nil || g.keyInfo.choice != keyInfoAgreed || !bytes.Equal(g.keyInfo.params, []byte{agreeOnePass}) {
			t.Fatalf("key-info %+v", g.keyInfo)
		}
		if !bytes.Equal(g.encode(), b) {
			t.Errorf("re-encoded %X", g.encode())
		}
	}

	// The server (party V) derives the request key: EK-GC-C.
	g, _ := decodeGeneralCiphering(req)
	pub, err := openOffer(elliptic.P256(), &kc.PublicKey, g.keyInfo.data, nil)
	if err != nil {
		t.Fatal(err)
	}
	z, _ := ecdhZ(aks, pub)
	if !bytes.Equal(z, vh(t, "0D4385BA0DD756CBCAB9887EB538396EE8F090A14C1079B4359F115B977F4615")) {
		t.Errorf("Z-GC-C %X", z)
	}
	keyC := kdf(1, z, vh(t, vecAlg), g.originator, g.recipient)
	if !bytes.Equal(keyC, vh(t, "59A71FD81C929A86A99438DA17A66C05")) {
		t.Errorf("EK-GC-C %X", keyC)
	}
	if got := openCT(t, keyC, g.originator, g.content); !bytes.Equal(got, vh(t, vecAccessRequest)) {
		t.Errorf("the request does not decrypt to the Table F.10 ACCESS request: %X", got)
	}

	// We are the client (party V of the response): recipientKey gives
	// EK-GC-S.
	sec := Security{Suite: 1, KAKey: akc, MeterSignKey: &ks.PublicKey}
	gs, _ := decodeGeneralCiphering(res)
	keyS, err := sec.recipientKey(gs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyS, vh(t, "F0184BDA9466BFA4601A64A7EF46504A")) {
		t.Errorf("EK-GC-S %X", keyS)
	}
	if got := openCT(t, keyS, gs.originator, gs.content); len(got) == 0 || got[0] != 0xDA {
		t.Errorf("the response does not decrypt to an ACCESS response: %X", got)
	}
}

// Covers: SIG-IPE-067
func TestIEC6205653AnnexI3Static(t *testing.T) {
	akc := vecKey(t, vecAKC, vecAKCp)
	aks := vecKey(t, vecAKS, vecAKSp)
	req := vh(t, vecGCHead1+"01"+"02"+"0102"+"00"+"81EB"+vecI3ReqCC)
	res := vh(t, vecGCHead2+"01"+"02"+"0102"+"00"+"3D"+vecI3ResCC)
	if len(req) != 272 || len(res) != 97 {
		t.Fatalf("APDU lengths %d and %d, the example says 272 and 97", len(req), len(res))
	}
	z, _ := ecdhZPub(akc, &aks.PublicKey)
	if !bytes.Equal(z, vh(t, "B1455B2AD5F68BCFFE6AD5412BA89548ACA7E0CBF4B1560D6A57496F15E931AD")) {
		t.Errorf("Z %X", z)
	}

	// The client as originator: the key of the request, from the header
	// alone (Nonce U = 08 ‖ transaction-id in party U info).
	sec := Security{Suite: 1, GeneralKey: GenKeyStatic, KAKey: akc, MeterKAKey: &aks.PublicKey}
	g, err := decodeGeneralCiphering(req)
	if err != nil {
		t.Fatal(err)
	}
	keyC, ki, err := sec.originatorKey(g.generalHeader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyC, vh(t, "56C46B57DF675515C31025455822514A")) {
		t.Errorf("EK-GC-C %X", keyC)
	}
	if got := (&generalCiphering{generalHeader: g.generalHeader, keyInfo: ki, content: g.content}).encode(); !bytes.Equal(got, req) {
		t.Errorf("request encodes as %X", got)
	}
	if got := openCT(t, keyC, g.originator, g.content); !bytes.Equal(got, vh(t, vecAccessRequest)) {
		t.Errorf("the request does not decrypt to the Table F.10 ACCESS request: %X", got)
	}

	// The client as recipient of the response: EK-GC-S.
	gs, err := decodeGeneralCiphering(res)
	if err != nil {
		t.Fatal(err)
	}
	keyS, err := sec.recipientKey(gs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyS, vh(t, "FC1314F7DE033B7DD19C80DBCF9FF2C5")) {
		t.Errorf("EK-GC-S %X", keyS)
	}
	// Both examples carry the same ACCESS exchange under different keys.
	i2, _ := decodeGeneralCiphering(vh(t, vecGCHead2+"01"+"02"+"0101"+"8180"+vecI2ResKD+"3D"+vecI2ResCC))
	if a, b := openCT(t, keyS, gs.originator, gs.content), openCT(t, vh(t, "F0184BDA9466BFA4601A64A7EF46504A"), i2.originator, i2.content); !bytes.Equal(a, b) || a[0] != 0xDA {
		t.Errorf("the I.2 and I.3 responses decrypt to different APDUs:\n%X\n%X", a, b)
	}
}

// The Table 31 / annex I tags do not verify with the authenticated data
// of Table 28 and the authentication key Table 31 names (F-171). This test
// records that, so a corrected edition shows up as a failure to revisit.
func TestIEC6205653Table31TagIsNotReproducible(t *testing.T) {
	g, err := decodeGeneralCiphering(vh(t, vecGCHead1+"01"+"02"+"0101"+"8180"+vecI2ReqKD+"81EB"+vecI2ReqCC))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = unprotectAAD(1, vh(t, "59A71FD81C929A86A99438DA17A66C05"), vh(t, vecAK), g.originator, g.content, g.generalHeader.encode())
	if err == nil {
		t.Fatal("the Table 31 request tag now verifies: close F-171 and turn this into a positive vector")
	}
}

// The xDLMS initiate request is authenticated and encrypted whenever it
// carries a dedicated key, whatever the configured policy (5.5.1), and an
// initiate response to it that is not is refused.
//
// Covers: SIG-IPE-051
func TestDedicatedKeyInitiateIsAuthenticatedEncrypted(t *testing.T) {
	// gosem's initiate request: no dedicated key, conformance 007E1F, 1200.
	ir := vh(t, "0100000006"+"5F1F0400007E1F"+"04B0")
	plain := encodeTLVs(0x60, []tlv{{0xA1, vh(t, "060760857405080103")}, {0xBE, concat([]byte{0x04}, putLen(len(ir)), ir)}})
	for _, policy := range []byte{SecAuthentication, SecEncryption, SecAuthentication | SecEncryption} {
		tr := &SecureTransport{sec: Security{Suite: 0, Policy: policy, Dedicated: true, SystemTitle: vh(t, vecST), Key: vh(t, vecEK), AuthKey: vh(t, vecAK)}, nextIC: vecIC}
		out, err := tr.aarq(plain)
		if err != nil {
			t.Fatal(err)
		}
		// BE len 04 len 21 len SC
		i := bytes.IndexByte(out, 0xBE)
		if i < 0 || out[i+4] != 0x21 || out[i+6] != SecAuthentication|SecEncryption {
			t.Errorf("policy %#x: the initiate request is protected as %X", policy, out[i:])
		}
		// A response protected with authentication only is refused.
		p, _ := Protect(0, SecAuthentication, tr.sec.Key, tr.sec.AuthKey, vh(t, vecST2), 5, vh(t, vecInitRes))
		ui := concat([]byte{0x28}, putLen(len(p)), p)
		aare := encodeTLVs(0x61, []tlv{{0xA1, vh(t, "060760857405080103")}, {0xA2, vh(t, "020100")}, {0xA4, vh(t, "0408"+vecST2)}, {0xBE, concat([]byte{0x04}, putLen(len(ui)), ui)}})
		if _, err := tr.aare(aare); err == nil {
			t.Errorf("policy %#x: an authentication-only initiate response to a dedicated key was accepted", policy)
		}
	}
}

// The key-set bit must be 0 with the dedicated key and in general
// ciphering (Table 27, Table 29 note); general-ciphering names the
// broadcast key by identified-key instead (5.5.3).
//
// Covers: SIG-IPE-620
func TestKeySetBitWhereItMustBeZero(t *testing.T) {
	key, bkey, ak, st := vh(t, vecEK), bytes.Repeat([]byte{0x42}, 16), vh(t, vecAK), vh(t, vecST2)
	res := vh(t, "C4010000")
	p, err := Protect(0, SecAuthentication|SecEncryption|SecBroadcastKey, bkey, ak, st, 9, res)
	if err != nil {
		t.Fatal(err)
	}
	tr := &SecureTransport{sec: Security{Suite: 0, Policy: 0x30, Key: key, AuthKey: ak, BroadcastKey: bkey, SystemTitle: vh(t, vecST)}, meterST: st, dedKey: key, lastRecvIC: map[bool]uint32{}}
	for _, apdu := range [][]byte{
		concat([]byte{0xD4}, putLen(len(p)), p),   // ded-get-response
		encodeGeneralGloDed(TagGeneralDed, st, p), // general-ded-ciphering
	} {
		if _, err := tr.incoming(apdu); err == nil {
			t.Errorf("%X: the key-set bit was accepted with the dedicated key", apdu[:1])
		}
	}
	h := generalHeader{transactionID: vh(t, vecTxC), originator: st, recipient: vh(t, vecST), dateTime: nil}
	gp, _ := protectAAD(0, SecAuthentication|SecEncryption|SecBroadcastKey, bkey, ak, st, 10, res, h.encode())
	g := &generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoIdentified, keyID: KeyGlobalUnicast}, content: gp}
	if _, err := tr.incoming(g.encode()); err == nil {
		t.Error("general-ciphering with the key-set bit set was accepted")
	}
	// Named by identified-key, the broadcast key opens it.
	gp, _ = protectAAD(0, SecAuthentication|SecEncryption, bkey, ak, st, 11, res, h.encode())
	g = &generalCiphering{generalHeader: h, keyInfo: &keyInfo{choice: keyInfoIdentified, keyID: KeyGlobalBroadcast}, content: gp}
	if out, err := tr.incoming(g.encode()); err != nil || !bytes.Equal(out, res) {
		t.Errorf("general-ciphering under the identified broadcast key: %X %v", out, err)
	}
}

// A server challenge equal to ours, or of a length outside Table 32, is
// refused before we answer it (5.2.2.2.4, Table 32).
//
// Covers: SIG-IPE-052
func TestServerChallengeChecks(t *testing.T) {
	ctos := bytes.Repeat([]byte{1}, 32)
	for _, tc := range []struct {
		mech byte
		stoc []byte
		ok   bool
	}{
		{MechGMAC, ctos, false},
		{MechGMAC, bytes.Repeat([]byte{2}, 7), false},
		{MechGMAC, bytes.Repeat([]byte{2}, 8), true},
		{MechSHA256, bytes.Repeat([]byte{2}, 64), true},
		{MechSHA256, bytes.Repeat([]byte{2}, 65), false},
		{MechECDSA, bytes.Repeat([]byte{2}, 31), false},
		{MechECDSA, bytes.Repeat([]byte{2}, 32), true},
		{MechHLS, bytes.Repeat([]byte{2}, 4), true},
		{MechHLS, ctos, false},
	} {
		if err := checkStoC(tc.mech, tc.stoc, ctos); (err == nil) != tc.ok {
			t.Errorf("mechanism %d, %d-octet challenge: %v", tc.mech, len(tc.stoc), err)
		}
	}
}
