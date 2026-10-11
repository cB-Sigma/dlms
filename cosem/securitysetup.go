package cosem

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// ClassSecuritySetup is the security setup interface class.
const ClassSecuritySetup = 64

// Security policy bits (security setup version 1).
const (
	PolicyAuthRequest   byte = 0x04
	PolicyEncRequest    byte = 0x08
	PolicySignRequest   byte = 0x10
	PolicyAuthResponse  byte = 0x20
	PolicyEncResponse   byte = 0x40
	PolicySignResponse  byte = 0x80
	PolicyAuthenticated      = PolicyAuthRequest | PolicyAuthResponse
	PolicyEncrypted          = PolicyEncRequest | PolicyEncResponse
	PolicySigned             = PolicySignRequest | PolicySignResponse
)

// KeyPairs names the key pairs of generate_key_pair and
// generate_certificate_request.
var KeyPairs = map[string]byte{"signing": 0, "key-agreement": 1, "tls": 2}

// CertEntities names the certificate entities.
var CertEntities = map[string]byte{"server": 0, "client": 1, "ca": 2, "other": 3}

// KeyNames name the keys key_transfer and key_agreement change.
var KeyNames = map[string]byte{"unicast": KeyGlobalUnicast, "broadcast": KeyGlobalBroadcast, "authentication": KeyAuthentication}

// SecuritySetup is the security setup object (class 64, version 1) of an
// open association: Client and Secure are the association's, OBIS the
// object's logical name (0.0.43.0.e.255).
type SecuritySetup struct {
	Client gdlms.Client
	Secure *SecureTransport
	OBIS   string
}

// Action invokes a security setup method and returns its return
// data (nil when it has none).
func (s SecuritySetup) Action(method int8, param *axdr.DlmsData) (*axdr.DlmsData, error) {
	_ = s.Secure.TakeAction()
	if err := s.Client.ActionRequest(gdlms.CreateMethodDescriptor(ClassSecuritySetup, s.OBIS, method), param); err != nil {
		if f := s.Secure.LastFailure(); f != nil {
			return nil, f
		}
		return nil, fmt.Errorf("security setup method %d: %w", method, err)
	}
	return actionReturn(s.Secure.TakeAction())
}

// actionReturn decodes the return data of an action-response-normal.
func actionReturn(apdu []byte) (*axdr.DlmsData, error) {
	if len(apdu) < 5 || apdu[0] != 0xC7 || apdu[1] != 0x01 {
		return nil, errors.New("no action response was seen")
	}
	if apdu[3] != 0 {
		return nil, fmt.Errorf("the meter answered with action result %d", apdu[3])
	}
	if apdu[4] == 0 {
		return nil, nil
	}
	if len(apdu) < 7 || apdu[5] != 0 {
		return nil, errors.New("the action response carries no data")
	}
	src := append([]byte(nil), apdu[6:]...)
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return nil, fmt.Errorf("the action response data does not decode: %w", err)
	}
	return &d, nil
}

func octetParam(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }

func octetValue(d *axdr.DlmsData) ([]byte, error) {
	if d != nil {
		if s, ok := d.Value.(string); ok {
			return hex.DecodeString(s)
		}
	}
	return nil, errors.New("the meter returned no octet string")
}

func structItems(d *axdr.DlmsData) []*axdr.DlmsData {
	if d == nil {
		return nil
	}
	v, _ := d.Value.([]*axdr.DlmsData)
	return v
}

func enumValue(d *axdr.DlmsData) (byte, bool) {
	if d == nil {
		return 0, false
	}
	v, ok := d.Value.(uint8)
	return v, ok
}

// PolicyBits is the version 1 security_policy for an APDU policy and
// signing.
func PolicyBits(policy byte, signing bool) byte {
	var b byte
	if policy&SecAuthentication != 0 {
		b |= PolicyAuthenticated
	}
	if policy&SecEncryption != 0 {
		b |= PolicyEncrypted
	}
	if signing {
		b |= PolicySigned
	}
	return b
}

// Activate raises the meter's security policy.
func (s SecuritySetup) Activate(bits byte) error {
	_, err := s.Action(1, axdr.CreateAxdrEnum(bits))
	return err
}

// TransferKeys sends new keys (by key_id) wrapped with the master key.
func (s SecuritySetup) TransferKeys(masterKey []byte, keys map[byte][]byte) error {
	if masterKey == nil {
		return errors.New("key_transfer needs the master key (masterKey)")
	}
	var list []*axdr.DlmsData
	for _, id := range sortedIDs(keys) {
		w, err := WrapKey(masterKey, keys[id])
		if err != nil {
			return err
		}
		list = append(list, KeyTransferItem(id, w))
	}
	_, err := s.Action(2, axdr.CreateAxdrArray(list))
	return err
}

// KeyTransferItem is one {key_id, wrapped key} of key_transfer.
func KeyTransferItem(id byte, wrapped []byte) *axdr.DlmsData {
	return axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(id), octetParam(wrapped)})
}

func sortedIDs(keys map[byte][]byte) []byte {
	var ids []byte
	for id := byte(0); id <= KeyMaster; id++ {
		if _, ok := keys[id]; ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// AgreeKeys runs key_agreement for the given key IDs with the signing
// keys and system title of sec and returns the agreed keys.
func (s SecuritySetup) AgreeKeys(sec *Security, ids []byte) (map[byte][]byte, error) {
	if sec.SignKey == nil || sec.MeterSignKey == nil {
		return nil, errors.New("key_agreement needs signingKey and meterSigningKey (suite 1 or 2)")
	}
	meterST, _ := s.Secure.Challenge()
	if len(meterST) != 8 {
		return nil, errors.New("key_agreement needs the meter's system title, which the association did not give")
	}
	eph := map[byte]*ecdsa.PrivateKey{}
	var list []*axdr.DlmsData
	for _, id := range ids {
		e, offer, err := ephemeralOffer(sec.SignKey, []byte{id})
		if err != nil {
			return nil, err
		}
		eph[id] = e
		list = append(list, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(id), octetParam(offer)}))
	}
	ret, err := s.Action(3, axdr.CreateAxdrArray(list))
	if err != nil {
		return nil, err
	}
	out := map[byte][]byte{}
	for _, it := range structItems(ret) {
		f := structItems(it)
		if len(f) != 2 {
			return nil, errors.New("the meter's key_agreement answer is not {key_id, key data}")
		}
		id, _ := enumValue(f[0])
		data, err := octetValue(f[1])
		if err != nil || eph[id] == nil {
			return nil, errors.New("the meter's key_agreement answer names a key we did not offer")
		}
		pub, err := openOffer(sec.SignKey.Curve, sec.MeterSignKey, data, []byte{id})
		if err != nil {
			return nil, fmt.Errorf("the meter's key_agreement answer: %w", err)
		}
		z, err := ecdhZ(eph[id], pub)
		if err != nil {
			return nil, err
		}
		out[id] = kdf(sec.Suite, z, sec.Suite.algorithmFor(id), sec.SystemTitle, meterST)
	}
	for _, id := range ids {
		if out[id] == nil {
			return nil, fmt.Errorf("the meter agreed no key %d", id)
		}
	}
	return out, nil
}

// GenerateKeyPair asks the meter to generate a key pair (0 signing, 1
// key agreement, 2 TLS).
func (s SecuritySetup) GenerateKeyPair(kind byte) error {
	_, err := s.Action(4, axdr.CreateAxdrEnum(kind))
	return err
}

// CertificateRequest asks the meter for a PKCS #10 request for one of its
// key pairs and checks its signature.
func (s SecuritySetup) CertificateRequest(kind byte) (*x509.CertificateRequest, error) {
	ret, err := s.Action(5, axdr.CreateAxdrEnum(kind))
	if err != nil {
		return nil, err
	}
	der, err := octetValue(ret)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("the meter's certificate request does not parse: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the meter's certificate request is not signed by its key: %w", err)
	}
	return csr, nil
}

// ImportCertificate gives the meter a certificate.
func (s SecuritySetup) ImportCertificate(c *x509.Certificate) error {
	_, err := s.Action(6, octetParam(c.Raw))
	return err
}

// CertID identifies a certificate on the meter: by entity, type and
// system title, or by serial number and issuer.
type CertID struct {
	BySerial     bool
	Entity, Type byte
	SystemTitle  []byte
	Serial       *big.Int
	Issuer       []byte // DER issuer name
}

func (id CertID) param() *axdr.DlmsData {
	if id.BySerial {
		return axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(1),
			axdr.CreateAxdrStructure([]*axdr.DlmsData{octetParam(id.Serial.Bytes()), octetParam(id.Issuer)})})
	}
	return axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(0),
		axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrEnum(id.Entity), axdr.CreateAxdrEnum(id.Type), octetParam(id.SystemTitle)})})
}

// ExportCertificate reads a certificate the meter holds.
func (s SecuritySetup) ExportCertificate(id CertID) (*x509.Certificate, error) {
	ret, err := s.Action(7, id.param())
	if err != nil {
		return nil, err
	}
	der, err := octetValue(ret)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("the meter's certificate does not parse: %w", err)
	}
	return c, nil
}

// RemoveCertificate removes a certificate from the meter.
func (s SecuritySetup) RemoveCertificate(id CertID) error {
	_, err := s.Action(8, id.param())
	return err
}

// CertInfo is one entry of the certificates attribute.
type CertInfo struct {
	Entity  byte   `json:"entity"`
	Type    byte   `json:"type"`
	Serial  string `json:"serial"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// Certificates reads the certificates attribute (6).
func (s SecuritySetup) Certificates() ([]CertInfo, error) {
	var d axdr.DlmsData
	if err := s.Client.GetRequest(gdlms.CreateAttributeDescriptor(ClassSecuritySetup, s.OBIS, 6), &d); err != nil {
		return nil, err
	}
	var out []CertInfo
	for _, it := range structItems(&d) {
		f := structItems(it)
		if len(f) < 5 {
			return nil, errors.New("a certificates entry is not in the expected form")
		}
		e, _ := enumValue(f[0])
		t, _ := enumValue(f[1])
		serial, _ := octetValue(f[2])
		issuer, _ := octetValue(f[3])
		subject, _ := octetValue(f[4])
		out = append(out, CertInfo{Entity: e, Type: t, Serial: hex.EncodeToString(serial), Issuer: nameString(issuer), Subject: nameString(subject)})
	}
	return out, nil
}

// nameString shows a DER name as text when it parses.
func nameString(der []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err == nil && len(rest) == 0 {
		var n pkix.Name
		n.FillFromRDNSequence(&rdn)
		return n.String()
	}
	return hex.EncodeToString(der)
}
