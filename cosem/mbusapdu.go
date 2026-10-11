package cosem

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	v44 "github.com/cB-Sigma/schc/v44"
)

// DLMS/COSEM APDUs carried by another protocol, such as wireless and wired
// M-Bus (EN 13757-1:2021 9.2.1, CI 7Ch/7Dh from the meter): the meter's
// data-notification, plain or protected with general-glo-ciphering under
// the meter's global key, is opened with the same code as the pushes this
// package receives itself.

// Keys are the global keys to open a protected APDU with.
type Keys struct {
	Suite        Suite
	Key          []byte // global unicast encryption key
	AuthKey      []byte // authentication key (empty: none)
	BroadcastKey []byte // global broadcast key (optional)
	// SystemTitle is the sender's system title when the APDU does not
	// carry one (service-specific ciphering); general-glo carries its own.
	SystemTitle []byte
	// comp is the meter's V.44 compression (SetCompression), nil: none.
	comp *CompressionParams
}

// SetCompression applies a meter's V.44 compression setting to general-glo
// ciphering with these keys (IEC 62056-5-3:2023 5.3.6; compression.go):
// Open decompresses APDUs with security control bit 7 and, with
// compressRequests, Seal compresses before ciphering when that makes the
// APDU smaller. Suites 1 and 2 only (Table 9). A nil or empty setting
// turns compression off.
func (k *Keys) SetCompression(c *Compression) error {
	sec := &Security{Suite: k.Suite, Policy: SecEncryption, Ciphering: CipherGeneralGlo}
	if err := c.Apply("", sec); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "meter : "))
	}
	k.comp = sec.Compression
	return nil
}

// ErrNoKeys is returned for a protected APDU when no key is configured.
var ErrNoKeys = errors.New("the DLMS APDU is protected and no key is configured (dlmsKey)")

// OpenNotification decodes a data-notification (tag 0Fh) or a
// general-glo-ciphering APDU (DBh) holding one; dates are read in loc.
func OpenNotification(apdu []byte, keys *Keys, loc *time.Location) (*Notification, error) {
	if loc == nil {
		loc = time.UTC
	}
	if len(apdu) == 0 {
		return nil, errors.New("empty DLMS APDU")
	}
	switch apdu[0] {
	case 0x0F:
		return DecodeDataNotification(apdu, loc)
	case TagGeneralGlo:
		if keys == nil || keys.Key == nil {
			return nil, ErrNoKeys
		}
		st, content, err := decodeGeneralGloDed(apdu)
		if err != nil {
			return nil, err
		}
		plain, ic, err := UnprotectKeys(keys.Suite, keys.Key, keys.BroadcastKey, keys.AuthKey, st, content, nil)
		if err != nil {
			return nil, err
		}
		n, err := DecodeDataNotification(plain, loc)
		if err != nil {
			return nil, fmt.Errorf("the opened APDU is not a data-notification: %w", err)
		}
		n.SystemTitle, n.IC = st, ic
		return n, nil
	}
	return nil, fmt.Errorf("DLMS APDU tag %#x is not a data-notification or general-glo-ciphering", apdu[0])
}

// NotificationValue is one value of a notification body.
type NotificationValue struct {
	Path  string // "1", "2.3": the element's position (1-based) in the body
	Value any    // as Value renders it
}

// Values flattens a notification body into its leaf values in order: a
// structure or array element's path is its parent's path, a dot and its
// position.
func (n *Notification) Values(loc *time.Location) []NotificationValue {
	var out []NotificationValue
	var walk func(d axdr.DlmsData, path string)
	walk = func(d axdr.DlmsData, path string) {
		switch d.Tag {
		case axdr.TagArray, axdr.TagStructure, axdr.TagCompactArray:
			items, _ := d.Value.([]*axdr.DlmsData)
			for i, it := range items {
				p := fmt.Sprint(i + 1)
				if path != "" {
					p = path + "." + p
				}
				if it != nil {
					walk(*it, p)
				}
			}
		default:
			if path == "" {
				path = "1"
			}
			out = append(out, NotificationValue{Path: path, Value: Value(d, loc, d.Tag == axdr.TagOctetString)})
		}
	}
	walk(n.Body, "")
	return out
}

// Requests to a meter over M-Bus (EN 13757-1:2021 9.2.1: CI 60h/61h to
// the meter, the answer behind 7Ch/7Dh): GET and SET normal
// (IEC 62056-5-3:2023 get-request-normal C0 01, set-request-normal C1 01)
// in the clear or under general-glo-ciphering with the meter's keys.

// Request is one GET, SET or ACTION.
type Request struct {
	Op     string // OpGet (default), OpSet, OpAction
	Set    bool   // OpSet (kept for callers that set it alone)
	Class  uint16
	OBIS   string
	Attr   int8           // the attribute, or the method of an ACTION
	Value  *axdr.DlmsData // SET: the value; ACTION: the parameters (nil: none)
	Access *Access        // GET: selective access
	Invoke byte           // invoke-id-and-priority (low four bits the id)
	// List holds further items of the same operation, sent "with list"
	// after this one (mbuslist.go); their Invoke is not used.
	List []Request
}

func (r Request) op() string {
	switch {
	case r.Op != "":
		return r.Op
	case r.Set:
		return OpSet
	}
	return OpGet
}

// descriptor is the attribute or method descriptor: class, instance,
// attribute or method id.
func (r Request) descriptor() ([]byte, error) {
	ln, err := ParseOBIS(r.OBIS)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{byte(r.Class >> 8), byte(r.Class)}, ln[:]...), byte(r.Attr)), nil
}

// Encode is the request's first APDU, without request blocks.
func (r Request) Encode() ([]byte, error) {
	_, apdu, err := r.Start(0)
	return apdu, err
}

// Seal protects an APDU with general-glo-ciphering: authenticated and
// encrypted when the keys have an authentication key, encrypted only
// otherwise.
func Seal(keys *Keys, systemTitle []byte, ic uint32, apdu []byte) ([]byte, error) {
	if keys == nil || keys.Key == nil {
		return nil, ErrNoKeys
	}
	if len(systemTitle) != 8 {
		return nil, errors.New("the system title is 8 bytes")
	}
	policy := SecEncryption
	if len(keys.AuthKey) > 0 {
		policy |= SecAuthentication
	}
	if c := keys.comp; c != nil && c.requests {
		if out, err := v44.Compress(c.params, apdu); err == nil && len(out) < len(apdu) {
			apdu, policy = out, policy|SecCompressed
		}
	}
	p, err := Protect(keys.Suite, policy, keys.Key, keys.AuthKey, systemTitle, ic, apdu)
	if err != nil {
		return nil, err
	}
	return encodeGeneralGloDed(TagGeneralGlo, systemTitle, p), nil
}

// Open removes general-glo-ciphering (an APDU in the clear comes back as
// it is, with a nil system title).
func Open(apdu []byte, keys *Keys) (plain, systemTitle []byte, ic uint32, err error) {
	if len(apdu) == 0 || apdu[0] != TagGeneralGlo {
		return apdu, nil, 0, nil
	}
	if keys == nil || keys.Key == nil {
		return nil, nil, 0, ErrNoKeys
	}
	st, content, err := decodeGeneralGloDed(apdu)
	if err != nil {
		return nil, nil, 0, err
	}
	plain, ic, err = unprotectGeneral(keys.comp, keys.Suite, keys.Key, keys.BroadcastKey, keys.AuthKey, st, content, nil)
	return plain, st, ic, err
}

// ParseRequest reads a plain get- or set-request-normal without selective
// access (a test meter's side).
func ParseRequest(apdu []byte) (Request, error) {
	var r Request
	if len(apdu) < 13 || apdu[1] != 0x01 || apdu[0] != 0xC0 && apdu[0] != 0xC1 {
		return r, errors.New("not a get- or set-request-normal")
	}
	r.Set, r.Invoke = apdu[0] == 0xC1, apdu[2]
	r.Class = uint16(apdu[3])<<8 | uint16(apdu[4])
	r.OBIS = fmt.Sprintf("%d.%d.%d.%d.%d.%d", apdu[5], apdu[6], apdu[7], apdu[8], apdu[9], apdu[10])
	r.Attr = int8(apdu[11])
	if apdu[12] != 0 {
		return r, errors.New("selective access is not supported here")
	}
	if r.Set {
		src := apdu[13:]
		d, err := axdr.NewDataDecoder(&src).Decode(&src)
		if err != nil {
			return r, err
		}
		r.Value = &d
	}
	return r, nil
}

// Response is a decoded get- or set-response-normal.
type Response struct {
	Set    bool
	Invoke byte
	Data   *axdr.DlmsData // GET: the value
	Result int            // data-access-result (0 success)
}

// EncodeResponse builds a response-normal (the meter's side): a GET with
// data, or a result code.
func EncodeResponse(r Response) ([]byte, error) {
	if r.Set {
		return []byte{0xC5, 0x01, r.Invoke, byte(r.Result)}, nil
	}
	if r.Data == nil {
		return []byte{0xC4, 0x01, r.Invoke, 0x01, byte(r.Result)}, nil
	}
	v, err := r.Data.Encode()
	if err != nil {
		return nil, err
	}
	return append([]byte{0xC4, 0x01, r.Invoke, 0x00}, v...), nil
}

// ParseResponse reads a plain get- or set-response-normal.
func ParseResponse(apdu []byte) (Response, error) {
	var r Response
	if len(apdu) < 4 || apdu[1] != 0x01 {
		return r, errors.New("not a get- or set-response-normal")
	}
	r.Invoke = apdu[2]
	switch apdu[0] {
	case 0xC5:
		r.Set, r.Result = true, int(apdu[3])
		return r, nil
	case 0xC4:
		if apdu[3] != 0 {
			if len(apdu) < 5 {
				return r, errors.New("a get-response without its result")
			}
			r.Result = int(apdu[4])
			return r, nil
		}
		src := apdu[4:]
		d, err := axdr.NewDataDecoder(&src).Decode(&src)
		if err != nil {
			return r, err
		}
		r.Data = &d
		return r, nil
	}
	return r, fmt.Errorf("APDU tag %#x is not a get- or set-response", apdu[0])
}

// PointName names an attribute as the catalogue does (catalogue name, OBIS
// model name, else the code).
func PointName(obis string, class uint16, attr int8) string { return NameOf(obis, class, attr) }

// CommandRequest is a DLMS request as an M-Bus application takes it: a GET or SET
// of one attribute.
type CommandRequest struct {
	Op        string `json:"op"` // get (default), set or action
	Class     int    `json:"class"`
	OBIS      string `json:"obis"`
	Attribute *int   `json:"attribute"` // get, set: 1 to 127, default 2
	Method    int    `json:"method"`    // action: the method id
	Value     string `json:"value"`     // set: the value; action: the parameters (optional); A-XDR in hex
	// Access is the selective access of a get: {"selector": "range",
	// "from", "to" (RFC 3339), "restrict": {"class", "obis",
	// "attribute"}} or {"selector": "entry", "fromEntry", "toEntry"}.
	Access *CommandAccess `json:"access"`
	// List adds further attributes (get, set) or methods (action) of the
	// same operation, each {"class", "obis", "attribute" or "method",
	// "value", "access"}; the request then goes "with list".
	List []CommandRequest `json:"list,omitempty"`
}

// CommandAccess is the selective access of a dlms command.
type CommandAccess struct {
	Selector  string `json:"selector"`
	From      string `json:"from"`
	To        string `json:"to"`
	FromEntry uint32 `json:"fromEntry"`
	ToEntry   uint32 `json:"toEntry"`
	Restrict  *struct {
		Class     int    `json:"class"`
		OBIS      string `json:"obis"`
		Attribute int    `json:"attribute"`
	} `json:"restrict"`
}

// Request checks the command and builds its request (invoke-id 0).
func (b CommandRequest) Request() (Request, error) {
	// An absent attribute is the value (2). Attribute 0 (all attributes,
	// Green Book attribute0 conformance) is not offered: it is refused
	// rather than sent as 2.
	attr := 2
	if b.Attribute != nil {
		attr = *b.Attribute
	}
	r := Request{Class: uint16(b.Class), OBIS: b.OBIS, Attr: int8(attr)}
	value := func(need bool) error {
		if b.Value == "" && !need {
			return nil
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(b.Value, " ", ""))
		if err != nil || len(raw) == 0 {
			return fmt.Errorf(`dlms %s needs "value": the A-XDR encoded value in hex`, b.Op)
		}
		src := raw
		d, err := axdr.NewDataDecoder(&src).Decode(&src)
		if err != nil || len(src) != 0 {
			return errors.New(`"value" is not one A-XDR encoded value`)
		}
		r.Value = &d
		return nil
	}
	switch b.Op {
	case "", OpGet:
		r.Op = OpGet
	case OpSet:
		r.Op, r.Set = OpSet, true
		if err := value(true); err != nil {
			return r, err
		}
	case OpAction:
		r.Op = OpAction
		if b.Method < 1 || b.Method > 127 {
			return r, errors.New(`dlms action needs "method" 1 to 127`)
		}
		r.Attr = int8(b.Method)
		if err := value(false); err != nil {
			return r, err
		}
	default:
		return r, fmt.Errorf(`dlms "op" %q is not get, set or action`, b.Op)
	}
	if b.Class < 1 || b.Class > 65535 || attr < 1 || attr > 127 {
		return r, errors.New(`dlms needs "class" 1 to 65535 and "attribute" 1 to 127`)
	}
	if b.Access != nil {
		if r.Op != OpGet {
			return r, errors.New("selective access applies to a get")
		}
		a, err := b.Access.access()
		if err != nil {
			return r, err
		}
		r.Access = &a
	}
	if len(b.List) >= MaxListItems {
		return r, fmt.Errorf(`"list" takes at most %d further items`, MaxListItems-1)
	}
	for i, it := range b.List {
		if len(it.List) > 0 {
			return r, fmt.Errorf(`list item %d: a list cannot hold a list`, i+1)
		}
		if it.Op == "" {
			it.Op = r.Op
		}
		if it.Op != r.Op {
			return r, fmt.Errorf(`list item %d: "op" %q differs from the request's %q`, i+1, it.Op, r.Op)
		}
		ir, err := it.Request()
		if err != nil {
			return r, fmt.Errorf("list item %d: %w", i+1, err)
		}
		r.List = append(r.List, ir)
	}
	if _, err := r.Encode(); err != nil {
		return r, err
	}
	return r, nil
}

func (c CommandAccess) access() (Access, error) {
	switch c.Selector {
	case "range":
		from, err1 := time.Parse(time.RFC3339, c.From)
		to, err2 := time.Parse(time.RFC3339, c.To)
		if err1 != nil || err2 != nil || to.Before(from) {
			return Access{}, errors.New(`a range access needs "from" and "to" (RFC 3339, from not after to)`)
		}
		a := Access{Selector: 1, From: from, To: to, Loc: from.Location()}
		if r := c.Restrict; r != nil {
			if _, err := ParseOBIS(r.OBIS); err != nil || r.Class < 1 || r.Class > 65535 || r.Attribute < 1 || r.Attribute > 127 {
				return Access{}, errors.New(`"restrict" needs "class", "obis" and "attribute" of the column compared`)
			}
			a.RestrictClass, a.RestrictOBIS, a.RestrictAttr = uint16(r.Class), r.OBIS, int8(r.Attribute)
		}
		return a, nil
	case "entry":
		if c.FromEntry < 1 || c.ToEntry != 0 && c.ToEntry < c.FromEntry {
			return Access{}, errors.New(`an entry access needs "fromEntry" 1 or more and "toEntry" 0 (the last) or at least fromEntry`)
		}
		return Access{Selector: 2, FromEntry: c.FromEntry, ToEntry: c.ToEntry}, nil
	}
	return Access{}, fmt.Errorf(`access "selector" %q is not range or entry`, c.Selector)
}

// ParseKeys reads a meter's DLMS keys of a security suite (IEC
// 62056-5-3:2023 Table 9: suites 0 and 1 AES-128, suite 2 AES-256; the
// authentication key has the same length, or none).
func ParseKeys(suite int, key, authKey string) (*Keys, error) {
	if suite < 0 || suite > 2 {
		return nil, fmt.Errorf("dlmsSuite %d is not 0, 1 or 2", suite)
	}
	n := Suite(suite).KeyLen()
	k, err1 := hex.DecodeString(strings.ReplaceAll(key, " ", ""))
	ak, err2 := hex.DecodeString(strings.ReplaceAll(authKey, " ", ""))
	if err1 != nil || err2 != nil || len(k) != n || len(ak) != 0 && len(ak) != n {
		return nil, fmt.Errorf("with security suite %d, dlmsKey is %d bytes of hex and dlmsAuthKey %d bytes or none", suite, n, n)
	}
	return &Keys{Suite: Suite(suite), Key: k, AuthKey: ak}, nil
}
