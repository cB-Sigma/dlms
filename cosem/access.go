// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

// The ACCESS service (IEC 62056-5-3:2023 7.3.8, the DLMS UA Green Book):
// one request carries any mix of get, set and action operations, each
// named by its descriptor, with a list of data in the same order (null for
// a get, the value for a set, the parameter for an action); the response
// gives one data and one result per operation. Long invoke ID and
// priority: bit 31 high priority, bit 30 confirmed, bit 29 break on error,
// bit 28 self-descriptive, bits 0 to 23 the invoke ID. ACCESS is protected
// only by general-glo, general-ded or general ciphering (SecureTransport
// chooses general-glo for it when service-specific ciphering is set).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// APDU tags of the ACCESS service.
const (
	TagAccessRequest  byte = 0xD9
	TagAccessResponse byte = 0xDA
)

// Bits of the long invoke ID and priority.
const (
	AccessHighPriority   uint32 = 1 << 31
	AccessConfirmed      uint32 = 1 << 30
	AccessBreakOnError   uint32 = 1 << 29
	AccessSelfDescribing uint32 = 1 << 28
)

// AccessKind is the operation of one access request specification.
type AccessKind byte

// Access request specifications.
const (
	AccessGet              AccessKind = 1
	AccessSet              AccessKind = 2
	AccessAction           AccessKind = 3
	AccessGetWithSelection AccessKind = 4
	AccessSetWithSelection AccessKind = 5
)

func (k AccessKind) String() string {
	switch k {
	case AccessGet:
		return "get"
	case AccessSet:
		return "set"
	case AccessAction:
		return "action"
	case AccessGetWithSelection:
		return "get with selection"
	case AccessSetWithSelection:
		return "set with selection"
	}
	return fmt.Sprintf("access kind %d", byte(k))
}

// AccessItem is one operation of an ACCESS request.
type AccessItem struct {
	Kind  AccessKind
	Class uint16
	OBIS  string
	// ID is the attribute (get, set) or method (action).
	ID int8
	// Selector and Parameters are the selective access of the "with
	// selection" kinds.
	Selector   uint8
	Parameters *axdr.DlmsData
	// Data is the value of a set or the parameter of an action; nil sends
	// null-data (always for a get).
	Data *axdr.DlmsData
}

// AccessRequest is an ACCESS request.
type AccessRequest struct {
	// InvokeID is the long invoke ID and priority.
	InvokeID uint32
	// Time, when not nil, is the request's date-time (12 octets).
	Time  []byte
	Items []AccessItem
}

// AccessResult is the outcome of one operation: the result code (a
// data-access-result or action-result, 0 success) and the data (the value
// read, the action's return parameter, or null-data).
type AccessResult struct {
	Kind   AccessKind
	Result byte
	Data   axdr.DlmsData
}

// AccessResponse is an ACCESS response.
type AccessResponse struct {
	InvokeID uint32
	Time     []byte
	Results  []AccessResult
}

func axdrNull() *axdr.DlmsData { return &axdr.DlmsData{Tag: axdr.TagNull} }

// encodeData is the A-XDR encoding of d (null-data as one octet).
func encodeData(d *axdr.DlmsData) ([]byte, error) {
	if d == nil {
		return []byte{0x00}, nil
	}
	r, _, _ := EncodeAXDR(d)
	if d.Tag != axdr.TagNull && d.Tag != axdr.TagArray && d.Tag != axdr.TagStructure {
		if _, err := d.Encode(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Encode is the APDU of the request.
func (r *AccessRequest) Encode() ([]byte, error) {
	if len(r.Items) == 0 {
		return nil, errors.New("an access request needs at least one operation")
	}
	out := []byte{TagAccessRequest, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], r.InvokeID)
	out = append(out, putLen(len(r.Time))...)
	out = append(out, r.Time...)
	out = append(out, putLen(len(r.Items))...)
	for _, it := range r.Items {
		ln, err := ParseOBIS(it.OBIS)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(it.Kind), byte(it.Class>>8), byte(it.Class))
		out = append(out, ln[:]...)
		out = append(out, byte(it.ID))
		switch it.Kind {
		case AccessGet, AccessSet, AccessAction:
		case AccessGetWithSelection, AccessSetWithSelection:
			p := it.Parameters
			if p == nil {
				p = axdrNull()
			}
			b, err := encodeData(p)
			if err != nil {
				return nil, err
			}
			out = append(out, it.Selector)
			out = append(out, b...)
		default:
			return nil, fmt.Errorf("%v is not an access request specification", it.Kind)
		}
	}
	out = append(out, putLen(len(r.Items))...)
	for _, it := range r.Items {
		d := it.Data
		if it.Kind == AccessGet || it.Kind == AccessGetWithSelection {
			d = nil
		}
		b, err := encodeData(d)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// apduReader walks an APDU.
type apduReader struct {
	b   []byte
	err error
}

func (r *apduReader) fail(what string) {
	if r.err == nil {
		r.err = fmt.Errorf("the APDU ends or is malformed at its %s", what)
	}
}

func (r *apduReader) bytes(n int, what string) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.fail(what)
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *apduReader) u8(what string) byte {
	b := r.bytes(1, what)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *apduReader) u16(what string) uint16 {
	b := r.bytes(2, what)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *apduReader) u32(what string) uint32 {
	b := r.bytes(4, what)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *apduReader) length(what string) int {
	if r.err != nil {
		return 0
	}
	n, sz := DecodeLength(r.b)
	if n < 0 {
		r.fail(what)
		return 0
	}
	r.b = r.b[sz:]
	return n
}

func (r *apduReader) data(what string) axdr.DlmsData {
	if r.err != nil {
		return axdr.DlmsData{}
	}
	if len(r.b) == 0 {
		r.fail(what)
		return axdr.DlmsData{}
	}
	src := r.b
	dec := axdr.NewDataDecoder(&src)
	d, err := dec.Decode(&src)
	if err != nil {
		r.err = fmt.Errorf("the %s does not decode: %w", what, err)
		return axdr.DlmsData{}
	}
	r.b = src
	return d
}

// DecodeAccessRequest reads an ACCESS request APDU.
func DecodeAccessRequest(apdu []byte) (*AccessRequest, error) {
	if len(apdu) == 0 || apdu[0] != TagAccessRequest {
		return nil, errors.New("not an access request")
	}
	r := &apduReader{b: apdu[1:]}
	req := &AccessRequest{InvokeID: r.u32("invoke ID")}
	if n := r.length("date-time"); n > 0 {
		req.Time = append([]byte(nil), r.bytes(n, "date-time")...)
	}
	n := r.length("specification count")
	for i := 0; i < n && r.err == nil; i++ {
		it := AccessItem{Kind: AccessKind(r.u8("specification"))}
		it.Class = r.u16("class")
		ln := r.bytes(6, "logical name")
		if ln != nil {
			it.OBIS = obisText(ln)
		}
		it.ID = int8(r.u8("attribute or method"))
		switch it.Kind {
		case AccessGet, AccessSet, AccessAction:
		case AccessGetWithSelection, AccessSetWithSelection:
			it.Selector = r.u8("access selector")
			p := r.data("access parameters")
			it.Parameters = &p
		default:
			return nil, fmt.Errorf("%v is not an access request specification", it.Kind)
		}
		req.Items = append(req.Items, it)
	}
	if m := r.length("data count"); r.err == nil && m != len(req.Items) {
		return nil, fmt.Errorf("the access request has %d operations and %d data", len(req.Items), m)
	}
	for i := range req.Items {
		d := r.data("data")
		if r.err != nil {
			break
		}
		if d.Tag != axdr.TagNull || req.Items[i].Kind == AccessSet || req.Items[i].Kind == AccessSetWithSelection {
			req.Items[i].Data = &d
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("the access request has %d octets after its data", len(r.b))
	}
	return req, nil
}

// Encode is the APDU of the response (the optional copy of the request's
// specifications is left out).
func (r *AccessResponse) Encode() ([]byte, error) {
	out := []byte{TagAccessResponse, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], r.InvokeID)
	out = append(out, putLen(len(r.Time))...)
	out = append(out, r.Time...)
	out = append(out, 0x00) // access-request-specification: absent
	out = append(out, putLen(len(r.Results))...)
	for i := range r.Results {
		d := &r.Results[i].Data
		if d.Tag == 0 && d.Value == nil {
			d = nil
		}
		b, err := encodeData(d)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	out = append(out, putLen(len(r.Results))...)
	for _, res := range r.Results {
		k := res.Kind
		if k == AccessGetWithSelection {
			k = AccessGet
		} else if k == AccessSetWithSelection {
			k = AccessSet
		}
		out = append(out, byte(k), res.Result)
	}
	return out, nil
}

// DecodeAccessResponse reads an ACCESS response APDU.
func DecodeAccessResponse(apdu []byte) (*AccessResponse, error) {
	if len(apdu) == 0 || apdu[0] != TagAccessResponse {
		return nil, errors.New("not an access response")
	}
	r := &apduReader{b: apdu[1:]}
	resp := &AccessResponse{InvokeID: r.u32("invoke ID")}
	if n := r.length("date-time"); n > 0 {
		resp.Time = append([]byte(nil), r.bytes(n, "date-time")...)
	}
	if r.u8("request specification flag") != 0 {
		// The meter repeated the request's specifications: skip them.
		n := r.length("specification count")
		for i := 0; i < n && r.err == nil; i++ {
			k := AccessKind(r.u8("specification"))
			r.bytes(9, "descriptor")
			if k == AccessGetWithSelection || k == AccessSetWithSelection {
				r.u8("access selector")
				r.data("access parameters")
			}
		}
	}
	n := r.length("data count")
	data := make([]axdr.DlmsData, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		data = append(data, r.data("data"))
	}
	m := r.length("result count")
	if r.err == nil && m != n {
		return nil, fmt.Errorf("the access response has %d data and %d results", n, m)
	}
	for i := 0; i < m && r.err == nil; i++ {
		res := AccessResult{Kind: AccessKind(r.u8("result kind")), Result: r.u8("result")}
		if i < len(data) {
			res.Data = data[i]
		}
		resp.Results = append(resp.Results, res)
	}
	if r.err != nil {
		return nil, r.err
	}
	return resp, nil
}

// obisText is a 6-octet logical name as "a.b.c.d.e.f".
func obisText(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", b[0], b[1], b[2], b[3], b[4], b[5])
}

// Access sends one ACCESS request (confirmed, normal priority) on the
// open association and returns one result per item, in order. An item the
// meter refused has a non-zero Result; the error is for the exchange
// itself.
func (c *Client) Access(items ...AccessItem) ([]AccessResult, error) {
	if c.a == nil {
		return nil, errNoAssociation
	}
	return c.a.Access(items...)
}

// Access is Client.Access on this association.
func (a *Association) Access(items ...AccessItem) ([]AccessResult, error) {
	a.invoke = (a.invoke + 1) & 0xFFFFFF
	req := &AccessRequest{InvokeID: AccessConfirmed | a.invoke, Items: items}
	apdu, err := req.Encode()
	if err != nil {
		return nil, err
	}
	back, err := a.Exchange(apdu)
	if err != nil {
		return nil, err
	}
	if len(back) > 0 && back[0] != TagAccessResponse {
		return nil, unexpected("access", back)
	}
	resp, err := DecodeAccessResponse(back)
	if err != nil {
		return nil, err
	}
	if resp.InvokeID&0xFFFFFF != a.invoke {
		return nil, fmt.Errorf("the access response answers invoke ID %d, not %d", resp.InvokeID&0xFFFFFF, a.invoke)
	}
	if len(resp.Results) != len(items) {
		return nil, fmt.Errorf("the access response has %d results for %d operations", len(resp.Results), len(items))
	}
	return resp.Results, nil
}

// unexpected describes an answer that is not the service's response:
// an exception or a confirmed service error, or another APDU.
func unexpected(service string, apdu []byte) error {
	switch apdu[0] {
	case 0xD8:
		if len(apdu) >= 3 {
			return fmt.Errorf("the meter answered the %s request with an exception (state %d, service %d)", service, apdu[1], apdu[2])
		}
	case 0x0E:
		return fmt.Errorf("the meter answered the %s request with a confirmed service error % X", service, apdu[1:])
	}
	return fmt.Errorf("the meter answered the %s request with an APDU of tag %#x", service, apdu[0])
}

var accessResults = map[byte]string{
	0: "success", 1: "hardware fault", 2: "temporary failure", 3: "read-write denied", 4: "object undefined",
	9: "object class inconsistent", 11: "object unavailable", 12: "type unmatched", 13: "scope of access violated",
	14: "data block unavailable", 15: "long operation aborted", 16: "no long operation in progress",
	17: "long set aborted", 18: "no long set in progress", 19: "data block number invalid", 250: "other reason",
}

// accessResultText names a data-access-result or action-result code.
func accessResultText(r byte) string {
	if s, ok := accessResults[r]; ok {
		return fmt.Sprintf("%s (%d)", s, r)
	}
	return fmt.Sprintf("result %d", r)
}

// String names the result code.
func (r AccessResult) String() string { return accessResultText(r.Result) }

// exchangeTimeout is the default bound of one Exchange.
const exchangeTimeout = 10 * time.Second
