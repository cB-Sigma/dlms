// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

// Short name referencing (IEC 62056-5-3:2023 7.4, the DLMS UA Green Book):
// an object is named by its base name, a 13-bit value; attribute i is at
// base + 8(i-1) and method j at base + a class-specific offset + 8(j-1).
// The services are ReadRequest (tag 0x05), WriteRequest (0x06) and
// UnconfirmedWriteRequest (0x16), answered by ReadResponse (0x0C) and
// WriteResponse (0x0D). A method is invoked by a read with parameterized
// access (selector 0, the parameter) when it returns data. Large read
// answers come in data blocks, each fetched with block-number access
// naming the block received. reply_to_HLS_authentication is written (the
// form Gurux's servers take, answering with a ReadResponse); a server that
// answers that write without data is asked again with a read. The association SN object (class 12) is at
// 0xFA00; its object list (attribute 2) gives every object's base name.
//
// The association itself is gosem's AARQ with the short name context
// (2, or 4 with ciphering) and the short name conformance block;
// SecureTransport protects the services with their glo- and ded- tags.

import (
	"encoding/hex"
	"errors"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Application contexts for short name referencing (the last arc).
const (
	ContextSN          byte = 2
	ContextSNCiphering byte = 4
)

// Conformance block bits (IEC 62056-5-3:2023 7.3.1, bit 0 the most
// significant of 24).
const (
	ConformanceGeneralProtection    uint32 = 1 << 22
	ConformanceGeneralBlockTransfer uint32 = 1 << 21
	ConformanceRead                 uint32 = 1 << 20
	ConformanceWrite                uint32 = 1 << 19
	ConformanceUnconfirmedWrite     uint32 = 1 << 18
	ConformanceAttribute0Set        uint32 = 1 << 15
	ConformancePriorityMgmt         uint32 = 1 << 14
	ConformanceAttribute0Get        uint32 = 1 << 13
	ConformanceBlockGetOrRead       uint32 = 1 << 12
	ConformanceBlockSetOrWrite      uint32 = 1 << 11
	ConformanceBlockAction          uint32 = 1 << 10
	ConformanceMultipleReferences   uint32 = 1 << 9
	ConformanceInformationReport    uint32 = 1 << 8
	ConformanceDataNotification     uint32 = 1 << 7
	ConformanceAccess               uint32 = 1 << 6
	ConformanceParameterizedAccess  uint32 = 1 << 5
	ConformanceGet                  uint32 = 1 << 4
	ConformanceSet                  uint32 = 1 << 3
	ConformanceSelectiveAccess      uint32 = 1 << 2
	ConformanceEventNotification    uint32 = 1 << 1
	ConformanceAction               uint32 = 1 << 0
)

// snConformance is what a short name client proposes.
const snConformance = ConformanceRead | ConformanceWrite | ConformanceUnconfirmedWrite | ConformanceBlockGetOrRead |
	ConformanceBlockSetOrWrite | ConformanceMultipleReferences | ConformanceInformationReport | ConformanceParameterizedAccess

// AssociationSNBaseName is the base name of the current association SN
// object.
const AssociationSNBaseName = 0xFA00

// snMethodOffsets are the short name offsets of method 1 of the classes
// that have methods (IEC 62056-6-2 class descriptions).
var snMethodOffsets = map[uint16]uint16{
	3: 0x28, 4: 0x38, 5: 0x48, 6: 0x30, 7: 0x58, 8: 0x60, 9: 0x20, 11: 0x10, 12: 0x20, 15: 0x60,
	17: 0x20, 18: 0x40, 20: 0x50, 40: 0x38, 42: 0x60, 61: 0x28, 64: 0x30, 70: 0x20, 100: 0x38,
}

// SNMethodOffset is the offset of method m of class from the object's
// base name.
func SNMethodOffset(class uint16, m int8) (uint16, bool) {
	first, ok := snMethodOffsets[class]
	if !ok || m < 1 {
		return 0, false
	}
	return first + uint16(m-1)*8, true
}

// snObject is one entry of the association SN object list.
type snObject struct {
	base    uint16
	class   uint16
	version uint8
}

// Read access specification choices.
const (
	snVariableName  = 2
	snParameterized = 4
	snBlockNumber   = 5
)

// ReadSN reads the variable at base name name (an attribute's, base +
// 8(i-1)) with a ReadRequest, following data blocks.
func (a *Association) ReadSN(name uint16) (axdr.DlmsData, error) {
	return a.readSN([]byte{snVariableName, byte(name >> 8), byte(name)})
}

// ReadSNParameterized reads a variable with parameterized access: a
// selective access of an attribute (a profile's buffer by range is
// selector 1) or, selector 0, a method that returns data.
func (a *Association) ReadSNParameterized(name uint16, selector uint8, param *axdr.DlmsData) (axdr.DlmsData, error) {
	p, err := encodeData(param)
	if err != nil {
		return axdr.DlmsData{}, err
	}
	return a.readSN(concat([]byte{snParameterized, byte(name >> 8), byte(name), selector}, p))
}

// readSN sends a ReadRequest of one variable and returns its data,
// fetching the remaining data blocks.
func (a *Association) readSN(spec []byte) (axdr.DlmsData, error) {
	var zero axdr.DlmsData
	back, err := a.Exchange(concat([]byte{0x05, 0x01}, spec))
	if err != nil {
		return zero, err
	}
	var raw []byte
	for block := uint16(1); ; block++ {
		item, err := readResponseItem(back)
		if err != nil {
			return zero, err
		}
		switch item.choice {
		case 0:
			if raw != nil {
				return zero, errors.New("the meter answered a data block read with plain data")
			}
			return item.data, nil
		case 1:
			return zero, fmt.Errorf("the meter refused the read: %s", accessResultText(item.result))
		case 2:
			if item.block != block {
				return zero, fmt.Errorf("the meter sent data block %d where %d was due", item.block, block)
			}
			raw = append(raw, item.raw...)
			if item.last {
				src := raw
				d, err := axdr.NewDataDecoder(&src).Decode(&src)
				if err != nil {
					return zero, fmt.Errorf("the data blocks do not decode: %w", err)
				}
				return d, nil
			}
			// The next block is asked for by naming the block received.
			if back, err = a.Exchange([]byte{0x05, 0x01, snBlockNumber, byte(block >> 8), byte(block)}); err != nil {
				return zero, err
			}
		default:
			return zero, fmt.Errorf("the meter answered the read with choice %d", item.choice)
		}
	}
}

type readItem struct {
	choice byte
	data   axdr.DlmsData
	result byte
	last   bool
	block  uint16
	raw    []byte
}

// readResponseItem reads the first item of a ReadResponse (later items,
// and anything after the APDU, are ignored).
func readResponseItem(apdu []byte) (readItem, error) {
	var it readItem
	if len(apdu) == 0 {
		return it, errors.New("empty answer")
	}
	if apdu[0] != 0x0C {
		return it, unexpected("read", apdu)
	}
	r := &apduReader{b: apdu[1:]}
	if r.length("item count") < 1 && r.err == nil {
		return it, errors.New("the read response has no item")
	}
	it.choice = r.u8("item choice")
	switch it.choice {
	case 0:
		it.data = r.data("data")
	case 1:
		it.result = r.u8("data access error")
	case 2:
		it.last = r.u8("last block") != 0
		it.block = r.u16("block number")
		it.raw = r.bytes(r.length("raw data length"), "raw data")
	case 3:
		it.block = r.u16("block number")
	}
	return it, r.err
}

// WriteSN writes v to the variable at base name name with a WriteRequest.
func (a *Association) WriteSN(name uint16, v *axdr.DlmsData) error {
	p, err := encodeData(v)
	if err != nil {
		return err
	}
	back, err := a.Exchange(concat([]byte{0x06, 0x01, snVariableName, byte(name >> 8), byte(name), 0x01}, p))
	if err != nil {
		return err
	}
	if len(back) == 0 || back[0] != 0x0D {
		if len(back) == 0 {
			return errors.New("empty answer")
		}
		return unexpected("write", back)
	}
	r := &apduReader{b: back[1:]}
	if r.length("item count") < 1 && r.err == nil {
		return errors.New("the write response has no item")
	}
	if c := r.u8("item"); c != 0 {
		return fmt.Errorf("the meter refused the write: %s", accessResultText(r.u8("data access error")))
	}
	return r.err
}

// ActionSN invokes method m of an object of class at base name base
// (a read with parameterized access, selector 0) and returns the
// method's return data.
func (a *Association) ActionSN(class uint16, base uint16, m int8, param *axdr.DlmsData) (axdr.DlmsData, error) {
	off, ok := SNMethodOffset(class, m)
	if !ok {
		return axdr.DlmsData{}, fmt.Errorf("the short name of method %d of class %d is not known", m, class)
	}
	if param == nil {
		param = axdrNull()
	}
	return a.ReadSNParameterized(base+off, 0, param)
}

// ReadObjectListSN reads the association SN object list (base name,
// class, version, logical name of each object) and keeps it for GetSN.
func (a *Association) ReadObjectListSN() error {
	d, err := a.ReadSN(AssociationSNBaseName + 8)
	if err != nil {
		return fmt.Errorf("reading the object list: %w", err)
	}
	items, ok := d.Value.([]*axdr.DlmsData)
	if !ok {
		return errors.New("the object list is not an array")
	}
	names := map[string]snObject{}
	for _, it := range items {
		f, ok := it.Value.([]*axdr.DlmsData)
		if !ok || len(f) < 4 {
			return errors.New("an object list entry is not a structure of four")
		}
		base, _ := Number(*f[0])
		class, _ := Number(*f[1])
		version, _ := Number(*f[2])
		ln, err := octetsOf(*f[3])
		if err != nil || len(ln) != 6 {
			return errors.New("an object list entry has no logical name")
		}
		names[snKey(uint16(class), obisText(ln))] = snObject{base: uint16(int64(base)), class: uint16(class), version: uint8(version)}
	}
	a.names = names
	return nil
}

func snKey(class uint16, obis string) string { return fmt.Sprintf("%d/%s", class, obis) }

// BaseName is the base name of an object, from the object list (read
// first if needed).
func (a *Association) BaseName(class uint16, obis string) (uint16, error) {
	if a.names == nil {
		if err := a.ReadObjectListSN(); err != nil {
			return 0, err
		}
	}
	o, ok := a.names[snKey(class, obis)]
	if !ok {
		return 0, fmt.Errorf("the meter lists no object %d/%s", class, obis)
	}
	return o.base, nil
}

// GetSN reads attribute attr of a logical name through its base name.
func (a *Association) GetSN(class uint16, obis string, attr int8) (axdr.DlmsData, error) {
	base, err := a.BaseName(class, obis)
	if err != nil {
		return axdr.DlmsData{}, err
	}
	return a.ReadSN(base + uint16(attr-1)*8)
}

// SetSN writes attribute attr of a logical name through its base name.
func (a *Association) SetSN(class uint16, obis string, attr int8, v *axdr.DlmsData) error {
	base, err := a.BaseName(class, obis)
	if err != nil {
		return err
	}
	return a.WriteSN(base+uint16(attr-1)*8, v)
}

// ShortNames reports an association that uses short name referencing.
func (a *Association) ShortNames() bool { return a.shortNames }

// octetsOf is the octet string in d.
func octetsOf(d axdr.DlmsData) ([]byte, error) {
	switch v := d.Value.(type) {
	case string:
		return hex.DecodeString(v)
	case []byte:
		return v, nil
	}
	return nil, errors.New("not an octet string")
}

// completeHLSSN runs passes 3 and 4 over a short name association: the
// answer goes to reply_to_HLS_authentication (method 8 of the association
// SN object) in a read with parameterized access, whose answer is the
// meter's f(CtoS).
func completeHLSSN(a *Association, h *HLS, ctos []byte) error {
	t := a.Secure
	meterST, stoc := t.Challenge()
	if len(stoc) == 0 {
		return errors.New("the meter's AARE carried no challenge; it does not offer this mechanism on this client address")
	}
	if err := checkStoC(h.Mechanism, stoc, ctos); err != nil {
		return err
	}
	if h.Mechanism >= MechGMAC && len(meterST) != 8 {
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
	t.setEstablishing(true)
	defer t.setEstablishing(false)
	param := axdr.CreateAxdrOctetString(hex.EncodeToString(ans))
	var back axdr.DlmsData
	p, _ := encodeData(param)
	name := uint16(AssociationSNBaseName + 0x58) // method 8
	resp, err := a.Exchange(concat([]byte{0x06, 0x01, snVariableName, byte(name >> 8), byte(name), 0x01}, p))
	if err == nil && len(resp) > 0 && resp[0] == 0x0C {
		var it readItem
		if it, err = readResponseItem(resp); err == nil && it.choice != 0 {
			err = fmt.Errorf("the meter refused our answer to its challenge: %s", accessResultText(it.result))
		}
		back = it.data
	} else {
		// A WriteResponse carries no answer: read the method instead.
		back, err = a.ActionSN(12, AssociationSNBaseName, 8, param)
	}
	if err != nil {
		return fmt.Errorf("the meter refused our answer to its challenge: %w", err)
	}
	got, err := octetsOf(back)
	if err != nil {
		return errors.New("the meter's reply carries no answer to our challenge")
	}
	return h.check(h.Security.SystemTitle, meterST, ctos, stoc, got)
}

// contextArc is the last arc of an AARQ's application context name (0
// when it has none).
func contextArc(aarq []byte) byte {
	if len(aarq) < 2 {
		return 0
	}
	n, sz, err := getLen(aarq[1:])
	if err != nil || 1+sz+n > len(aarq) {
		return 0
	}
	items, err := parseTLVs(aarq[1+sz : 1+sz+n])
	if err != nil {
		return 0
	}
	for _, it := range items {
		if it.tag == 0xA1 && len(it.val) == 9 {
			return it.val[8]
		}
	}
	return 0
}
