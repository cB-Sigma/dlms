package cosem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// GET, SET and ACTION "with list" (IEC 62056-5-3:2023 xDLMS services;
// get-request-with-list [3], set-request-with-list [4] and
// -with-list-and-first-datablock [5], action-request-with-list [3] and
// -with-list-and-first-pblock [5], and their responses). A Request with
// List names further attributes (GET, SET) or methods (ACTION) served in
// the same APDU after its own; all items share the operation. Items are
// answered in order, each with its own result.

// MaxListItems bounds the items of one request with list (ours).
const MaxListItems = 64

// ItemResult is one list item's outcome: a data-access-result (GET, SET)
// or action-result (ACTION), and the data a GET or ACTION returned.
type ItemResult struct {
	Result int
	Data   *axdr.DlmsData
}

// items is the request followed by its list.
func (r Request) items() []Request { return append([]Request{r}, r.List...) }

// selection is a Cosem-Attribute-Descriptor-With-Selection: descriptor,
// then access-selection OPTIONAL.
func (r Request) selection() ([]byte, error) {
	d, err := r.descriptor()
	if err != nil {
		return nil, err
	}
	if r.Access == nil {
		return append(d, 0x00), nil
	}
	p, err := r.Access.parameter()
	if err != nil {
		return nil, err
	}
	pb, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return append(append(d, 0x01, r.Access.Selector), pb...), nil
}

func appendLen(b []byte, n int) []byte {
	l, _ := axdr.EncodeLength(n)
	return append(b, l...)
}

// startList begins a request with list.
func (r Request) startList(x *Exchange, block int) ([]byte, error) {
	items := r.items()
	if len(items) > MaxListItems {
		return nil, fmt.Errorf("a request with list takes at most %d items", MaxListItems)
	}
	op := r.op()
	for i, it := range items[1:] {
		if it.op() != op {
			return nil, fmt.Errorf("list item %d is a %s, not a %s like the request", i+1, it.op(), op)
		}
	}
	x.list = len(items)
	switch op {
	case OpGet:
		apdu := appendLen([]byte{0xC0, 0x03, r.Invoke}, len(items))
		for _, it := range items {
			s, err := it.selection()
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, s...)
		}
		return apdu, nil
	case OpSet:
		descs := appendLen(nil, len(items))
		values := appendLen(nil, len(items))
		for i, it := range items {
			if it.Access != nil {
				return nil, errors.New("selective access applies to a get")
			}
			s, _ := it.selection()
			descs = append(descs, s...)
			if it.Value == nil {
				return nil, fmt.Errorf("list item %d of a SET needs a value", i)
			}
			v, err := it.Value.Encode()
			if err != nil {
				return nil, err
			}
			values = append(values, v...)
		}
		if block <= 0 || len(values) <= block {
			return append(append([]byte{0xC1, 0x04, r.Invoke}, descs...), values...), nil
		}
		// The value list goes in data blocks (our reading of the raw
		// data: the encoded SEQUENCE OF Data with its count).
		x.chunks = split(values, block)
		return append(append([]byte{0xC1, 0x05, r.Invoke}, descs...), x.blockSA(0)...), nil
	case OpAction:
		descs := appendLen(nil, len(items))
		params := appendLen(nil, len(items))
		for _, it := range items {
			d, err := it.descriptor()
			if err != nil {
				return nil, err
			}
			descs = append(descs, d...)
			if it.Value == nil {
				params = append(params, 0x00) // null-data: no parameters
				continue
			}
			v, err := it.Value.Encode()
			if err != nil {
				return nil, err
			}
			params = append(params, v...)
		}
		if block <= 0 || len(params) <= block {
			return append(append([]byte{0xC3, 0x03, r.Invoke}, descs...), params...), nil
		}
		x.chunks = split(params, block)
		return append(append([]byte{0xC3, 0x05, r.Invoke}, descs...), x.blockSA(0)...), nil
	}
	return nil, fmt.Errorf("operation %q is not get, set or action", op)
}

// readCount reads a SEQUENCE OF quantity and checks it against the items.
func (x *Exchange) readCount(b []byte) ([]byte, error) {
	n, sz := DecodeLength(b)
	if n < 0 {
		return nil, errors.New("the result list is cut short")
	}
	if n != x.list {
		return nil, fmt.Errorf("the answer has %d results for %d items", n, x.list)
	}
	return b[sz:], nil
}

// getDataResult reads Get-Data-Result: [0] Data or [1] data-access-result.
func getDataResult(b []byte) (ItemResult, []byte, error) {
	if len(b) < 2 {
		return ItemResult{}, nil, errors.New("a result is cut short")
	}
	if b[0] == 1 {
		return ItemResult{Result: int(b[1])}, b[2:], nil
	}
	if b[0] != 0 {
		return ItemResult{}, nil, fmt.Errorf("Get-Data-Result choice %d", b[0])
	}
	src := b[1:]
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return ItemResult{}, nil, fmt.Errorf("a result's data does not decode: %w", err)
	}
	return ItemResult{Data: &d}, src, nil
}

// finishList reads the answers of a list: Get-Data-Results (GET),
// data-access-results (SET) or Action-Response-With-Optional-Data
// (ACTION), after their count.
func (x *Exchange) finishList(b []byte) error {
	x.done = true
	b, err := x.readCount(b)
	if err != nil {
		return err
	}
	res := make([]ItemResult, 0, x.list)
	for range x.list {
		var it ItemResult
		switch x.Req.op() {
		case OpGet:
			if it, b, err = getDataResult(b); err != nil {
				return err
			}
		case OpSet:
			if len(b) < 1 {
				return errors.New("a result is cut short")
			}
			it.Result, b = int(b[0]), b[1:]
		case OpAction:
			if len(b) < 2 {
				return errors.New("a result is cut short")
			}
			it.Result = int(b[0])
			present := b[1]
			b = b[2:]
			if present != 0 {
				var r ItemResult
				if r, b, err = getDataResult(b); err != nil {
					return err
				}
				it.Data = r.Data
				if r.Data == nil && it.Result == 0 {
					it.Result = r.Result
				}
			}
		}
		res = append(res, it)
	}
	if len(b) != 0 {
		return fmt.Errorf("%d octets after the last result", len(b))
	}
	x.res.Items = res
	for _, it := range res {
		if it.Result != 0 {
			x.res.Result = it.Result
			break
		}
	}
	return nil
}

// stepList handles the answers only a request with list gets; ok is false
// for an answer the ordinary steps handle.
func (x *Exchange) stepList(resp []byte) (next []byte, ok bool, err error) {
	b := resp[3:]
	switch op := x.Req.op(); {
	case op == OpGet && resp[0] == 0xC4 && resp[1] == 0x03:
		return nil, true, x.finishList(b)
	case op == OpSet && resp[0] == 0xC5 && resp[1] == 0x05:
		return nil, true, x.finishList(b)
	case op == OpSet && resp[0] == 0xC5 && resp[1] == 0x04: // last-datablock-with-list
		if len(b) < 4 {
			return nil, true, errors.New("set-response-last-datablock-with-list is too short")
		}
		n := binary.BigEndian.Uint32(b[len(b)-4:])
		if n != uint32(x.sent) || x.sent != len(x.chunks) {
			return nil, true, fmt.Errorf("set-response-last-datablock-with-list acknowledges block %d, not %d", n, x.sent)
		}
		return nil, true, x.finishList(b[:len(b)-4])
	case op == OpAction && resp[0] == 0xC7 && resp[1] == 0x03:
		return nil, true, x.finishList(b)
	}
	return nil, false, nil
}

// listOutcome is Outcome for a request with list: every item's result and
// value go into the dlmsResult record ("items"); no single point.
func (x *Exchange) listOutcome(loc *time.Location, result map[string]any) map[string]any {
	items := x.Req.items()
	out := make([]any, 0, len(items))
	for i, it := range items {
		m := map[string]any{"class": int(it.Class), "obis": it.OBIS}
		if x.Req.op() == OpAction {
			m["method"] = int(it.Attr)
		} else {
			m["attribute"] = int(it.Attr)
		}
		if i < len(x.res.Items) {
			m["result"] = x.res.Items[i].Result
			if d := x.res.Items[i].Data; d != nil {
				key := "value"
				if x.Req.op() == OpAction {
					key = "return"
				}
				m[key] = Value(*d, loc, false)
				if x.Req.op() == OpGet {
					m["point"] = PointName(it.OBIS, it.Class, it.Attr)
				}
			}
		}
		out = append(out, m)
	}
	result["items"] = out
	return result
}
