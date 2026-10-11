package cosem

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// One GET, SET or ACTION with a meter reached over M-Bus, as a sequence
// of APDUs (IEC 62056-5-3:2023 xDLMS services): the caller sends the
// APDU Start returns and each one Step returns, protected as it likes, and
// hands every answer to Step until it reports done. Blocks go both ways:
// GET answers with-datablock are fetched with get-request-next; a SET or
// ACTION too long for the block size goes with-first-datablock /
// with-first-pblock and the rest after each acknowledgement; an ACTION
// answer with-pblock is fetched with action-request-next-pblock.
// Selective access (range or entry) applies to a GET.

// Operations.
const (
	OpGet    = "get"
	OpSet    = "set"
	OpAction = "action"
)

// Access is a selective access of a GET (IEC 62056-6-2:2023 profile
// generic buffer: selector 1 by range, 2 by entry).
type Access struct {
	Selector byte
	// Range: the restricting column (default the clock 0.0.1.0.0.255,
	// class 8, attribute 2) and the date-times from and to.
	RestrictClass uint16
	RestrictOBIS  string
	RestrictAttr  int8
	From, To      time.Time
	Loc           *time.Location
	// Entry: from and to entry (1-based; to 0 is the last).
	FromEntry, ToEntry uint32
}

// parameter is the access selector's parameter.
func (a Access) parameter() (*axdr.DlmsData, error) {
	switch a.Selector {
	case 1:
		obis, class, attr := a.RestrictOBIS, a.RestrictClass, a.RestrictAttr
		if obis == "" {
			obis, class, attr = ClockOBIS, ClassClock, 2
		}
		ln, err := ParseOBIS(obis)
		if err != nil {
			return nil, err
		}
		loc := a.Loc
		if loc == nil {
			loc = time.UTC
		}
		return axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrStructure([]*axdr.DlmsData{
				axdr.CreateAxdrLongUnsigned(class), axdr.CreateAxdrOctetString(hex.EncodeToString(ln[:])),
				axdr.CreateAxdrInteger(attr), axdr.CreateAxdrLongUnsigned(0),
			}),
			axdr.CreateAxdrOctetString(hex.EncodeToString(EncodeDateTime(a.From, loc))),
			axdr.CreateAxdrOctetString(hex.EncodeToString(EncodeDateTime(a.To, loc))),
			axdr.CreateAxdrArray([]*axdr.DlmsData{}),
		}), nil
	case 2:
		return axdr.CreateAxdrStructure([]*axdr.DlmsData{
			axdr.CreateAxdrDoubleLongUnsigned(a.FromEntry), axdr.CreateAxdrDoubleLongUnsigned(a.ToEntry),
			axdr.CreateAxdrLongUnsigned(1), axdr.CreateAxdrLongUnsigned(0), // every column
		}), nil
	}
	return nil, fmt.Errorf("access selector %d is not 1 (range) or 2 (entry)", a.Selector)
}

// Result is what a finished exchange brought.
type Result struct {
	Data   *axdr.DlmsData // GET: the value; ACTION: the return parameters
	Result int            // data-access-result (GET, SET) or action-result (ACTION); 0 success
	// Blocks counts the blocks received (GET, ACTION answers) and Sent the
	// blocks sent (SET, ACTION requests).
	Blocks, Sent int
	// Items are the results of a request with list, in order; Result is
	// then the first item's non-zero result, or 0.
	Items []ItemResult
}

// Exchange runs one request.
type Exchange struct {
	Req    Request
	block  int
	chunks [][]byte // request blocks
	sent   int
	recv   []byte
	recvN  uint32
	res    Result
	done   bool
	list   int // items of a request with list (0: none)
}

// Start begins an exchange; block is the largest raw data of one request
// block (0: no request blocks).
func (r Request) Start(block int) (*Exchange, []byte, error) {
	x := &Exchange{Req: r, block: block}
	if len(r.List) > 0 {
		apdu, err := r.startList(x, block)
		if err != nil {
			return nil, nil, err
		}
		return x, apdu, nil
	}
	op := r.op()
	desc, err := r.descriptor()
	if err != nil {
		return nil, nil, err
	}
	switch op {
	case OpGet:
		apdu := append([]byte{0xC0, 0x01, r.Invoke}, desc...)
		if r.Access == nil {
			return x, append(apdu, 0x00), nil
		}
		p, err := r.Access.parameter()
		if err != nil {
			return nil, nil, err
		}
		pb, err := p.Encode()
		if err != nil {
			return nil, nil, err
		}
		return x, append(append(apdu, 0x01, r.Access.Selector), pb...), nil
	case OpSet:
		if r.Value == nil {
			return nil, nil, errors.New("a SET needs a value")
		}
		v, err := r.Value.Encode()
		if err != nil {
			return nil, nil, err
		}
		if block <= 0 || len(v) <= block {
			return x, append(append(append([]byte{0xC1, 0x01, r.Invoke}, desc...), 0x00), v...), nil
		}
		x.chunks = split(v, block)
		return x, append(append(append([]byte{0xC1, 0x02, r.Invoke}, desc...), 0x00), x.blockSA(0)...), nil
	case OpAction:
		var v []byte
		if r.Value != nil {
			if v, err = r.Value.Encode(); err != nil {
				return nil, nil, err
			}
		}
		if r.Value == nil {
			return x, append(append([]byte{0xC3, 0x01, r.Invoke}, desc...), 0x00), nil
		}
		if block <= 0 || len(v) <= block {
			return x, append(append(append([]byte{0xC3, 0x01, r.Invoke}, desc...), 0x01), v...), nil
		}
		x.chunks = split(v, block)
		return x, append(append([]byte{0xC3, 0x04, r.Invoke}, desc...), x.blockSA(0)...), nil
	}
	return nil, nil, fmt.Errorf("operation %q is not get, set or action", op)
}

func split(b []byte, n int) [][]byte {
	var out [][]byte
	for len(b) > n {
		out = append(out, b[:n])
		b = b[n:]
	}
	return append(out, b)
}

// blockSA encodes request block i: last-block, block-number (from 1),
// raw-data.
func (x *Exchange) blockSA(i int) []byte {
	x.sent = i + 1
	x.res.Sent = x.sent
	last := byte(0)
	if i == len(x.chunks)-1 {
		last = 1
	}
	out := []byte{last, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(i+1))
	l, _ := axdr.EncodeLength(len(x.chunks[i]))
	return append(append(out, l...), x.chunks[i]...)
}

// Done reports a finished exchange.
func (x *Exchange) Done() bool { return x.done }

// Result is what a finished exchange brought.
func (x *Exchange) Result() Result { return x.res }

// Step takes the meter's answer (unprotected) and returns the next APDU
// to send, or nil when the exchange is done.
func (x *Exchange) Step(resp []byte) ([]byte, error) {
	if x.done {
		return nil, errors.New("the exchange is finished")
	}
	if len(resp) >= 1 && (resp[0] == 0xD8 || resp[0] == 0x0E) {
		x.done = true
		return nil, fmt.Errorf("the meter refused the request (APDU % X)", resp)
	}
	if len(resp) < 4 {
		return nil, fmt.Errorf("answer % X is too short", resp)
	}
	if resp[2] != x.Req.Invoke {
		return nil, fmt.Errorf("answer invoke-id %02X, not %02X", resp[2], x.Req.Invoke)
	}
	inv := x.Req.Invoke
	b := resp[3:]
	if x.list > 0 {
		if next, ok, err := x.stepList(resp); ok {
			return next, err
		}
	}
	switch op := x.Req.op(); {
	case op == OpGet && resp[0] == 0xC4 && resp[1] == 0x01:
		return nil, x.finishResult(b)
	case op == OpGet && resp[0] == 0xC4 && resp[1] == 0x02:
		last, n, raw, dar, err := dataBlock(b, true)
		if err != nil {
			return nil, err
		}
		if dar >= 0 {
			x.done, x.res.Result = true, dar
			return nil, nil
		}
		if err := x.takeBlock(n, raw); err != nil {
			return nil, err
		}
		if last {
			return nil, x.finishData()
		}
		out := []byte{0xC0, 0x02, inv, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[3:], n)
		return out, nil
	case op == OpSet && resp[0] == 0xC5 && resp[1] == 0x01:
		x.done, x.res.Result = true, int(b[0])
		return nil, nil
	case op == OpSet && resp[0] == 0xC5 && resp[1] == 0x02:
		if len(b) < 4 || binary.BigEndian.Uint32(b) != uint32(x.sent) || x.sent >= len(x.chunks) {
			return nil, fmt.Errorf("set-response-datablock % X does not acknowledge block %d", b, x.sent)
		}
		return append([]byte{0xC1, 0x03, inv}, x.blockSA(x.sent)...), nil
	case op == OpSet && resp[0] == 0xC5 && resp[1] == 0x03:
		if len(b) < 5 {
			return nil, errors.New("set-response-last-datablock is too short")
		}
		x.done, x.res.Result = true, int(b[0])
		return nil, nil
	case op == OpAction && resp[0] == 0xC7 && resp[1] == 0x04: // next-pblock
		if len(b) < 4 || binary.BigEndian.Uint32(b) != uint32(x.sent) || x.sent >= len(x.chunks) {
			return nil, fmt.Errorf("action-response-next-pblock % X does not acknowledge block %d", b, x.sent)
		}
		return append([]byte{0xC3, 0x06, inv}, x.blockSA(x.sent)...), nil
	case op == OpAction && resp[0] == 0xC7 && resp[1] == 0x01:
		x.res.Result = int(b[0])
		x.done = true
		if len(b) < 2 || b[1] == 0 {
			return nil, nil
		}
		return nil, x.finishResult(b[2:])
	case op == OpAction && resp[0] == 0xC7 && resp[1] == 0x02: // with-pblock
		last, n, raw, _, err := dataBlock(b, false)
		if err != nil {
			return nil, err
		}
		if err := x.takeBlock(n, raw); err != nil {
			return nil, err
		}
		if last {
			return nil, x.finishData()
		}
		out := []byte{0xC3, 0x02, inv, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[3:], n)
		return out, nil
	}
	return nil, fmt.Errorf("answer % X does not fit a %s", resp[:2], x.Req.op())
}

// dataBlock reads DataBlock-G (withResult: raw-data [0] or
// data-access-result [1]) or DataBlock-SA; dar is -1 for data.
func dataBlock(b []byte, withResult bool) (last bool, n uint32, raw []byte, dar int, err error) {
	if len(b) < 6 {
		return false, 0, nil, 0, errors.New("the data block is too short")
	}
	last, n, b = b[0] != 0, binary.BigEndian.Uint32(b[1:5]), b[5:]
	if withResult {
		if b[0] == 1 {
			if len(b) < 2 {
				return false, 0, nil, 0, errors.New("the data block result is cut short")
			}
			return last, n, nil, int(b[1]), nil
		}
		b = b[1:]
	}
	l, sz := DecodeLength(b)
	if l < 0 || sz+l != len(b) {
		return false, 0, nil, 0, errors.New("the data block's raw data length does not match")
	}
	return last, n, b[sz:], -1, nil
}

func (x *Exchange) takeBlock(n uint32, raw []byte) error {
	if n != x.recvN+1 {
		x.done = true
		return fmt.Errorf("block %d arrived after block %d", n, x.recvN)
	}
	x.recvN = n
	x.res.Blocks++
	x.recv = append(x.recv, raw...)
	return nil
}

// finishResult reads Get-Data-Result: [0] data or [1] data-access-result.
func (x *Exchange) finishResult(b []byte) error {
	x.done = true
	if len(b) < 2 {
		return errors.New("the result is too short")
	}
	if b[0] == 1 {
		x.res.Result = int(b[1])
		return nil
	}
	x.recv = b[1:]
	return x.finishData()
}

func (x *Exchange) finishData() error {
	x.done = true
	if x.list > 0 {
		// The blocks of a list answer carry the encoded result list.
		return x.finishList(x.recv)
	}
	src := x.recv
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return fmt.Errorf("the data does not decode: %w", err)
	}
	x.res.Data = &d
	return nil
}

// Outcome is what a finished exchange writes: the attribute's point and
// value (a GET that brought data; empty otherwise) and the dlmsResult
// record.
func (x *Exchange) Outcome(loc *time.Location) (point string, value any, result map[string]any) {
	r, res := x.Req, x.res
	result = map[string]any{"op": r.op(), "class": int(r.Class), "obis": r.OBIS, "result": res.Result}
	if r.op() == OpAction {
		result["method"] = int(r.Attr)
	} else {
		result["attribute"] = int(r.Attr)
	}
	if res.Blocks > 0 {
		result["blocksReceived"] = res.Blocks
	}
	if res.Sent > 1 {
		result["blocksSent"] = res.Sent
	}
	if r.Access != nil {
		result["access"] = map[byte]string{1: "range", 2: "entry"}[r.Access.Selector]
	}
	if x.list > 0 {
		return "", nil, x.listOutcome(loc, result)
	}
	if res.Data == nil {
		return "", nil, result
	}
	v := Value(*res.Data, loc, false)
	if r.op() == OpAction {
		result["return"] = v
		return "", nil, result
	}
	return PointName(r.OBIS, r.Class, r.Attr), v, result
}
