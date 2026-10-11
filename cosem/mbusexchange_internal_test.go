package cosem

import (
	"strings"
	"testing"
)

// Covers: SIG-IPE-2630
func TestExchangeRefusesBadAnswers(t *testing.T) {
	start := func(op string) *Exchange {
		t.Helper()
		b := CommandRequest{Op: op, Class: 1, OBIS: "0.0.96.50.1.255"}
		if op == OpSet {
			b.Value = "0981C8" + strings.Repeat("00", 200)
		}
		if op == OpAction {
			b.Method, b.Value = 1, "0981C8"+strings.Repeat("00", 200)
		}
		r, err := b.Request()
		if err != nil {
			t.Fatal(err)
		}
		r.Invoke = 0xC5
		x, _, err := r.Start(64)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	for name, c := range map[string]struct {
		op   string
		resp []byte
	}{
		"other invoke-id":       {OpGet, []byte{0xC4, 0x01, 0xC6, 0x00, 0x11, 0x01}},
		"block 2 first":         {OpGet, []byte{0xC4, 0x02, 0xC5, 0x00, 0, 0, 0, 2, 0x00, 0x01, 0xAA}},
		"raw length mismatch":   {OpGet, []byte{0xC4, 0x02, 0xC5, 0x00, 0, 0, 0, 1, 0x00, 0x05, 0xAA}},
		"exception":             {OpGet, []byte{0xD8, 0x01, 0x02}},
		"set ack of block 3":    {OpSet, []byte{0xC5, 0x02, 0xC5, 0, 0, 0, 3}},
		"action ack of block 2": {OpAction, []byte{0xC7, 0x04, 0xC5, 0, 0, 0, 2}},
		"get answer to a set":   {OpSet, []byte{0xC4, 0x01, 0xC5, 0x00, 0x11, 0x01}},
		"truncated":             {OpGet, []byte{0xC4, 0x01}},
	} {
		if _, err := start(c.op).Step(c.resp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A refused GET, SET and ACTION end with their result codes.
	for op, resp := range map[string][]byte{
		OpGet:    {0xC4, 0x01, 0xC5, 0x01, 0x04},
		OpSet:    {0xC5, 0x01, 0xC5, 0x03},
		OpAction: {0xC7, 0x01, 0xC5, 0x0B, 0x00},
	} {
		x := start(op)
		if next, err := x.Step(resp); err != nil || next != nil || !x.Done() || x.Result().Result == 0 {
			t.Errorf("%s refused: %v %v %+v", op, next, err, x.Result())
		}
	}
	// Selective access applies to a get only, and a range needs from <= to.
	for _, b := range []CommandRequest{
		{Op: OpSet, Class: 7, OBIS: "0.0.99.1.0.255", Value: "0F01", Access: &CommandAccess{Selector: "entry", FromEntry: 1}},
		{Class: 7, OBIS: "0.0.99.1.0.255", Access: &CommandAccess{Selector: "range", From: "2026-09-25T10:00:00Z", To: "2026-09-25T09:00:00Z"}},
		{Class: 7, OBIS: "0.0.99.1.0.255", Access: &CommandAccess{Selector: "entry", FromEntry: 0}},
		{Class: 7, OBIS: "0.0.99.1.0.255", Access: &CommandAccess{Selector: "column"}},
		{Op: OpAction, Class: 1, OBIS: "0.0.96.50.2.255"},
	} {
		if _, err := b.Request(); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
	if _, err := ParseKeys(2, strings.Repeat("11", 16), ""); err == nil {
		t.Error("a 16-byte key accepted for suite 2")
	}
	if k, err := ParseKeys(2, strings.Repeat("11", 32), strings.Repeat("22", 32)); err != nil || k.Suite != 2 {
		t.Errorf("suite 2 keys: %v", err)
	}
}
