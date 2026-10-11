// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cB-Sigma/iotsec"
)

// kvStore is an iotsec.Store in memory that can fail.
type kvStore struct {
	b    []byte
	fail error
}

func (s *kvStore) Load(_ context.Context, v any) error {
	if s.fail != nil {
		return s.fail
	}
	if s.b == nil {
		return iotsec.ErrNotStored
	}
	return json.Unmarshal(s.b, v)
}

func (s *kvStore) Save(_ context.Context, v any) error {
	if s.fail != nil {
		return s.fail
	}
	b, err := json.Marshal(v)
	s.b = b
	return err
}

// The reservation moves ahead by its window when half of it is used, is
// stored before a counter is handed out, and a store that cannot be read
// or written stops the association.
func TestICReservation(t *testing.T) {
	ctx := context.Background()
	s := &kvStore{}
	r := &ICReservation{Store: s, Window: 100, Name: "M"}
	for _, step := range []struct {
		ic    uint32
		first bool
		want  uint32
		next  string
	}{
		{1, true, 1, `{"next":101}`},
		{40, false, 40, `{"next":101}`},
		{60, false, 60, `{"next":160}`},
	} {
		got, err := r.Reserve(ctx, step.ic, step.first)
		if err != nil || got != step.want || string(s.b) != step.next {
			t.Fatalf("Reserve(%d) = %d, %v; stored %s, want %d and %s", step.ic, got, err, s.b, step.want, step.next)
		}
	}
	again := &ICReservation{Store: s, Window: 100, Name: "M"}
	if got, _ := again.Reserve(ctx, 1, true); got != 160 {
		t.Errorf("after a restart the first counter is %d, want 160", got)
	}
	down := &ICReservation{Store: &kvStore{fail: errors.New("store down")}, Name: "M"}
	if _, err := down.Reserve(ctx, 1, true); err == nil {
		t.Error("a store that cannot be read gave a counter")
	}
	bad := &ICReservation{Store: &kvStore{b: []byte(`{"next":"x"}`)}, Name: "M"}
	if _, err := bad.Reserve(ctx, 1, true); err == nil {
		t.Error("a stored value that does not decode gave a counter")
	}
}

// Counter stores each counter before handing it out and stops at the
// last one.
func TestCounter(t *testing.T) {
	ctx := context.Background()
	s := &kvStore{b: []byte(`{"ic":41}`)}
	c := &Counter{Store: s, Name: "M"}
	if n, err := c.Next(ctx); n != 42 || err != nil || string(s.b) != `{"ic":42}` {
		t.Fatalf("Next = %d, %v; stored %s", n, err, s.b)
	}
	full := &Counter{Store: &kvStore{b: []byte(`{"ic":4294967295}`)}, Name: "M"}
	if _, err := full.Next(ctx); err == nil {
		t.Error("a used-up counter gave another")
	}
}

// An authenticated push moves the stored counter; an encryption-only push
// never does, is refused when repeated, and a counter far ahead takes only
// one place among the recent ones.
func TestPushCounter(t *testing.T) {
	ctx := context.Background()
	s := &kvStore{}
	p := &PushCounter{Store: s, Name: "M"}
	if err := p.Accept(ctx, 10, true); err != nil {
		t.Fatal(err)
	}
	if err := p.Accept(ctx, 10, true); err == nil {
		t.Error("a repeated authenticated counter was accepted")
	}
	if err := p.Accept(ctx, 5, false); err == nil {
		t.Error("an unauthenticated counter below the authenticated one was accepted")
	}
	if err := p.Accept(ctx, 1000, false); err != nil {
		t.Fatal(err)
	}
	if err := p.Accept(ctx, 1000, false); err == nil {
		t.Error("a repeated unauthenticated counter was accepted")
	}
	if err := p.Accept(ctx, 11, true); err != nil {
		t.Errorf("the meter's next authenticated push after a forged jump was refused: %v", err)
	}
	restarted := &PushCounter{Store: s, Name: "M"}
	if err := restarted.Accept(ctx, 11, true); err == nil {
		t.Error("after a restart a replayed push was accepted")
	}
	if err := restarted.Accept(ctx, 1000, false); err == nil {
		t.Error("after a restart a replayed unauthenticated push was accepted")
	}
}
