package cosem

// Invocation counters across restarts, kept through an iotsec.Store (the
// application's durable storage). A meter keeps the last invocation
// counter it saw from a client under a key and refuses a lower or equal
// one, so a client that restarts must not start at 1 again; and a push
// whose counter was accepted once must not be accepted again.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cB-Sigma/iotsec"
)

// DefaultICWindow is how far ICReservation reserves ahead.
const DefaultICWindow = 100000

// ICReservation keeps a reservation, "next", above every invocation
// counter the process may have used for an association's key. Each
// association starts at least there, and the reservation moves Window
// ahead whenever fewer than half of it remain, so one write covers many
// associations and a restart skips at most Window. The stored value is
// {"next": n}.
type ICReservation struct {
	Store  iotsec.Store
	Window uint32 // default DefaultICWindow
	// Name names the meter in errors.
	Name string

	mu       sync.Mutex
	loaded   bool
	reserved uint32
}

// Reserve returns ic, raised to the stored reservation when first is set
// (the first association since a restart), and keeps the reservation
// ahead of it; the reservation is stored before Reserve returns.
func (r *ICReservation) Reserve(ctx context.Context, ic uint32, first bool) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.loaded {
		var m map[string]any
		switch err := r.Store.Load(ctx, &m); {
		case err == nil:
			f, ok := m["next"].(float64)
			if !ok {
				return 0, fmt.Errorf("meter %s: the stored invocation counter does not decode", r.Name)
			}
			r.reserved = uint32(f)
		case errors.Is(err, iotsec.ErrNotStored):
		default:
			return 0, fmt.Errorf("meter %s: reading the stored invocation counter: %w", r.Name, err)
		}
		r.loaded = true
	}
	if first && ic < r.reserved {
		ic = r.reserved
	}
	w := r.Window
	if w == 0 {
		w = DefaultICWindow
	}
	if uint64(ic)+uint64(w/2) > uint64(r.reserved) {
		next := uint64(ic) + uint64(w)
		if next > uint64(^uint32(0)) {
			next = uint64(^uint32(0))
		}
		if err := r.Store.Save(ctx, map[string]any{"next": next}); err != nil {
			return 0, fmt.Errorf("meter %s: storing the invocation counter: %w", r.Name, err)
		}
		r.reserved = uint32(next)
	}
	return ic, nil
}

// Counter hands out the invocation counters of the APDUs a client
// protects for one meter (general-glo-ciphering never reuses a counter
// with a key): each counter is stored before it is used, so a restart
// continues above it. The stored value is {"ic": n}.
type Counter struct {
	Store iotsec.Store
	Name  string // the meter, in errors

	mu     sync.Mutex
	loaded bool
	ic     uint32
}

// Next returns the next counter, stored first.
func (c *Counter) Next(ctx context.Context) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		var m map[string]any
		switch err := c.Store.Load(ctx, &m); {
		case err == nil:
			f, ok := m["ic"].(float64)
			if !ok {
				return 0, fmt.Errorf("meter %s: the stored DLMS counter does not decode", c.Name)
			}
			c.ic = uint32(f)
		case errors.Is(err, iotsec.ErrNotStored):
		default:
			return 0, fmt.Errorf("meter %s: reading the stored DLMS counter: %w", c.Name, err)
		}
		c.loaded = true
	}
	if c.ic == ^uint32(0) {
		return 0, fmt.Errorf("meter %s: the DLMS invocation counter is used up; change the key", c.Name)
	}
	next := c.ic + 1
	if err := c.Store.Save(ctx, map[string]any{"ic": next}); err != nil {
		return 0, fmt.Errorf("meter %s: storing the DLMS counter: %w", c.Name, err)
	}
	c.ic = next
	return next, nil
}

// RecentPushICs bounds the counters of unauthenticated pushes a
// PushCounter keeps.
const RecentPushICs = 64

// PushCounter keeps the invocation counter of the last protected push
// accepted from a meter. A push is accepted only after its counter is
// stored, so a replayed push is refused after a restart too.
//
// An authenticated push (its tag verified with the meter's keys) moves the
// stored counter ("ic"), and every later push must be past it. An
// encryption-only push proves nothing about its sender: anyone holding
// shared global keys could send one with a counter far ahead and so block
// the meter's own pushes. It therefore never moves "ic"; it is refused if
// its counter is at or below "ic", or is one of the recent unauthenticated
// counters kept ("recent", ascending, the newest RecentPushICs), or, once
// that list is full, at or below its smallest. A counter far ahead only
// takes one place in the list, so the meter's next push is still taken.
// The stored value is {"last": n, "ic": n, "recent": [n...]}.
type PushCounter struct {
	Store iotsec.Store
	Name  string // the meter, in errors

	mu     sync.Mutex
	loaded bool
	ic     uint32
	seen   bool
	recent []uint32
}

// Accept checks a push's invocation counter against the stored ones and
// stores it.
func (p *PushCounter) Accept(ctx context.Context, ic uint32, authenticated bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.load(ctx); err != nil {
		return err
	}
	if p.seen && ic <= p.ic {
		return fmt.Errorf("meter %s repeated push invocation counter %d (last accepted %d)", p.Name, ic, p.ic)
	}
	recent := p.recent
	if !authenticated {
		i, found := slices.BinarySearch(recent, ic)
		if found || (len(recent) >= RecentPushICs && ic <= recent[0]) {
			return fmt.Errorf("meter %s repeated push invocation counter %d (an unauthenticated push already seen)", p.Name, ic)
		}
		recent = slices.Insert(slices.Clone(recent), i, ic)
		if len(recent) > RecentPushICs {
			recent = recent[1:]
		}
	}
	stored, seen := p.ic, p.seen
	if authenticated {
		stored, seen = ic, true
	}
	v := map[string]any{"last": ic}
	if seen {
		v["ic"] = stored
	}
	if len(recent) > 0 {
		v["recent"] = recent
	}
	if err := p.Store.Save(ctx, v); err != nil {
		return fmt.Errorf("meter %s: storing the push counter: %w", p.Name, err)
	}
	p.ic, p.seen, p.recent = stored, seen, recent
	return nil
}

// load reads the stored counters once (callers hold mu).
func (p *PushCounter) load(ctx context.Context) error {
	if p.loaded {
		return nil
	}
	var m map[string]any
	switch err := p.Store.Load(ctx, &m); {
	case err == nil:
		f, ok := m["ic"].(float64)
		list, lok := m["recent"].([]any)
		if !ok && !lok {
			return fmt.Errorf("meter %s: the stored push counter does not decode", p.Name)
		}
		if ok {
			p.ic, p.seen = uint32(f), true
		}
		for _, x := range list {
			if n, ok := x.(float64); ok {
				p.recent = append(p.recent, uint32(n))
			}
		}
		slices.Sort(p.recent)
	case errors.Is(err, iotsec.ErrNotStored):
	default:
		return fmt.Errorf("meter %s: reading the stored push counter: %w", p.Name, err)
	}
	p.loaded = true
	return nil
}
