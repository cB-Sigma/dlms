package lpwan

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Command states in the queue of a meter that sleeps.
const (
	Queued  = "queued"  // waiting for the meter to call
	Sent    = "sent"    // running on the meter's current call
	Done    = "done"    // the meter carried it out
	Failed  = "failed"  // the meter refused it, or every attempt failed
	Expired = "expired" // the meter did not call before it expired
)

// Item is one queued command.
type Item struct {
	ID       string          `json:"id"`
	Meter    string          `json:"meter"`
	Command  json.RawMessage `json:"command"`
	Status   string          `json:"status"`
	Queued   time.Time       `json:"queuedAt"`
	Expires  time.Time       `json:"expiresAt"`
	Updated  time.Time       `json:"updatedAt"`
	Attempts int             `json:"attempts"`
	Error    string          `json:"error,omitempty"`
}

// ErrQueueFull is returned when a meter's queue holds its maximum of
// commands waiting.
var ErrQueueFull = errors.New("the meter's command queue is full")

// QueueOptions bound a queue.
type QueueOptions struct {
	Max      int           // commands waiting per meter (default 16)
	TTL      time.Duration // how long a command waits (default 72 h)
	Attempts int           // calls a command is tried on before it fails (default 3)
	Keep     time.Duration // how long finished commands stay listed (default 7 days)
	Now      func() time.Time
}

// Queue holds commands for meters that are asleep, to run when each next
// calls. It is safe for concurrent use; Snapshot and Restore let the
// caller keep it across restarts.
type Queue struct {
	opt QueueOptions

	mu    sync.Mutex
	items map[string][]*Item // meter → items, oldest first
}

// NewQueue makes a queue.
func NewQueue(opt QueueOptions) *Queue {
	if opt.Max <= 0 {
		opt.Max = 16
	}
	if opt.TTL <= 0 {
		opt.TTL = 72 * time.Hour
	}
	if opt.Attempts <= 0 {
		opt.Attempts = 3
	}
	if opt.Keep <= 0 {
		opt.Keep = 7 * 24 * time.Hour
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Queue{opt: opt, items: map[string][]*Item{}}
}

// Enqueue adds a command for a meter; ttl 0 takes the queue's.
func (q *Queue) Enqueue(meter, id string, cmd json.RawMessage, ttl time.Duration) (Item, error) {
	if ttl <= 0 {
		ttl = q.opt.TTL
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.opt.Now()
	q.expireLocked(now)
	waiting := 0
	for _, it := range q.items[meter] {
		if it.ID == id {
			return *it, fmt.Errorf("command %s is already queued", id)
		}
		if it.Status == Queued || it.Status == Sent {
			waiting++
		}
	}
	if waiting >= q.opt.Max {
		return Item{}, fmt.Errorf("%w (%d waiting)", ErrQueueFull, waiting)
	}
	it := &Item{ID: id, Meter: meter, Command: append(json.RawMessage(nil), cmd...), Status: Queued,
		Queued: now, Expires: now.Add(ttl), Updated: now}
	q.items[meter] = append(q.items[meter], it)
	return *it, nil
}

// Due returns the meter's commands to run now, oldest first, marking them
// sent (expired ones are marked expired first).
func (q *Queue) Due(meter string) []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.opt.Now()
	q.expireLocked(now)
	var out []Item
	for _, it := range q.items[meter] {
		if it.Status == Queued {
			it.Status, it.Updated = Sent, now
			it.Attempts++
			out = append(out, *it)
		}
	}
	return out
}

// Finish records a sent command's outcome: done, or on error queued again
// for the next call until its attempts are used up (then failed). A
// permanent error (the meter refused it) fails at once.
func (q *Queue) Finish(meter, id string, err error, permanent bool) (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range q.items[meter] {
		if it.ID != id {
			continue
		}
		it.Updated = q.opt.Now()
		switch {
		case err == nil:
			it.Status, it.Error = Done, ""
		case permanent || it.Attempts >= q.opt.Attempts:
			it.Status, it.Error = Failed, err.Error()
		default:
			it.Status, it.Error = Queued, err.Error()
		}
		return *it, true
	}
	return Item{}, false
}

// Cancel removes a waiting command.
func (q *Queue) Cancel(meter, id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	items := q.items[meter]
	for i, it := range items {
		if it.ID == id && it.Status == Queued {
			q.items[meter] = append(items[:i:i], items[i+1:]...)
			return true
		}
	}
	return false
}

// Expire marks commands past their expiry and returns them.
func (q *Queue) Expire() []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.expireLocked(q.opt.Now())
}

func (q *Queue) expireLocked(now time.Time) []Item {
	var out []Item
	for m, items := range q.items {
		keep := items[:0]
		for _, it := range items {
			if it.Status == Queued && !now.Before(it.Expires) {
				it.Status, it.Updated = Expired, now
				out = append(out, *it)
			}
			finished := it.Status == Done || it.Status == Failed || it.Status == Expired
			if finished && now.Sub(it.Updated) > q.opt.Keep {
				continue
			}
			keep = append(keep, it)
		}
		if len(keep) == 0 {
			delete(q.items, m)
		} else {
			q.items[m] = keep
		}
	}
	return out
}

// Waiting counts a meter's queued and sent commands.
func (q *Queue) Waiting(meter string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, it := range q.items[meter] {
		if it.Status == Queued || it.Status == Sent {
			n++
		}
	}
	return n
}

// List returns a meter's commands (every meter's with meter ""), newest
// first.
func (q *Queue) List(meter string) []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Item
	for m, items := range q.items {
		if meter != "" && m != meter {
			continue
		}
		for _, it := range items {
			out = append(out, *it)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Queued.Equal(out[j].Queued) {
			return out[i].Queued.After(out[j].Queued)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// Snapshot is every item, for storage.
func (q *Queue) Snapshot() []Item { return q.List("") }

// Restore loads stored items; commands that were being sent when the
// process stopped are queued again.
func (q *Queue) Restore(items []Item) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := len(items) - 1; i >= 0; i-- {
		it := items[i]
		if it.Status == Sent {
			it.Status = Queued
		}
		q.items[it.Meter] = append(q.items[it.Meter], &it)
	}
}
