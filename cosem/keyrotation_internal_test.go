package cosem

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cB-Sigma/iotsec"
)

// memStore is an iotsec.Store in memory, JSON as a real store keeps it.
type memStore struct {
	mu   sync.Mutex
	b    []byte
	fail bool
}

func (s *memStore) Load(_ context.Context, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b == nil {
		return iotsec.ErrNotStored
	}
	return json.Unmarshal(s.b, v)
}

func (s *memStore) Save(_ context.Context, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("store down")
	}
	b, err := json.Marshal(v)
	s.b = b
	return err
}

func (s *memStore) state(t *testing.T) RotationState {
	t.Helper()
	var rec rotationRecord
	if err := s.Load(context.Background(), &rec); err != nil {
		t.Fatal(err)
	}
	return rec.State
}

// fakeMeter models a meter's security setup: keys taken by key_transfer or
// key_agreement apply from the next association; an association needs the
// unicast and authentication keys the meter holds; key_transfer needs its
// master key.
type fakeMeter struct {
	keys, pending KeySet
	open          bool
	down          bool // associations fail
	refuse        bool // key_transfer answered with an error, nothing changes
	ignore        bool // key_transfer answered with success, nothing changes
	transfers     int
	crash         string // "before" or "after": panic around the method
}

type crashed struct{}

func (m *fakeMeter) Open(keys KeySet) error {
	m.open = false
	for id, k := range m.pending {
		m.keys[id] = k
	}
	m.pending = nil
	if m.down {
		return errors.New("no answer")
	}
	for _, id := range []byte{KeyGlobalUnicast, KeyAuthentication} {
		if !bytes.Equal(keys[id], m.keys[id]) {
			return errors.New("the association was refused")
		}
	}
	m.open = true
	return nil
}

func (m *fakeMeter) Transfer(master []byte, keys KeySet) error {
	if m.crash == "before" {
		panic(crashed{})
	}
	if !m.open {
		return errNoAssociation
	}
	m.transfers++
	if !bytes.Equal(master, m.keys[KeyMaster]) {
		return errors.New("the meter answered with action result 250")
	}
	if m.refuse {
		return errors.New("the meter answered with action result 250")
	}
	if !m.ignore {
		if m.pending == nil {
			m.pending = KeySet{}
		}
		for id, k := range keys {
			m.pending[id] = append([]byte(nil), k...)
		}
	}
	if m.crash == "after" {
		panic(crashed{})
	}
	return nil
}

func (m *fakeMeter) Agree(ids []byte) (KeySet, error) {
	if !m.open {
		return nil, errNoAssociation
	}
	out := KeySet{}
	m.pending = KeySet{}
	for _, id := range ids {
		k := make([]byte, 16)
		_, _ = rand.Read(k)
		out[id], m.pending[id] = k, append([]byte(nil), k...)
	}
	if m.crash == "after" {
		panic(crashed{})
	}
	return out, nil
}

func (m *fakeMeter) Check() error {
	if !m.open {
		return errNoAssociation
	}
	return nil
}

func (m *fakeMeter) Close() { m.open = false }

func startKeys() KeySet {
	return KeySet{KeyGlobalUnicast: bytes.Repeat([]byte{0x11}, 16), KeyAuthentication: bytes.Repeat([]byte{0x22}, 16),
		KeyGlobalBroadcast: bytes.Repeat([]byte{0x33}, 16), KeyMaster: bytes.Repeat([]byte{0x44}, 16)}
}

func newRotation(m *fakeMeter, st *memStore) (*KeyRotation, *[]RotationState) {
	var states []RotationState
	return &KeyRotation{Link: m, Store: st, StorageKey: bytes.Repeat([]byte{0x5A}, 16),
		OnState: func(s RotationStatus) { states = append(states, s.State) }}, &states
}

func rotateCatching(r *KeyRotation, cur KeySet, ids []byte) (ks KeySet, err error, crash bool) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(crashed); !ok {
				panic(p)
			}
			crash = true
		}
	}()
	ks, err = r.Rotate(context.Background(), cur, ids)
	return ks, err, false
}

// Key rotation by key_transfer: the new keys are stored (wrapped, never in
// clear) before they are sent, sent under the current master key, proved
// by a new association (and, for the master key, by a transfer under the
// new one), then stored as active. A meter that takes nothing or refuses
// leaves the old keys active (rolled back).
//
// Covers: SIG-IPE-069
func TestKeyRotationTransfer(t *testing.T) {
	ctx := context.Background()
	cur := startKeys()
	m := &fakeMeter{keys: cur.Clone()}
	st := &memStore{}
	r, states := newRotation(m, st)
	ks, err := r.Rotate(ctx, cur, []byte{KeyMaster, KeyGlobalUnicast, KeyAuthentication, KeyGlobalBroadcast})
	if err != nil {
		t.Fatal(err)
	}
	for id := byte(0); id <= KeyMaster; id++ {
		if bytes.Equal(ks[id], cur[id]) || !bytes.Equal(ks[id], m.keys[id]) {
			t.Errorf("key %d: rotated % X, meter % X", id, ks[id], m.keys[id])
		}
	}
	if got := strings.Join([]string{string((*states)[0]), string((*states)[1]), string((*states)[2])}, " "); got != "prepared invoked done" || len(*states) != 3 {
		t.Errorf("states %v", *states)
	}
	if s := r.Status(); s.State != RotationDone || len(s.IDs) != 4 || s.Method != RotateByTransfer {
		t.Errorf("status %+v", s)
	}
	if m.transfers != 2 {
		t.Errorf("%d transfers, want the change and the master key proof", m.transfers)
	}
	for _, k := range append([]KeySet{cur}, ks) {
		for _, v := range k {
			if bytes.Contains(st.b, []byte(hex.EncodeToString(v))) {
				t.Fatal("the store holds a key in clear")
			}
		}
	}
	// Resume after done returns the active keys and does nothing.
	r2, _ := newRotation(m, st)
	got, s, err := r2.Resume(ctx)
	if err != nil || s.State != RotationDone || !bytes.Equal(got[KeyGlobalUnicast], ks[KeyGlobalUnicast]) {
		t.Errorf("resume after done: %v %+v", err, s)
	}

	// The meter answers success but keeps its keys: rolled back.
	m.ignore = true
	old := ks
	ks, err = r.Rotate(ctx, old, []byte{KeyGlobalUnicast})
	if !errors.Is(err, ErrRotationRolledBack) || !bytes.Equal(ks[KeyGlobalUnicast], old[KeyGlobalUnicast]) || st.state(t) != RotationRolledBack {
		t.Fatalf("ignored transfer: %v", err)
	}
	// It refuses: rolled back too, the old keys still work.
	m.ignore, m.refuse = false, true
	if _, err := r.Rotate(ctx, old, []byte{KeyAuthentication}); !errors.Is(err, ErrRotationRolledBack) || !strings.Contains(err.Error(), "key_transfer") {
		t.Fatalf("refused transfer: %v", err)
	}
	if !bytes.Equal(m.keys[KeyAuthentication], old[KeyAuthentication]) {
		t.Error("the meter's key changed after a refusal")
	}
	// The meter is unreachable: nothing was sent, rolled back.
	m.refuse, m.down = false, true
	if _, err := r.Rotate(ctx, old, []byte{KeyAuthentication}); !errors.Is(err, ErrRotationRolledBack) {
		t.Fatalf("unreachable meter: %v", err)
	}

	// Checks of the request.
	m.down = false
	noMaster := old.Clone()
	delete(noMaster, KeyMaster)
	for name, c := range map[string]struct {
		r   *KeyRotation
		cur KeySet
		ids []byte
	}{
		"no master":    {r, noMaster, []byte{0}},
		"no ids":       {r, old, nil},
		"repeated id":  {r, old, []byte{0, 0}},
		"id 4":         {r, old, []byte{4}},
		"no store":     {&KeyRotation{Link: m, StorageKey: make([]byte, 16)}, old, []byte{0}},
		"storage key":  {&KeyRotation{Link: m, Store: st, StorageKey: make([]byte, 5)}, old, []byte{0}},
		"wrong method": {&KeyRotation{Link: m, Store: st, StorageKey: make([]byte, 16), Method: "push"}, old, []byte{0}},
	} {
		if _, err := c.r.Rotate(ctx, c.cur, c.ids); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A store that cannot keep the new keys stops the rotation before
	// anything is sent.
	st.fail = true
	before := m.transfers
	if _, err := r.Rotate(ctx, old, []byte{0}); err == nil || m.transfers != before {
		t.Errorf("rotation without storage: %v, %d transfers", err, m.transfers-before)
	}
}

// A process that stops after the meter took the new keys resumes from the
// stored record and finds them active; one that stopped before the method
// reached the meter finds the old keys; when neither set works the record
// stays unconfirmed, a new rotation is refused, and Resume settles it once
// the meter answers again.
//
// Covers: SIG-IPE-069
func TestKeyRotationResume(t *testing.T) {
	ctx := context.Background()
	cur := startKeys()
	m := &fakeMeter{keys: cur.Clone(), crash: "after"}
	st := &memStore{}
	r, _ := newRotation(m, st)
	if _, _, crash := rotateCatching(r, cur, []byte{KeyGlobalUnicast, KeyAuthentication}); !crash {
		t.Fatal("no crash")
	}
	if st.state(t) != RotationPrepared {
		t.Fatalf("stored %v after the crash", st.state(t))
	}
	m.crash = ""
	r2, _ := newRotation(m, st)
	ks, s, err := r2.Resume(ctx)
	if err != nil || s.State != RotationDone || !bytes.Equal(ks[KeyGlobalUnicast], m.keys[KeyGlobalUnicast]) || bytes.Equal(ks[KeyGlobalUnicast], cur[KeyGlobalUnicast]) {
		t.Fatalf("resume: %v %+v", err, s)
	}

	// Stopped before the method reached the meter.
	m.crash = "before"
	cur = ks
	if _, _, crash := rotateCatching(r2, cur, []byte{KeyGlobalUnicast}); !crash {
		t.Fatal("no crash")
	}
	m.crash = ""
	ks, s, err = r2.Resume(ctx)
	if !errors.Is(err, ErrRotationRolledBack) || s.State != RotationRolledBack || !bytes.Equal(ks[KeyGlobalUnicast], cur[KeyGlobalUnicast]) {
		t.Fatalf("resume before the method: %v %+v", err, s)
	}

	// The meter goes quiet after taking the keys: unconfirmed.
	m.crash = "after"
	if _, _, crash := rotateCatching(r2, cur, []byte{KeyAuthentication}); !crash {
		t.Fatal("no crash")
	}
	m.crash, m.down = "", true
	if ks, s, err = r2.Resume(ctx); !errors.Is(err, ErrRotationUnconfirmed) || ks != nil || s.State != RotationUnconfirmed || s.Err == "" {
		t.Fatalf("meter down: %v %+v", err, s)
	}
	if _, err := r2.Rotate(ctx, cur, []byte{0}); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("a rotation over an unconfirmed one: %v", err)
	}
	m.down = false
	if ks, s, err = r2.Resume(ctx); err != nil || s.State != RotationDone || !bytes.Equal(ks[KeyAuthentication], m.keys[KeyAuthentication]) {
		t.Fatalf("meter back: %v %+v", err, s)
	}
	// Nothing stored: idle.
	if ks, s, err := (&KeyRotation{Link: m, Store: &memStore{}, StorageKey: make([]byte, 16)}).Resume(ctx); err != nil || ks != nil || s.State != RotationIdle {
		t.Errorf("empty store: %v %+v", err, s)
	}
	// A record under another storage key is refused.
	if _, _, err := (&KeyRotation{Link: m, Store: st, StorageKey: make([]byte, 16)}).Resume(ctx); err == nil {
		t.Error("a record was read under the wrong storage key")
	}
}

// Key rotation by key_agreement: the agreed keys are stored once the meter
// answers and proved by a new association. A stop between the meter's
// answer and the store loses the agreed keys: the old ones no longer work
// and the record stays unconfirmed (the keys must then be provisioned
// again, by key_transfer under the master key on a working association or
// at the meter).
//
// Covers: SIG-IPE-070
func TestKeyRotationAgreement(t *testing.T) {
	ctx := context.Background()
	cur := startKeys()
	m := &fakeMeter{keys: cur.Clone()}
	st := &memStore{}
	r, states := newRotation(m, st)
	r.Method = RotateByAgreement
	ks, err := r.Rotate(ctx, cur, []byte{KeyGlobalUnicast, KeyAuthentication})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ks[KeyGlobalUnicast], m.keys[KeyGlobalUnicast]) || bytes.Equal(ks[KeyGlobalUnicast], cur[KeyGlobalUnicast]) ||
		!bytes.Equal(ks[KeyMaster], cur[KeyMaster]) || len(*states) != 3 || r.Status().Method != RotateByAgreement {
		t.Fatalf("agreed %v, states %v", ks, *states)
	}
	m.crash = "after"
	if _, _, crash := rotateCatching(r, ks, []byte{KeyGlobalUnicast}); !crash {
		t.Fatal("no crash")
	}
	m.crash = ""
	if _, s, err := r.Resume(ctx); !errors.Is(err, ErrRotationUnconfirmed) || s.State != RotationUnconfirmed {
		t.Fatalf("lost agreement: %v %+v", err, s)
	}
}
