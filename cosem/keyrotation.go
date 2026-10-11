package cosem

// Key rotation as a client state machine over the security setup object
// (class 64): new global unicast, broadcast, authentication or master keys
// are sent with key_transfer (wrapped under the current master key) or
// agreed with key_agreement, proved by associating with them, and kept in
// an iotsec.Store (wrapped under a storage key) at every step, so a process
// that stops half way resumes from the stored state.
//
// States, as stored and reported:
//
//	prepared     the new keys (transfer) or the intent (agreement) are
//	             stored; the method may or may not have reached the meter
//	invoked      the meter answered the method with success
//	done         an association with the new keys works: they are active
//	rolled-back  the new keys did not work and the old ones do: the old
//	             keys are active (also when nothing reached the meter)
//	unconfirmed  neither key set works for now; both are kept and Resume
//	             tries them again
//
// The meter applies new keys from the next association (as dlms-sim's
// meter does). A master key change is proved by sending the authentication
// key again (the same value) wrapped under the new master key, which the
// meter only takes if it holds that master key. A broadcast key change is
// proved only by the meter's answer to the method: no association uses it.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/cB-Sigma/iotsec"
)

// KeySet holds keys by key_id (KeyGlobalUnicast, KeyGlobalBroadcast,
// KeyAuthentication, KeyMaster).
type KeySet map[byte][]byte

// Clone copies the set and its keys.
func (k KeySet) Clone() KeySet {
	if k == nil {
		return nil
	}
	out := KeySet{}
	for id, v := range k {
		out[id] = append([]byte(nil), v...)
	}
	return out
}

// RotationMethod is how new keys reach the meter.
type RotationMethod string

// Rotation methods.
const (
	RotateByTransfer  RotationMethod = "transfer"  // key_transfer (method 2)
	RotateByAgreement RotationMethod = "agreement" // key_agreement (method 3)
)

// RotationState is a step of a key rotation.
type RotationState string

// Rotation states (see the package comment above).
const (
	RotationIdle        RotationState = "idle"
	RotationPrepared    RotationState = "prepared"
	RotationInvoked     RotationState = "invoked"
	RotationDone        RotationState = "done"
	RotationRolledBack  RotationState = "rolled-back"
	RotationUnconfirmed RotationState = "unconfirmed"
)

// pending reports a state a new rotation must not start from.
func (s RotationState) pending() bool {
	return s == RotationPrepared || s == RotationInvoked || s == RotationUnconfirmed
}

// RotationStatus is the state of a rotation as callers see it.
type RotationStatus struct {
	State  RotationState
	Method RotationMethod
	IDs    []byte // the key_ids being changed
	Err    string // why the rotation stopped short, when it did
}

// Errors of a key rotation.
var (
	// ErrRotationPending: an earlier rotation is not settled; call Resume.
	ErrRotationPending = errors.New("an earlier key rotation is not settled yet")
	// ErrRotationRolledBack: the new keys did not work; the old keys are
	// active (the error wraps the cause).
	ErrRotationRolledBack = errors.New("the new keys were not taken; the old keys are kept")
	// ErrRotationUnconfirmed: neither key set works now; both are stored
	// and Resume tries them again.
	ErrRotationUnconfirmed = errors.New("neither the new nor the old keys work yet")
)

// RotationLink is what a rotation drives: associations opened with a key
// set and the security setup methods on the open one.
type RotationLink interface {
	// Open associates with the given keys (closing any open association).
	Open(keys KeySet) error
	// Transfer runs key_transfer with keys wrapped under master.
	Transfer(master []byte, keys KeySet) error
	// Agree runs key_agreement for the key_ids and returns the keys.
	Agree(ids []byte) (KeySet, error)
	// Check proves the open association works through its protection.
	Check() error
	// Close releases the open association.
	Close()
}

// ClientRotationLink is a RotationLink over a Client: Open sets the keys
// of Client.Config.HLS.Security (so the client keeps the last keys opened)
// and connects; Check reads security_policy of the security setup object.
type ClientRotationLink struct {
	Client    *Client
	SetupOBIS string // default 0.0.43.0.0.255
}

func (l *ClientRotationLink) obis() string {
	if l.SetupOBIS == "" {
		return "0.0.43.0.0.255"
	}
	return l.SetupOBIS
}

// Open applies keys to the client's security and associates.
func (l *ClientRotationLink) Open(keys KeySet) error {
	cfg := &l.Client.Config
	if cfg.HLS == nil {
		return errors.New("key rotation needs the client's HLS settings")
	}
	sec := &cfg.HLS.Security
	for id, dst := range map[byte]*[]byte{KeyGlobalUnicast: &sec.Key, KeyAuthentication: &sec.AuthKey,
		KeyGlobalBroadcast: &sec.BroadcastKey, KeyMaster: &sec.MasterKey} {
		if k, ok := keys[id]; ok {
			*dst = append([]byte(nil), k...)
		}
	}
	return l.Client.Connect()
}

func (l *ClientRotationLink) setup() (SecuritySetup, error) {
	a := l.Client.Association()
	if a == nil {
		return SecuritySetup{}, errNoAssociation
	}
	return SecuritySetup{Client: a.Client, Secure: l.Client.Secure(), OBIS: l.obis()}, nil
}

// Transfer runs key_transfer on the open association.
func (l *ClientRotationLink) Transfer(master []byte, keys KeySet) error {
	s, err := l.setup()
	if err != nil {
		return err
	}
	return s.TransferKeys(master, keys)
}

// Agree runs key_agreement on the open association with the client's
// signing keys and system title.
func (l *ClientRotationLink) Agree(ids []byte) (KeySet, error) {
	s, err := l.setup()
	if err != nil {
		return nil, err
	}
	got, err := s.AgreeKeys(&l.Client.Config.HLS.Security, ids)
	return KeySet(got), err
}

// Check reads security_policy (attribute 2) through the association.
func (l *ClientRotationLink) Check() error {
	_, err := l.Client.Get(ClassSecuritySetup, l.obis(), 2)
	return err
}

// Close closes the client's association.
func (l *ClientRotationLink) Close() { l.Client.Close() }

// KeyRotation changes keys on one meter. It is not safe for concurrent
// use; run one rotation per meter at a time.
type KeyRotation struct {
	Link RotationLink
	// Store keeps the rotation record; StorageKey (an AES key) wraps every
	// key in it (RFC 3394), so the store never holds a key in clear.
	Store      iotsec.Store
	StorageKey []byte
	// Method is RotateByTransfer (the default) or RotateByAgreement.
	Method RotationMethod
	// KeyLen is the length of generated keys: by default that of the
	// current unicast key, else 16.
	KeyLen int
	// Rand generates keys (default crypto/rand).
	Rand io.Reader
	// OnState, when set, learns of every state stored.
	OnState func(RotationStatus)

	status RotationStatus
}

// rotationRecord is the stored form: keys wrapped under the storage key,
// in hex, by key_id. Old are the keys before the rotation, New the keys it
// sets; the active ones are New when done and Old when rolled back.
type rotationRecord struct {
	State  RotationState     `json:"state"`
	Method RotationMethod    `json:"method"`
	IDs    []int             `json:"ids"`
	Old    map[string]string `json:"old"`
	New    map[string]string `json:"new,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// rotation is a record with its keys unwrapped.
type rotation struct {
	state     RotationState
	method    RotationMethod
	ids       []byte
	old, next KeySet
	err       string
}

// Status is the state of the last rotation run or resumed.
func (r *KeyRotation) Status() RotationStatus {
	s := r.status
	s.IDs = slices.Clone(s.IDs)
	return s
}

func (r *KeyRotation) check() error {
	if r.Link == nil || r.Store == nil {
		return errors.New("key rotation needs a link and a store")
	}
	if _, err := WrapKey(r.StorageKey, make([]byte, 16)); err != nil {
		return fmt.Errorf("key rotation storage key: %w", err)
	}
	return nil
}

// Rotate changes the keys named by ids (key_ids 0 to 3) from current,
// which must hold the keys the meter takes now (the master key too for
// key_transfer), and returns the keys active afterwards: the new ones, or
// with ErrRotationRolledBack the old ones, or nil with
// ErrRotationUnconfirmed. An unsettled earlier rotation is refused with
// ErrRotationPending.
func (r *KeyRotation) Rotate(ctx context.Context, current KeySet, ids []byte) (KeySet, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	method := r.Method
	if method == "" {
		method = RotateByTransfer
	}
	if method != RotateByTransfer && method != RotateByAgreement {
		return nil, fmt.Errorf("key rotation method %q is not transfer or agreement", method)
	}
	ids = slices.Clone(ids)
	slices.Sort(ids)
	if len(ids) == 0 || len(slices.Compact(slices.Clone(ids))) != len(ids) || ids[len(ids)-1] > KeyMaster {
		return nil, fmt.Errorf("key rotation needs distinct key_ids 0 to 3, not %v", ids)
	}
	if method == RotateByTransfer && current[KeyMaster] == nil {
		return nil, errors.New("key_transfer needs the current master key")
	}
	prev, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	if prev != nil && prev.state.pending() {
		r.status = prev.status()
		return nil, ErrRotationPending
	}
	rot := &rotation{method: method, ids: ids, old: current.Clone()}
	if method == RotateByTransfer {
		n := r.KeyLen
		if n == 0 {
			n = len(current[KeyGlobalUnicast])
		}
		if n == 0 {
			n = 16
		}
		rnd := r.Rand
		if rnd == nil {
			rnd = rand.Reader
		}
		fresh := KeySet{}
		for _, id := range ids {
			k := make([]byte, n)
			if _, err := io.ReadFull(rnd, k); err != nil {
				return nil, fmt.Errorf("generating key %d: %w", id, err)
			}
			fresh[id] = k
		}
		rot.next = current.Clone()
		for id, k := range fresh {
			rot.next[id] = k
		}
		// Stored before they are sent: a stop after the transfer cannot
		// lose them.
		if err := r.save(ctx, rot, RotationPrepared, ""); err != nil {
			return nil, fmt.Errorf("storing the new keys before sending them: %w", err)
		}
		if err := r.Link.Open(rot.old); err != nil {
			r.Link.Close()
			return r.rolledBack(ctx, rot, fmt.Errorf("associating with the current keys: %w", err))
		}
		if err := r.Link.Transfer(rot.old[KeyMaster], fresh); err != nil {
			// A refusal leaves the old keys; a lost answer may not:
			// settle by trying both.
			return r.settle(ctx, rot, fmt.Errorf("key_transfer: %w", err))
		}
	} else {
		if err := r.save(ctx, rot, RotationPrepared, ""); err != nil {
			return nil, fmt.Errorf("storing the rotation before key_agreement: %w", err)
		}
		if err := r.Link.Open(rot.old); err != nil {
			r.Link.Close()
			return r.rolledBack(ctx, rot, fmt.Errorf("associating with the current keys: %w", err))
		}
		agreed, err := r.Link.Agree(ids)
		if err != nil {
			return r.settle(ctx, rot, fmt.Errorf("key_agreement: %w", err))
		}
		rot.next = current.Clone()
		for _, id := range ids {
			if agreed[id] == nil {
				return r.settle(ctx, rot, fmt.Errorf("key_agreement gave no key %d", id))
			}
			rot.next[id] = agreed[id]
		}
	}
	if err := r.save(ctx, rot, RotationInvoked, ""); err != nil {
		// The meter has the keys; keep going and report the store
		// failure if nothing else goes wrong.
		ks, verr := r.settle(ctx, rot, nil)
		if verr != nil {
			return ks, verr
		}
		return ks, fmt.Errorf("the new keys work but the invoked state could not be stored: %w", err)
	}
	return r.settle(ctx, rot, nil)
}

// Resume settles a rotation a stopped process left: it proves the new keys
// or the old ones and stores the outcome. With nothing stored it returns
// nil keys and RotationIdle; a settled rotation returns its active keys.
func (r *KeyRotation) Resume(ctx context.Context) (KeySet, RotationStatus, error) {
	if err := r.check(); err != nil {
		return nil, RotationStatus{}, err
	}
	rot, err := r.load(ctx)
	if err != nil {
		return nil, RotationStatus{}, err
	}
	if rot == nil {
		r.status = RotationStatus{State: RotationIdle}
		return nil, r.Status(), nil
	}
	r.status = rot.status()
	switch rot.state {
	case RotationDone:
		return rot.next.Clone(), r.Status(), nil
	case RotationRolledBack:
		return rot.old.Clone(), r.Status(), nil
	}
	ks, err := r.settle(ctx, rot, nil)
	return ks, r.Status(), err
}

// settle proves the new keys, then the old ones, and stores the outcome.
func (r *KeyRotation) settle(ctx context.Context, rot *rotation, cause error) (KeySet, error) {
	r.Link.Close()
	var errs []error
	if cause != nil {
		errs = append(errs, cause)
	}
	if rot.next != nil {
		err := r.prove(rot, rot.next)
		r.Link.Close()
		if err == nil {
			if serr := r.save(ctx, rot, RotationDone, ""); serr != nil {
				return rot.next.Clone(), fmt.Errorf("the new keys work but could not be stored as active: %w", serr)
			}
			return rot.next.Clone(), nil
		}
		errs = append(errs, fmt.Errorf("the new keys: %w", err))
	}
	err := r.prove(rot, rot.old)
	r.Link.Close()
	if err == nil {
		return r.rolledBack(ctx, rot, errors.Join(errs...))
	}
	errs = append(errs, fmt.Errorf("the old keys: %w", err))
	why := errors.Join(errs...)
	if serr := r.save(ctx, rot, RotationUnconfirmed, why.Error()); serr != nil {
		return nil, fmt.Errorf("%w (%v); storing that failed: %v", ErrRotationUnconfirmed, why, serr)
	}
	return nil, fmt.Errorf("%w: %v", ErrRotationUnconfirmed, why)
}

// rolledBack stores the old keys as active.
func (r *KeyRotation) rolledBack(ctx context.Context, rot *rotation, cause error) (KeySet, error) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	if err := r.save(ctx, rot, RotationRolledBack, msg); err != nil {
		return rot.old.Clone(), fmt.Errorf("%w (%v); storing that failed: %v", ErrRotationRolledBack, cause, err)
	}
	return rot.old.Clone(), fmt.Errorf("%w: %v", ErrRotationRolledBack, cause)
}

// prove associates with keys and checks the association; when the master
// key is being changed it also sends the authentication key (or the
// unicast key) again under keys' master key.
func (r *KeyRotation) prove(rot *rotation, keys KeySet) error {
	if err := r.Link.Open(keys); err != nil {
		return err
	}
	if err := r.Link.Check(); err != nil {
		return err
	}
	if !slices.Contains(rot.ids, KeyMaster) || keys[KeyMaster] == nil {
		return nil
	}
	for _, id := range []byte{KeyAuthentication, KeyGlobalUnicast} {
		if k := keys[id]; k != nil {
			if err := r.Link.Transfer(keys[KeyMaster], KeySet{id: k}); err != nil {
				return fmt.Errorf("the master key: %w", err)
			}
			return nil
		}
	}
	return nil
}

func (rot *rotation) status() RotationStatus {
	return RotationStatus{State: rot.state, Method: rot.method, IDs: slices.Clone(rot.ids), Err: rot.err}
}

// save stores the rotation in a state and reports it.
func (r *KeyRotation) save(ctx context.Context, rot *rotation, state RotationState, why string) error {
	rec := rotationRecord{State: state, Method: rot.method, Error: why}
	for _, id := range rot.ids {
		rec.IDs = append(rec.IDs, int(id))
	}
	var err error
	if rec.Old, err = r.wrapSet(rot.old); err != nil {
		return err
	}
	if rec.New, err = r.wrapSet(rot.next); err != nil {
		return err
	}
	if err := r.Store.Save(ctx, rec); err != nil {
		return err
	}
	rot.state, rot.err = state, why
	r.status = rot.status()
	if r.OnState != nil {
		r.OnState(r.Status())
	}
	return nil
}

// load reads the stored rotation, nil when there is none.
func (r *KeyRotation) load(ctx context.Context) (*rotation, error) {
	var rec rotationRecord
	switch err := r.Store.Load(ctx, &rec); {
	case errors.Is(err, iotsec.ErrNotStored):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("reading the key rotation record: %w", err)
	}
	rot := &rotation{state: rec.State, method: rec.Method, err: rec.Error}
	for _, id := range rec.IDs {
		if id < 0 || id > int(KeyMaster) {
			return nil, fmt.Errorf("the key rotation record names key %d", id)
		}
		rot.ids = append(rot.ids, byte(id))
	}
	var err error
	if rot.old, err = r.unwrapSet(rec.Old); err != nil {
		return nil, fmt.Errorf("the key rotation record: old keys: %w", err)
	}
	if rot.next, err = r.unwrapSet(rec.New); err != nil {
		return nil, fmt.Errorf("the key rotation record: new keys: %w", err)
	}
	return rot, nil
}

func (r *KeyRotation) wrapSet(ks KeySet) (map[string]string, error) {
	if ks == nil {
		return nil, nil
	}
	out := map[string]string{}
	for id, k := range ks {
		if k == nil {
			continue
		}
		w, err := WrapKey(r.StorageKey, k)
		if err != nil {
			return nil, fmt.Errorf("wrapping key %d for the store: %w", id, err)
		}
		out[strconv.Itoa(int(id))] = hex.EncodeToString(w)
	}
	return out, nil
}

func (r *KeyRotation) unwrapSet(w map[string]string) (KeySet, error) {
	if w == nil {
		return nil, nil
	}
	ks := KeySet{}
	for name, v := range w {
		id, err := strconv.Atoi(name)
		if err != nil || id < 0 || id > int(KeyMaster) {
			return nil, fmt.Errorf("key %q is not a key_id", name)
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if ks[byte(id)], err = UnwrapKey(r.StorageKey, b); err != nil {
			return nil, fmt.Errorf("key %d: %w", id, err)
		}
	}
	return ks, nil
}
