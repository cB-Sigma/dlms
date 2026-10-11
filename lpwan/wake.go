package lpwan

import (
	"fmt"
	"sync"
	"time"
)

// Sleep describes how an NB-IoT (or LTE-M) meter sleeps: 3GPP power
// saving mode (PSM) and extended discontinuous reception (eDRX) as the
// network granted them. We cannot reach a meter in PSM; after each call
// it listens for about its active time (T3324), then sleeps until its
// next call or periodic update (T3412). With eDRX it listens once per
// cycle for its paging time window. These are per-meter settings; the
// values come from the meter or the operator, as the network grants them.
type Sleep struct {
	// ActiveTime is how long the meter listens after it last sent
	// (T3324; default 20 s). Requests are only sent within it.
	ActiveTime Duration `json:"activeTime,omitempty"`
	// Period is when the meter is expected to call again (its push
	// interval or T3412; default 24 h). A meter silent for twice this is
	// shown as overdue.
	Period Duration `json:"period,omitempty"`
	// EDRXCycle and PagingWindow: with eDRX the meter can be paged once
	// per cycle for the window; requests are then held for the next
	// window rather than failed. 0: no eDRX.
	EDRXCycle    Duration `json:"edrxCycle,omitempty"`
	PagingWindow Duration `json:"pagingWindow,omitempty"`
	// RequestTimeout is each DLMS request's time-out on this network
	// (default 30 s: NB-IoT round trips run to seconds, longer in
	// coverage extension).
	RequestTimeout Duration `json:"requestTimeout,omitempty"`
	// Retries is how many calls a queued command is tried on (default 3).
	Retries int `json:"retries,omitempty"`
	// QueueMax and QueueTTL bound the meter's command queue (default 16
	// commands, 72 h).
	QueueMax int      `json:"queueMax,omitempty"`
	QueueTTL Duration `json:"queueTtl,omitempty"`
}

// Duration is a JSON duration ("20s" or seconds).
type Duration time.Duration

// D is the duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON writes "20s".
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// UnmarshalJSON reads "20s" or a number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' {
		v, err := time.ParseDuration(s[1 : len(s)-1])
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var f float64
	if _, err := fmt.Sscan(s, &f); err != nil {
		return fmt.Errorf("a duration is a string such as \"20s\" or a number of seconds")
	}
	*d = Duration(f * float64(time.Second))
	return nil
}

// Defaults fills in the defaults and checks the values.
func (s *Sleep) Defaults() error {
	if s.ActiveTime == 0 {
		s.ActiveTime = Duration(20 * time.Second)
	}
	if s.Period == 0 {
		s.Period = Duration(24 * time.Hour)
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = Duration(30 * time.Second)
	}
	if s.Retries == 0 {
		s.Retries = 3
	}
	if s.QueueMax == 0 {
		s.QueueMax = 16
	}
	if s.QueueTTL == 0 {
		s.QueueTTL = Duration(72 * time.Hour)
	}
	if s.ActiveTime < 0 || s.Period < 0 || s.EDRXCycle < 0 || s.PagingWindow < 0 || s.RequestTimeout < 0 || s.Retries < 0 || s.QueueMax < 0 || s.QueueTTL < 0 {
		return fmt.Errorf("sleep settings are not negative")
	}
	if s.EDRXCycle > 0 && s.PagingWindow == 0 {
		s.PagingWindow = Duration(2560 * time.Millisecond)
	}
	return nil
}

// WakeState is what we know of one meter's sleep.
type WakeState struct {
	LastWake    time.Time `json:"lastWake,omitempty"`    // first datagram of its last call
	LastSeen    time.Time `json:"lastSeen,omitempty"`    // its last datagram
	ListenUntil time.Time `json:"listenUntil,omitempty"` // when it is expected to sleep again
	NextCall    time.Time `json:"nextCall,omitempty"`    // when it is expected to call again
	Calls       int       `json:"calls"`
	Awake       bool      `json:"awake"`
	Overdue     bool      `json:"overdue"`
}

// Wakes tracks meters' calls.
type Wakes struct {
	mu  sync.Mutex
	m   map[string]*WakeState
	cfg map[string]Sleep
	now func() time.Time
}

// NewWakes makes a tracker; now is the clock (nil: time.Now).
func NewWakes(now func() time.Time) *Wakes {
	if now == nil {
		now = time.Now
	}
	return &Wakes{m: map[string]*WakeState{}, cfg: map[string]Sleep{}, now: now}
}

// Configure sets a meter's sleep settings.
func (w *Wakes) Configure(meter string, s Sleep) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cfg[meter] = s
}

// Heard records a datagram from a meter; newCall is true for the first
// of a call.
func (w *Wakes) Heard(meter string, newCall bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	st := w.m[meter]
	if st == nil {
		st = &WakeState{}
		w.m[meter] = st
	}
	s := w.cfg[meter]
	if newCall || st.LastWake.IsZero() {
		st.LastWake = now
		st.Calls++
		st.NextCall = now.Add(s.Period.D())
	}
	st.LastSeen = now
	st.ListenUntil = now.Add(s.ActiveTime.D())
}

// State is a meter's state now.
func (w *Wakes) State(meter string) WakeState {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.m[meter]
	if st == nil {
		return WakeState{}
	}
	out := *st
	now := w.now()
	out.Awake = now.Before(st.ListenUntil)
	s := w.cfg[meter]
	out.Overdue = s.Period > 0 && now.Sub(st.LastWake) > 2*s.Period.D()
	return out
}

// Listening reports whether the meter can be sent to now, and for how long.
func (w *Wakes) Listening(meter string) (bool, time.Duration) {
	st := w.State(meter)
	if !st.Awake {
		return false, 0
	}
	return true, st.ListenUntil.Sub(w.now())
}

// NextWindow is the start of the meter's next eDRX paging window after
// now, or zero without eDRX: reckoned from its last call, which the
// network aligns cycles to only approximately, so treat it as a hint.
func (w *Wakes) NextWindow(meter string) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, st := w.cfg[meter], w.m[meter]
	if s.EDRXCycle <= 0 || st == nil {
		return time.Time{}
	}
	now := w.now()
	n := now.Sub(st.LastSeen) / s.EDRXCycle.D()
	return st.LastSeen.Add((n + 1) * s.EDRXCycle.D())
}
