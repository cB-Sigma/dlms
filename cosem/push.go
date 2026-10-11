package cosem

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/is15959"
)

// Notification is a decoded data-notification.
type Notification struct {
	InvokeID uint32
	Time     time.Time // zero when the meter sent none
	Body     axdr.DlmsData
	// SystemTitle is the sender's system title when the APDU was
	// protected, IC its invocation counter, and Authenticated whether its
	// authentication tag was verified with the meter's keys.
	SystemTitle   []byte
	IC            uint32
	Authenticated bool
}

// PushSecurityError is a push refused for its protection. Event is a
// stable name for a security log ("dlms_push_unauthenticated_refused",
// "dlms_push_system_title_refused"), Meter the source it was checked
// against (empty when none was) and SystemTitle the sender's, when known.
type PushSecurityError struct {
	Event, Meter string
	SystemTitle  []byte
	Err          error
}

// Error is the refusal's reason.
func (e *PushSecurityError) Error() string { return e.Err.Error() }

// Unwrap returns the reason.
func (e *PushSecurityError) Unwrap() error { return e.Err }

// DecodeDataNotification decodes a plain data-notification APDU:
// long-invoke-id-and-priority (4 bytes), date-time (an octet string, empty
// or 12 bytes; a leading octet-string tag 0x09 is tolerated), then the
// notification body as tagged A-XDR data.
func DecodeDataNotification(apdu []byte, loc *time.Location) (*Notification, error) {
	if len(apdu) < 6 || apdu[0] != 0x0F {
		return nil, errors.New("not a data-notification APDU")
	}
	n := &Notification{InvokeID: binary.BigEndian.Uint32(apdu[1:5])}
	b := apdu[5:]
	if b[0] == 0x09 && len(b) > 1 && b[1] == 12 {
		b = b[1:]
	}
	switch b[0] {
	case 0:
		b = b[1:]
	case 12:
		if len(b) < 13 {
			return nil, errors.New("the data-notification date-time is cut short")
		}
		if t, ok := DateTime(hex.EncodeToString(b[1:13]), loc); ok {
			n.Time = t
		}
		b = b[13:]
	default:
		return nil, fmt.Errorf("the data-notification date-time has length %d, not 0 or 12", b[0])
	}
	if len(b) == 0 {
		return nil, errors.New("the data-notification has no body")
	}
	src := b
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return nil, fmt.Errorf("the data-notification body does not decode: %w", err)
	}
	n.Body = d
	return n, nil
}

// TextOf returns a string or octet string's text (octet strings holding
// printable characters are read as text).
func TextOf(d axdr.DlmsData) string {
	s, ok := d.Value.(string)
	if !ok {
		return ""
	}
	if d.Tag == axdr.TagOctetString {
		b, err := hex.DecodeString(s)
		if err != nil {
			return ""
		}
		for _, c := range b {
			if c < 0x20 || c > 0x7E {
				return ""
			}
		}
		return string(b)
	}
	return s
}

// BitsSet lists the bit numbers set in a bit string (bit 0 first, the
// most significant bit of the first byte), as IS 15959 numbers the event
// status word.
func BitsSet(d axdr.DlmsData) []int {
	var out []int
	switch v := d.Value.(type) {
	case string:
		if d.Tag == axdr.TagBitString {
			for i, c := range v {
				if c == '1' {
					out = append(out, i)
				}
			}
			return out
		}
		b, err := hex.DecodeString(strings.ReplaceAll(v, " ", ""))
		if err != nil {
			return nil
		}
		for i, x := range b {
			for j := range 8 {
				if x&(0x80>>j) != 0 {
					out = append(out, i*8+j)
				}
			}
		}
	}
	return out
}

// PushSource is a meter a protected push may come from: its keys, the
// system title it is configured with (nil: not configured), whether it
// may push encryption-only APDUs, and the time zone of its clock.
type PushSource struct {
	ID                    string
	Security              *Security
	SystemTitle           []byte
	AcceptUnauthenticated bool
	Location              *time.Location
}

// OpenProtectedPush removes general-glo-ciphering from a pushed APDU with
// the keys of the first source it opens with, in the order given, and
// decodes the data-notification inside. named returns the index in
// sources of the meter a notification's device ID element names, or -1.
//
// An encryption-only push (no authentication tag; the IS 15959 Part 2
// push association) proves nothing about its sender, and global keys may
// be shared between meters: it is taken only from a source that accepts
// such pushes, only from that source's configured system title, and only
// when it names no other source. Refusals for the protection are
// *PushSecurityError. The notification's SystemTitle, IC and
// Authenticated are filled in.
func OpenProtectedPush(apdu []byte, sources []PushSource, named func(*Notification) int) (int, *Notification, error) {
	st, content, err := decodeGeneralGloDed(apdu)
	if err != nil {
		return -1, nil, err
	}
	var lastErr error = errors.New("no configured meter has keys for this push")
	for i, src := range sources {
		sec := src.Security
		if sec == nil || sec.Policy == 0 || sec.Key == nil {
			continue
		}
		if want := src.SystemTitle; want != nil && string(want) != string(st) {
			if _, ok := lastErr.(*PushSecurityError); !ok {
				lastErr = &PushSecurityError{Event: "dlms_push_system_title_refused",
					Err: fmt.Errorf("no configured meter has system title %X", st)}
			}
			continue
		}
		plain, ic, err := UnprotectKeys(sec.Suite, sec.Key, sec.BroadcastKey, sec.AuthKey, st, content, nil)
		if err != nil {
			lastErr = err
			continue
		}
		loc := src.Location
		if loc == nil {
			loc = time.UTC
		}
		n, err := DecodeDataNotification(plain, loc)
		if err != nil {
			lastErr = fmt.Errorf("meter %s: the opened push is not a data-notification: %w", src.ID, err)
			continue
		}
		if content[0]&SecAuthentication == 0 {
			// Encryption only: see the function comment.
			if !src.AcceptUnauthenticated {
				lastErr = &PushSecurityError{Event: "dlms_push_unauthenticated_refused", Meter: src.ID, SystemTitle: st,
					Err: fmt.Errorf("meter %s: an encryption-only push is refused (its sender is not authenticated; set acceptUnauthenticatedPush to take such pushes)", src.ID)}
				continue
			}
			if src.SystemTitle == nil || string(src.SystemTitle) != string(st) {
				lastErr = &PushSecurityError{Event: "dlms_push_system_title_refused", Meter: src.ID,
					Err: fmt.Errorf("meter %s: an encryption-only push is taken only from the meter's configured meterSystemTitle (sent from %X)", src.ID, st)}
				continue
			}
			if named != nil {
				if o := named(n); o >= 0 && o != i {
					lastErr = &PushSecurityError{Event: "dlms_push_system_title_refused", Meter: src.ID,
						Err: fmt.Errorf("meter %s: the encryption-only push names device %s", src.ID, sources[o].ID)}
					continue
				}
			}
		}
		n.SystemTitle, n.IC, n.Authenticated = st, ic, content[0]&SecAuthentication != 0
		return i, n, nil
	}
	return -1, nil, lastErr
}

// PushSetupOf finds the push setup of a profile a notification came from:
// the element captured from a class 40 logical name names it; otherwise
// the one push setup whose capture list has as many elements. read, when
// not nil, gives the push_object_list read from the meter for a push
// setup, which then replaces the profile's capture list.
func PushSetupOf(sp *is15959.Spec, items []*axdr.DlmsData, read func(obis string) ([]is15959.Column, bool)) (*is15959.PushSetup, error) {
	withRead := func(ps *is15959.PushSetup) *is15959.PushSetup {
		if read != nil {
			if cols, ok := read(ps.OBIS); ok {
				return &is15959.PushSetup{Name: ps.Name, OBIS: ps.OBIS, Capture: cols, Ref: "push_object_list read from the meter"}
			}
		}
		return ps
	}
	for _, it := range items {
		if it == nil || it.Tag != axdr.TagOctetString {
			continue
		}
		s, _ := it.Value.(string)
		if obis, err := OBISFromHex(s); err == nil {
			if ps := sp.PushSetup(obis); ps != nil {
				return withRead(ps), nil
			}
		}
	}
	var found *is15959.PushSetup
	for i := range sp.Push {
		if len(sp.Push[i].Capture) == len(items) {
			if found != nil {
				return nil, errors.New("the push names no push setup and more than one has as many capture objects")
			}
			found = withRead(&sp.Push[i])
		}
	}
	if found == nil {
		return nil, fmt.Errorf("the push names no push setup of profile %s", sp.ID)
	}
	return found, nil
}

// PushValue is one captured value of a push.
type PushValue struct {
	Name    string
	Class   uint16
	OBIS    string
	Value   any
	Unit    string
	Quality string // "unscaled" when a register's scaler is not known yet
}

// PushReport is a notification mapped by its push setup's capture
// objects. Time is the notification's time, the time of a captured clock,
// or the time it was mapped. Row holds the push setup's logical name
// ("pushSetup"), every value by name and the events ("events"); Values
// are the values in capture order (clock and push setup elements left
// out); LastGasp and FirstBreath say the event status word reported a
// power failure or its end.
type PushReport struct {
	Time        time.Time
	Row         map[string]any
	Values      []PushValue
	Events      []map[string]any
	LastGasp    bool
	FirstBreath bool
}

// MapPush maps a notification by its push setup. Register values are
// scaled with scaler (from an earlier read of the register) and carry its
// unit; without one they are marked "unscaled". Event status word bits are
// named by the profile sp.
func MapPush(n *Notification, setup *is15959.PushSetup, sp *is15959.Spec, loc *time.Location, scaler func(obis string) (Scaler, bool)) *PushReport {
	items, _ := n.Body.Value.([]*axdr.DlmsData)
	at := n.Time
	for i, c := range setup.Capture {
		if i < len(items) && c.Class == ClassClock && items[i] != nil {
			if s, ok := items[i].Value.(string); ok {
				if t, ok := DateTime(s, loc); ok {
					at = t
				}
			}
		}
	}
	if at.IsZero() {
		at = time.Now()
	}
	r := &PushReport{Time: at, Row: map[string]any{"pushSetup": setup.OBIS}}
	for i, c := range setup.Capture {
		if i >= len(items) || items[i] == nil {
			break
		}
		f := *items[i]
		switch {
		case c.Class == 40 && c.Attr == 1, c.Class == ClassClock:
			continue
		case c.OBIS == is15959.EventStatusWord:
			bits := BitsSet(f)
			r.Row[c.Name] = bits
			for _, b := range bits {
				ev := map[string]any{"bit": b}
				if sp != nil {
					if e, ok := sp.ESWBit(b); ok {
						ev["name"] = e.Name
						if k := is15959.ESWKey(e); k != "" {
							ev["key"] = k
						}
						if o, ok := is15959.Info(e.Occurrence); ok && o.Tamper {
							ev["tamper"] = true
						}
						if e.Occurrence != 0 {
							ev["occurrence"] = e.Occurrence
						}
						if e.Restoration != 0 {
							ev["restoration"] = e.Restoration
						}
					}
				}
				r.Events = append(r.Events, ev)
				switch b {
				case is15959.BitLastGasp:
					r.LastGasp = true
				case is15959.BitFirstBreath:
					r.FirstBreath = true
				}
			}
			continue
		}
		v := Readable(f, loc, c.Class == ClassClock)
		unit, quality := "", ""
		if ScaledValue(c.Class, c.Attr) {
			if x, ok := Number(f); ok {
				if s, ok := scaler(c.OBIS); ok {
					v, unit = Scaled(x, s.Exponent), s.Unit
				} else {
					// No scaler_unit read yet (the meter may be without
					// power): the raw value, marked.
					quality = "unscaled"
				}
			}
		}
		r.Row[c.Name] = v
		r.Values = append(r.Values, PushValue{Name: c.Name, Class: c.Class, OBIS: c.OBIS, Value: v, Unit: unit, Quality: quality})
	}
	if len(r.Events) > 0 {
		r.Row["events"] = r.Events
	}
	return r
}
