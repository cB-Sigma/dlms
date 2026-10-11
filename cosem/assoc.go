package cosem

// Opening an application association (IEC 62056-5-3:2023 7.2.4; the AARQ
// and AARE) with a meter over supporting layers the caller opened: low-
// level or high-level security authentication, APDU protection, and the
// checks done before an association is used.

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
	"gitlab.com/circutor-library/gosem/pkg/dlmsclient"

	"github.com/cB-Sigma/iotsec"
)

// AssociationConfig is what Associate needs.
type AssociationConfig struct {
	// Transport is the supporting layers for the client address (a
	// wrapper, HDLC or gateway transport); Associate owns it from now on.
	Transport gdlms.Transport
	// Mechanism is the authentication mechanism (MechNone to MechECDSA).
	// Password is the low-level password (MechLow).
	Mechanism byte
	Password  []byte
	// HLS holds the mechanism's secret and keys (mechanisms 2 to 7) and
	// the APDU protection (Security) of the association.
	HLS *HLS
	// FirstIC is the invocation counter the association starts at (see
	// ICReservation and ReadInvocationCounter).
	FirstIC uint32
	// ExpectSystemTitle, when set, is the meter's system title: an AARE
	// naming another is refused.
	ExpectSystemTitle []byte
	// Timeout bounds each request (default 10s).
	Timeout time.Duration
	// Writes, when set, counts the set and action requests sent.
	Writes *atomic.Int64
	// Alive, when set, says whether the link is still up when a request
	// is sent (a request sent on a link known closed never arrived).
	Alive func() bool
	// Check, when set, runs on the open association before it is
	// returned (an identity check, say); an error releases it.
	Check func(gdlms.Client) error
	// Policy, when set, is asked whether the mechanism's algorithm may be
	// used (Use names the use) before anything is sent.
	Policy iotsec.CryptoPolicy
	Use    string
	// Name names the meter and Where its address in errors.
	Name, Where string
	// Conformance, when not 0, is the conformance block proposed instead
	// of the default (Conformance* bits).
	Conformance uint32
}

// Association is an open application association: gosem's client over
// our secure transport.
type Association struct {
	Client gdlms.Client
	Secure *SecureTransport
	Raw    *RawSetTransport
	// Link is the supporting layers under the secure transport.
	Link gdlms.Transport

	timeout time.Duration
	invoke  uint32 // the last ACCESS invoke ID
	// shortNames: the association uses short name referencing (sn.go);
	// names maps logical names to base names once the object list is read.
	shortNames bool
	names      map[string]snObject
	writes     *atomic.Int64
}

// Exchange sends one APDU on the association and returns the meter's
// answer, with the association's protection applied both ways (the
// services gosem does not offer: ACCESS, short name referencing).
func (a *Association) Exchange(apdu []byte) ([]byte, error) {
	to := a.timeout
	if to <= 0 {
		to = exchangeTimeout
	}
	if a.writes != nil && isWrite(apdu) {
		a.writes.Add(1)
	}
	return a.Secure.Exchange(apdu, to)
}

// isWrite reports a request that changes the meter: an ACCESS request with
// a set or action, or a short name write.
func isWrite(apdu []byte) bool {
	if len(apdu) == 0 {
		return false
	}
	switch apdu[0] {
	case 0x06, 0x16:
		return true
	case TagAccessRequest:
		req, err := DecodeAccessRequest(apdu)
		if err != nil {
			return true
		}
		for _, it := range req.Items {
			if it.Kind != AccessGet && it.Kind != AccessGetWithSelection {
				return true
			}
		}
	}
	return false
}

// Associate opens an association. On failure the returned association,
// when not nil, still tells the invocation counters used (Secure.usedIC)
// so the next attempt never repeats one.
func Associate(cfg AssociationConfig) (*Association, error) {
	h := cfg.HLS
	if h == nil {
		h = &HLS{Mechanism: cfg.Mechanism}
	}
	to := cfg.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	if cfg.Policy != nil {
		if alg, ok := MechanismAlgorithm(cfg.Mechanism); ok {
			if err := cfg.Policy.Allow(context.Background(), cfg.Use, alg); err != nil {
				cfg.Transport.Close()
				return nil, err
			}
		}
	}
	set, err := gdlms.NewSettingsWithoutAuthentication()
	if err != nil {
		cfg.Transport.Close()
		return nil, err
	}
	// The services we propose (the conformance block): gosem's set plus
	// ACCESS for logical names; the short name services for short names.
	set.ConformanceBlock |= int(ConformanceAccess)
	if h.Security.ShortNames {
		set.ConformanceBlock = int(snConformance)
	}
	if cfg.Conformance != 0 {
		set.ConformanceBlock = int(cfg.Conformance)
	}
	var ctos []byte
	switch {
	case cfg.Mechanism == MechLow:
		set.Authentication, set.Password = gdlms.AuthenticationLow, cfg.Password
	case cfg.Mechanism >= MechHLS:
		if ctos, err = newChallenge(); err != nil {
			cfg.Transport.Close()
			return nil, err
		}
		if cfg.Mechanism == MechHLS {
			// Mechanism 2 is manufacturer-specific: we encrypt with AES in
			// ECB mode, others (Gurux) in CBC mode with a zero IV. The two
			// agree on one block, so the challenge is one block long.
			ctos = ctos[:16]
		}
		set.Authentication, set.Password = gdlms.Authentication(cfg.Mechanism), ctos
	}
	// The calling AP title (our system title) is sent when APDUs are
	// protected or the mechanism uses system titles; gosem then names the
	// ciphering application context, and the secure transport does the
	// rest.
	if h.Security.Policy != 0 || cfg.Mechanism >= MechGMAC {
		set.Ciphering.SystemTitle = h.Security.SystemTitle
	}
	st := newSecureTransport(cfg.Transport, h.Security, cfg.FirstIC)
	st.expectST = cfg.ExpectSystemTitle
	raw := &RawSetTransport{Transport: st, writes: cfg.Writes, alive: cfg.Alive}
	c := dlmsclient.New(set, raw, to, 0)
	if err := c.Connect(); err != nil {
		st.Close()
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Where, err)
	}
	a := &Association{Client: c, Secure: st, Raw: raw, Link: cfg.Transport, timeout: to, writes: cfg.Writes,
		shortNames: h.Security.ShortNames}
	if err := c.Associate(); err != nil {
		_ = c.Disconnect()
		st.Close()
		if f := st.LastFailure(); f != nil {
			err = f
		}
		return a, fmt.Errorf("association with meter %s refused: %w", cfg.Name, err)
	}
	if cfg.Mechanism >= MechHLS {
		complete := func() error { return completeHLS(c, st, h, ctos) }
		if a.shortNames {
			complete = func() error { return completeHLSSN(a, h, ctos) }
		}
		if err := complete(); err != nil {
			_ = c.Disconnect()
			st.Close()
			return a, fmt.Errorf("high-level security with meter %s failed: %w", cfg.Name, err)
		}
	}
	if cfg.Check != nil {
		if err := cfg.Check(c); err != nil {
			_ = c.CloseAssociation()
			_ = c.Disconnect()
			st.Close()
			return a, fmt.Errorf("meter %s: %w", cfg.Name, err)
		}
	}
	return a, nil
}

// ReadInvocationCounter reads the frame counter a meter keeps for a
// client (class 1 value attribute at obis) through a public association
// on tr, which it closes. name and where name the meter in errors.
func ReadInvocationCounter(tr gdlms.Transport, obis string, timeout time.Duration, name, where string) (uint32, error) {
	set, err := gdlms.NewSettingsWithoutAuthentication()
	if err != nil {
		tr.Close()
		return 0, err
	}
	c := dlmsclient.New(set, tr, timeout, 0)
	if err := c.Connect(); err != nil {
		tr.Close()
		return 0, fmt.Errorf("connecting to %s to read the invocation counter: %w", where, err)
	}
	defer func() {
		_ = c.CloseAssociation()
		_ = c.Disconnect()
		tr.Close()
	}()
	if err := c.Associate(); err != nil {
		return 0, fmt.Errorf("public association with meter %s for the invocation counter refused: %w", name, err)
	}
	var v uint32
	if err := c.GetRequest(gdlms.CreateAttributeDescriptor(1, obis, 2), &v); err != nil {
		return 0, fmt.Errorf("reading invocation counter %s from meter %s: %w", obis, name, err)
	}
	return v, nil
}
