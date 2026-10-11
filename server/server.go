// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package server is the meter side of DLMS/COSEM: a logical device that
// holds COSEM objects (package classes) and serves them to clients over
// the wrapper (TCP or UDP) and HDLC.
//
// It accepts application associations per client address with no
// security, low-level security or HLS (mechanisms 2 to 7), security
// suites 0 to 2 with authenticated, encrypted or authenticated and
// encrypted APDUs under the global or a dedicated key, in service-specific,
// general-glo or general-ded ciphering. It answers GET, SET and ACTION
// (normal, with list, and in data blocks both ways), the ACCESS service,
// and, with ShortNames, the short name services (read, write, unconfirmed
// write, with data blocks and parameterized access). Long answers go in
// data blocks, or in general block transfer when the client negotiated
// it. Data notifications are pushed to a client address or a push setup's
// destination. The current association object (class 15, or class 12
// with short names) is built from the server's objects and the client's
// rights.
//
// The protection of APDUs is cosem's (Protect, UnprotectKeys and the HLS
// answers), so a client of this module and this server share one
// implementation; dlms-sim's meter, written separately, and Gurux's client
// check both.
package server

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/hdlc"
)

// Op is what a client does to an attribute or method.
type Op byte

// Operations checked by Association.Allow.
const (
	OpRead Op = iota + 1
	OpWrite
	OpExecute
)

// Association is what the server accepts from one client address.
type Association struct {
	// ClientAddress is the client's SAP (wrapper wPort, HDLC client
	// address); 16 is the public client.
	ClientAddress uint16
	// Mechanism is the authentication: 0 none, 1 low-level (Secret is the
	// password), 2 to 7 HLS (Secret is the secret of 2, 3, 4 and 6).
	Mechanism byte
	Secret    []byte
	// Policy protects APDUs after the association: 0 none, or
	// cosem.SecAuthentication and/or cosem.SecEncryption. Suite is the
	// security suite (0, 1 or 2); Key and AuthKey the global unicast and
	// authentication keys; BroadcastKey the global broadcast key.
	Policy       byte
	Suite        byte
	Key, AuthKey []byte
	BroadcastKey []byte
	// SigningKey is the server's key and ClientKey the client's public key
	// (mechanism 7).
	SigningKey *ecdsa.PrivateKey
	ClientKey  *ecdsa.PublicKey
	// Context, when not 0, is the only application context accepted (1 LN,
	// 2 SN, 3 LN with ciphering, 4 SN with ciphering); an AARQ proposing
	// another is refused with diagnostic 2. 0 accepts the server's
	// referencing with or without ciphering.
	Context byte
	// InvocationCounter, when set, is the logical name of a class 1 object
	// holding the client's last invocation counter (readable by the public
	// client): an AARQ whose counter is not above it is refused.
	InvocationCounter string
	// Allow, when set, decides each access (rights of the association);
	// nil allows everything the objects allow.
	Allow func(class uint16, ln string, id int8, op Op) bool
	// Conformance is the services offered to this client (0: the server's).
	Conformance uint32
}

// Server is one logical device. Set the fields, Add objects, then serve.
type Server struct {
	// SystemTitle is the server's, 8 octets (needed with protected APDUs
	// and mechanisms 5 to 7).
	SystemTitle []byte
	// Associations are the clients accepted, by client address; a client
	// address with none is refused.
	Associations []*Association
	// ShortNames serves short name referencing instead of logical names;
	// objects get base names as they are added (AddSN to choose one).
	ShortNames bool
	// MaxPDU is the largest APDU the server receives and sends (default
	// 1024); BlockSize, when set, bounds the data in one block.
	MaxPDU    uint16
	BlockSize int
	// Conformance is the services offered (default: get, set, action,
	// selective access, block transfer in all three, multiple references,
	// ACCESS, data notification and general protection; with ShortNames
	// read, write, unconfirmed write, parameterized access, multiple
	// references and block transfer). GBT adds general block transfer.
	Conformance uint32
	GBT         bool
	// Address is the server's SAP: the wrapper wPort and the HDLC upper
	// address (default 1). HDLCAddress is the lower (physical) address and
	// HDLCAddressSize the size of the server address (1, 2 or 4; default
	// 1); HDLCParams the data link parameters (zero: the defaults).
	Address         uint16
	HDLCAddress     int
	HDLCAddressSize int
	HDLCParams      hdlc.Params
	HDLCInactivity  time.Duration
	// Logf, when set, receives events (refused associations, protocol
	// errors).
	Logf func(format string, args ...any)

	mu      sync.Mutex
	objects map[string]classes.Object
	order   []string
	bases   map[string]uint16 // short names: base name of each object
	byBase  map[uint16]string
	nextSN  uint16
	ic      uint32 // the server's invocation counter
	lns     []net.Listener
	pcs     []net.PacketConn
	conns   map[net.Conn]bool
	sts     []*hdlc.Station
	bcast   uint32 // the highest counter seen under the broadcast key
	stats   Stats
}

// Stats counts what the server did.
type Stats struct {
	Associations int // accepted (after HLS pass 3 when HLS is used)
	Refused      int // AARQs refused and failed HLS passes
	Blocks       int // data blocks sent (GET, ACTION, short name read)
	GBTBlocks    int // general-block-transfer APDUs sent
	// Protected requests opened, by form.
	ServiceSpecific, GeneralGlo, GeneralDed int
}

// Stats returns the counters so far.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Server) count(f func(*Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

func objKey(class uint16, ln string) string { return fmt.Sprintf("%d/%s", class, ln) }

// Add puts objects in the server. An object with the class and logical
// name of one already there replaces it.
func (s *Server) Add(objs ...classes.Object) {
	for _, o := range objs {
		s.add(o, 0)
	}
}

// AddSN puts an object in the server at a chosen base name (short names).
func (s *Server) AddSN(o classes.Object, base uint16) { s.add(o, base) }

func (s *Server) add(o classes.Object, base uint16) {
	s.mu.Lock()
	if s.objects == nil {
		s.objects, s.bases, s.byBase = map[string]classes.Object{}, map[string]uint16{}, map[uint16]string{}
		s.nextSN = 0x0100
	}
	k := objKey(o.ClassID(), o.LogicalName())
	if _, ok := s.objects[k]; !ok {
		s.order = append(s.order, k)
	}
	s.objects[k] = o
	if old, ok := s.bases[k]; ok {
		delete(s.byBase, old)
	}
	if base == 0 {
		base = s.nextSN
		s.nextSN += snStride(o.ClassID())
	}
	s.bases[k], s.byBase[base] = base, k
	s.mu.Unlock()
	if b, ok := o.(classes.Binder); ok {
		b.Bind(s)
	}
}

// snStride is the room an object's short names take: its attributes and
// its methods, eight apart.
func snStride(class uint16) uint16 {
	c, ok := classes.Lookup(class)
	if !ok {
		return 0x100
	}
	n := uint16(len(c.Attributes)) * 8
	if m := c.FirstMethodSN + uint16(len(c.Methods))*8; len(c.Methods) > 0 && m > n {
		n = m
	}
	return (n + 0x1F) &^ 0x0F
}

// Object returns the object of a class and logical name.
func (s *Server) Object(class uint16, ln string) (classes.Object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[objKey(class, ln)]
	return o, ok
}

// Objects lists the server's objects in the order they were added.
func (s *Server) Objects() []classes.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]classes.Object, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.objects[k])
	}
	return out
}

// BaseName is an object's base name (short names).
func (s *Server) BaseName(class uint16, ln string) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bases[objKey(class, ln)]
	return b, ok
}

// Resolve reads an attribute of another object (classes.Resolver).
func (s *Server) Resolve(class uint16, ln string, attr int8) (*axdr.DlmsData, error) {
	o, ok := s.Object(class, ln)
	if !ok {
		return nil, classes.ObjectUndefined
	}
	return o.Get(attr, nil)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) association(client uint16) *Association {
	for _, a := range s.Associations {
		if a.ClientAddress == client {
			return a
		}
	}
	return nil
}

func (s *Server) maxPDU() int {
	if s.MaxPDU == 0 {
		return 1024
	}
	return int(s.MaxPDU)
}

func (s *Server) address() uint16 {
	if s.Address == 0 {
		return 1
	}
	return s.Address
}

// Default conformance blocks.
const (
	lnConformance = 1<<22 | 1<<12 | 1<<11 | 1<<10 | 1<<9 | 1<<7 | 1<<6 | 1<<4 | 1<<3 | 1<<2 | 1<<0
	snConformance = 1<<20 | 1<<19 | 1<<18 | 1<<12 | 1<<11 | 1<<9 | 1<<8 | 1<<5
	gbtBit        = 1 << 21
	accessBit     = 1 << 6
)

func (s *Server) conformance(a *Association) uint32 {
	c := s.Conformance
	if c == 0 {
		c = lnConformance
		if s.ShortNames {
			c = snConformance
		}
	}
	if s.GBT {
		c |= gbtBit
	}
	if a != nil && a.Conformance != 0 {
		c = a.Conformance
	}
	return c
}

func (s *Server) nextIC() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ic++
	return s.ic
}

// Close stops every listener and closes open connections.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, l := range s.lns {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, p := range s.pcs {
		_ = p.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.lns, s.pcs, s.conns = nil, nil, nil
	return first
}

func (s *Server) track(c net.Conn, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[net.Conn]bool{}
	}
	if on {
		s.conns[c] = true
	} else {
		delete(s.conns, c)
	}
}

// check reports settings the server cannot serve.
func (s *Server) check() error {
	seen := map[uint16]bool{}
	for _, a := range s.Associations {
		if seen[a.ClientAddress] {
			return fmt.Errorf("client address %d has two associations", a.ClientAddress)
		}
		seen[a.ClientAddress] = true
		if a.Mechanism > 7 {
			return fmt.Errorf("client %d: mechanism %d is not 0 to 7", a.ClientAddress, a.Mechanism)
		}
		if a.Suite > 2 {
			return fmt.Errorf("client %d: security suite %d is not 0, 1 or 2", a.ClientAddress, a.Suite)
		}
		if (a.Policy != 0 || a.Mechanism >= 5) && len(s.SystemTitle) != 8 {
			return fmt.Errorf("client %d: protected APDUs and mechanisms 5 to 7 need the server's 8-octet system title", a.ClientAddress)
		}
		n := 16
		if a.Suite == 2 {
			n = 32
		}
		if (a.Policy != 0 || a.Mechanism == 5) && (len(a.Key) != n || len(a.AuthKey) != n) {
			return fmt.Errorf("client %d: suite %d needs %d-octet keys", a.ClientAddress, a.Suite, n)
		}
		if a.Mechanism == 7 && (a.SigningKey == nil || a.ClientKey == nil || a.Suite == 0) {
			return fmt.Errorf("client %d: mechanism 7 needs suite 1 or 2, the server's signing key and the client's public key", a.ClientAddress)
		}
		if a.Mechanism == 2 && len(a.Secret) != 16 && len(a.Secret) != 24 && len(a.Secret) != 32 {
			return fmt.Errorf("client %d: the mechanism 2 secret must be an AES key (16, 24 or 32 octets)", a.ClientAddress)
		}
	}
	if len(s.Associations) == 0 {
		return errors.New("the server accepts no client: add Associations")
	}
	return nil
}

// sortedKeys lists the object keys in order (for the object list).
func (s *Server) sortedKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.order...)
	if s.ShortNames {
		sort.SliceStable(out, func(i, j int) bool { return s.bases[out[i]] < s.bases[out[j]] })
	}
	return out
}
