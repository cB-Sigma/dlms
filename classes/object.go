// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package classes is the COSEM object model: the interface classes of IEC
// 62056-6-2 (the DLMS UA Blue Book) as data (class, version, attributes,
// methods, short name offsets) and as Go types a server holds and a client
// reads into. Class, attribute and method numbers are facts of the
// standard; the names and descriptions are our own wording.
//
// A server (package server) serves any Object; the typed objects here
// (Register, Clock, ProfileGeneric, ...) keep their attributes as Go
// values and encode them on GET, decode them on SET and run their methods
// on ACTION. Generic holds the attributes of a class this package has no
// type for.
package classes

import (
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Object is one COSEM object (an instance of an interface class).
type Object interface {
	// ClassID and Version name the interface class; LogicalName is the
	// object's OBIS code as "a.b.c.d.e.f".
	ClassID() uint16
	Version() uint8
	LogicalName() string
	// Get returns attribute attr; sel, when not nil, is the selective
	// access the client asked for. Errors are Result values (other errors
	// are answered as other-reason).
	Get(attr int8, sel *Selector) (*axdr.DlmsData, error)
	// Set writes attribute attr.
	Set(attr int8, v *axdr.DlmsData, sel *Selector) error
	// Action runs method m with its parameter (nil: none) and returns the
	// method's return parameter (nil: none).
	Action(m int8, param *axdr.DlmsData) (*axdr.DlmsData, error)
}

// Selector is a selective access descriptor: the access selector and its
// parameters.
type Selector struct {
	ID         uint8
	Parameters *axdr.DlmsData
}

// Result is a data access result or action result (the two share their
// codes): an error an Object returns to have the server answer with that
// code.
type Result uint8

// Results.
const (
	Success            Result = 0
	HardwareFault      Result = 1
	TemporaryFailure   Result = 2
	ReadWriteDenied    Result = 3
	ObjectUndefined    Result = 4
	ClassInconsistent  Result = 9
	ObjectUnavailable  Result = 11
	TypeUnmatched      Result = 12
	ScopeViolated      Result = 13
	BlockUnavailable   Result = 14
	LongAborted        Result = 15
	NoLongInProgress   Result = 16
	LongSetAborted     Result = 17
	NoLongSetProgress  Result = 18
	BlockNumberInvalid Result = 19
	OtherReason        Result = 250
)

var resultNames = map[Result]string{
	Success: "success", HardwareFault: "hardware fault", TemporaryFailure: "temporary failure",
	ReadWriteDenied: "read-write denied", ObjectUndefined: "object undefined",
	ClassInconsistent: "object class inconsistent", ObjectUnavailable: "object unavailable",
	TypeUnmatched: "type unmatched", ScopeViolated: "scope of access violated",
	BlockUnavailable: "data block unavailable", LongAborted: "long get or action aborted",
	NoLongInProgress: "no long get or action in progress", LongSetAborted: "long set aborted",
	NoLongSetProgress: "no long set in progress", BlockNumberInvalid: "data block number invalid",
	OtherReason: "other reason",
}

func (r Result) Error() string {
	if s, ok := resultNames[r]; ok {
		return s
	}
	return fmt.Sprintf("result %d", uint8(r))
}

// ResultOf is the result code an error from an Object stands for.
func ResultOf(err error) Result {
	if err == nil {
		return Success
	}
	if r, ok := err.(Result); ok {
		return r
	}
	return OtherReason
}

// Resolver reads attributes of other objects of the same server (a
// profile capturing registers, a register monitor watching a value).
type Resolver interface {
	Resolve(class uint16, ln string, attr int8) (*axdr.DlmsData, error)
}

// Binder is an Object that needs the other objects of its server; the
// server calls Bind when the object is added.
type Binder interface {
	Bind(r Resolver)
}
