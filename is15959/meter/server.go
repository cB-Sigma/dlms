// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meter

import (
	"errors"
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/server"
)

// Meter is an IS 15959 meter on package server: serve it with the
// server's Listen and Serve methods.
type Meter struct {
	*server.Server
	Spec    *is15959.Spec
	Options Options // with the defaults filled in
	// Associations are what each client of the profile is held to.
	Associations []Association
}

// New builds a meter for a profile: the server holds every object (the
// clock, profiles and event logs, disconnect control and image transfer
// as typed objects of package classes; the others as classes.Generic with
// every attribute the profile names, writable where the profile lets an
// association write it), an association per client of the profile with
// its access rights, and the system title. Disconnect control logs its
// connection and disconnection events (codes 301 and 302 where the
// profile has them); the billing script captures the billing profile.
func New(spec *is15959.Spec, o Options) (*Meter, error) {
	if spec == nil {
		return nil, errors.New("is15959 meter: no profile")
	}
	o = o.Defaults()
	mem := &Memory{}
	Populate(mem, spec, o)
	s := &server.Server{SystemTitle: append([]byte(nil), o.SystemTitle...)}
	m := &Meter{Server: s, Spec: spec, Options: o, Associations: Associations(spec, o)}
	loc := o.Location
	generic := map[string]*classes.Generic{}
	var order []string
	for _, a := range mem.Attrs() {
		if a.Class == is15959.ClassClock && a.OBIS == is15959.ClockOBIS && a.Attr == 2 {
			continue
		}
		gk := fmt.Sprintf("%d/%s", a.Class, a.OBIS)
		g := generic[gk]
		if g == nil {
			g = &classes.Generic{Class: a.Class, LN: a.OBIS, Attrs: map[int8]*axdr.DlmsData{}, Writable: map[int8]bool{}}
			generic[gk] = g
			order = append(order, gk)
		}
		v := a.Value
		g.Attrs[a.Attr] = &v
		g.Writable[a.Attr] = writable(spec, a.Class, a.OBIS, a.Attr)
	}
	profiles := map[string]bool{}
	for _, obis := range mem.Profiles() {
		profiles[obis] = true
	}
	itOBIS := ImageTransferOBIS(spec)
	for _, gk := range order {
		g := generic[gk]
		switch {
		case g.Class == is15959.ClassClock && g.LN == is15959.ClockOBIS:
			s.Add(&classes.Clock{LN: g.LN, Location: loc})
		case g.Class == is15959.ClassDisconnect && g.LN == is15959.DisconnectControl:
			d := &classes.DisconnectControl{LN: g.LN, OutputState: true, ControlState: 1, ControlMode: 4}
			d.OnChange = func(on bool) error {
				code := 301
				if on {
					code = 302
				}
				m.RaiseEvent(code, time.Now())
				return nil
			}
			s.Add(d)
		case g.Class == is15959.ClassImageTransfer && g.LN == itOBIS:
			s.Add(&classes.ImageTransfer{LN: g.LN, BlockSize: 64, Enabled: true})
		case g.Class == is15959.ClassProfileGeneric && profiles[g.LN]:
			// Added below with its buffer.
		case g.Class == is15959.ClassScriptTable:
			s.Add(m.scriptTable(g))
		default:
			s.Add(g)
		}
	}
	if _, ok := generic[fmt.Sprintf("%d/%s", is15959.ClassClock, is15959.ClockOBIS)]; !ok {
		s.Add(&classes.Clock{LN: is15959.ClockOBIS, Location: loc})
	}
	for _, obis := range mem.Profiles() {
		cols, rows, _ := mem.Rows(obis)
		pg := &classes.ProfileGeneric{LN: obis, Location: loc}
		for _, c := range cols {
			attr := c.Attr
			if attr == 0 {
				attr = 2
			}
			pg.CaptureObjects = append(pg.CaptureObjects, classes.CaptureObject{Class: c.Class, LN: c.OBIS, Attr: attr})
		}
		for _, r := range rows {
			pg.Buffer = append(pg.Buffer, append([]*axdr.DlmsData(nil), r...))
		}
		if v, ok := mem.Value(7, obis, 4); ok {
			if n, ok := v.Value.(uint32); ok {
				pg.CapturePeriod = n
			}
		}
		s.Add(pg)
	}
	for _, a := range m.Associations {
		if a.Role == is15959.Push {
			continue
		}
		sa := &server.Association{ClientAddress: a.Client, Mechanism: a.Mechanism, Secret: a.Secret, Policy: a.Policy,
			Key: a.Key, AuthKey: a.AuthKey, MasterKey: a.MasterKey}
		if a.Policy == 0 {
			sa.Key, sa.AuthKey, sa.MasterKey = nil, nil, nil
		}
		role := a.Role
		sa.Allow = func(class uint16, ln string, id int8, op server.Op) bool {
			want := map[server.Op]is15959.Right{server.OpRead: is15959.Read, server.OpWrite: is15959.Write, server.OpExecute: is15959.Exec}[op]
			rights, listed := spec.Access(class, ln, id, op == server.OpExecute)
			return !listed || rights.Of(role)&want != 0
		}
		s.Associations = append(s.Associations, sa)
	}
	if len(s.Associations) == 0 {
		return nil, errors.New("is15959 meter: the profile has no association to serve")
	}
	return m, nil
}

// writable says whether any association may write an attribute.
func writable(spec *is15959.Spec, class uint16, obis string, attr int8) bool {
	rights, listed := spec.Access(class, obis, attr, false)
	if !listed {
		return true
	}
	for r := is15959.PC; r <= is15959.IHD; r++ {
		if rights.Of(r)&is15959.Write != 0 {
			return true
		}
	}
	return false
}

// scriptTable is a script table whose execute (method 1) runs the
// profile's billing reset: the billing profile captures an entry and the
// billing count goes up.
func (m *Meter) scriptTable(g *classes.Generic) classes.Object {
	billing := false
	for _, mt := range m.Spec.Methods {
		if mt.OBIS == g.LN && mt.Class == is15959.ClassScriptTable && mt.Name == "billing-reset" {
			billing = true
		}
	}
	g.Methods = map[int8]func(*axdr.DlmsData) (*axdr.DlmsData, error){
		1: func(*axdr.DlmsData) (*axdr.DlmsData, error) {
			if billing {
				m.BillingReset(time.Now())
			}
			return nil, nil
		},
	}
	return g
}

// BillingReset captures an entry of the billing profile and counts it.
func (m *Meter) BillingReset(at time.Time) {
	st := &serverStore{m.Server}
	if cols, rows, ok := st.Rows("1.0.98.1.0.255"); ok {
		st.SetRows("1.0.98.1.0.255", cols, append(rows, Row(st, cols, at, len(rows), m.Options.Location)))
	}
	if v, ok := st.Value(1, "0.0.0.1.0.255", 2); ok {
		if n, ok := v.Value.(uint32); ok {
			st.SetValue(1, "0.0.0.1.0.255", 2, axdr.CreateAxdrDoubleLongUnsigned(n+1))
		}
	}
}

// RaiseEvent logs an event (see the package function).
func (m *Meter) RaiseEvent(code int, at time.Time) bool {
	return RaiseEvent(&serverStore{m.Server}, m.Spec, code, at, m.Options.Location)
}

// Recapture rebuilds the periodic and scaler profiles from the present
// register values (see the package function).
func (m *Meter) Recapture(now time.Time) {
	Recapture(&serverStore{m.Server}, m.Spec, m.Options.Rows, now, m.Options.Location)
}

// serverStore is a Store over a server's objects.
type serverStore struct{ s *server.Server }

func (st *serverStore) Value(class uint16, obis string, attr int8) (axdr.DlmsData, bool) {
	o, ok := st.s.Object(class, obis)
	if !ok {
		return axdr.DlmsData{}, false
	}
	if g, ok := o.(*classes.Generic); ok {
		g.Lock()
		defer g.Unlock()
		v, ok := g.Attrs[attr]
		if !ok || v == nil {
			return axdr.DlmsData{}, false
		}
		return *v, true
	}
	v, err := o.Get(attr, nil)
	if err != nil || v == nil {
		return axdr.DlmsData{}, false
	}
	return *v, true
}

func (st *serverStore) SetValue(class uint16, obis string, attr int8, v *axdr.DlmsData) {
	o, ok := st.s.Object(class, obis)
	if !ok {
		g := &classes.Generic{Class: class, LN: obis, Attrs: map[int8]*axdr.DlmsData{attr: v}, Writable: map[int8]bool{}}
		st.s.Add(g)
		return
	}
	if g, ok := o.(*classes.Generic); ok {
		g.Lock()
		g.Attrs[attr] = v
		g.Unlock()
		return
	}
	_ = o.Set(attr, v, nil)
}

func (st *serverStore) Rows(obis string) ([]is15959.Column, [][]*axdr.DlmsData, bool) {
	o, ok := st.s.Object(7, obis)
	if !ok {
		return nil, nil, false
	}
	pg, ok := o.(*classes.ProfileGeneric)
	if !ok {
		return nil, nil, false
	}
	pg.Lock()
	defer pg.Unlock()
	var cols []is15959.Column
	for _, c := range pg.CaptureObjects {
		cols = append(cols, is15959.Column{Class: c.Class, OBIS: c.LN, Attr: c.Attr})
	}
	return cols, append([][]*axdr.DlmsData(nil), pg.Buffer...), true
}

func (st *serverStore) SetRows(obis string, cols []is15959.Column, rows [][]*axdr.DlmsData) {
	o, ok := st.s.Object(7, obis)
	if !ok {
		return
	}
	if pg, ok := o.(*classes.ProfileGeneric); ok {
		pg.Lock()
		pg.Buffer = rows
		pg.Unlock()
	}
}
