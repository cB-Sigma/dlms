// Package is15959 is the object catalogue of the Indian DLMS/COSEM
// companion standards, as data: IS 15959 Part 1:2011 (meter categories),
// Part 2:2016 with Amendments 1 and 2 (2017) for single- and three-phase
// whole-current smart meters, and Part 3:2017 for CT and CT/PT operated
// smart meters. Each profile (a Spec) lists the objects the standard
// requires with their OBIS code, interface class, attribute, value type,
// unit and access rights per association, the profile generic objects with
// their capture objects and periods, the event logs with their event
// codes, the push setups and the methods commands use. Clause and table
// references are to the standard; the wording is ours.
//
// The package has no dependencies, so that a head end (SigmaM2M's DLMS
// adapter) and the meter simulator (package sim) can share it.
package is15959

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Role is an association (client) a standard defines.
type Role uint8

// Roles, in the order of IS 15959 Part 2 table 2.
const (
	PC   Role = iota // public client
	MR               // meter reader
	US               // utility settings
	Push             // push (pre-established)
	FW               // firmware upgrade
	IHD              // in-home display
	numRoles
)

var roleNames = [numRoles]string{"PC", "MR", "US", "PUSH", "FW", "IHD"}

// String is the role's short name (PC, MR, US, PUSH, FW, IHD).
func (r Role) String() string {
	if r < numRoles {
		return roleNames[r]
	}
	return fmt.Sprintf("role-%d", r)
}

// RoleNamed returns the role for a settings name.
func RoleNamed(s string) (Role, bool) {
	switch strings.ToLower(strings.ReplaceAll(s, "_", "-")) {
	case "pc", "public", "public-client":
		return PC, true
	case "mr", "reader", "meter-reader":
		return MR, true
	case "us", "utility", "utility-settings", "utility-setting":
		return US, true
	case "push":
		return Push, true
	case "fw", "firmware", "firmware-upgrade":
		return FW, true
	case "ihd", "in-home-display":
		return IHD, true
	}
	return 0, false
}

// Right is what one association may do with an attribute or method.
type Right uint8

// Rights bits.
const (
	None  Right = 0
	Read  Right = 1
	Write Right = 2
	Exec  Right = 4 // method invocation
	RW          = Read | Write
)

// String writes the right as R, W, X or a combination, or - for none.
func (r Right) String() string {
	var s string
	if r&Read != 0 {
		s += "R"
	}
	if r&Write != 0 {
		s += "W"
	}
	if r&Exec != 0 {
		s += "X"
	}
	if s == "" {
		return "-"
	}
	return s
}

// Rights holds one Right per role.
type Rights [numRoles]Right

// Of returns a role's right.
func (a Rights) Of(r Role) Right {
	if r >= numRoles {
		return None
	}
	return a[r]
}

// String lists the rights by role, as A reads them.
func (a Rights) String() string {
	var parts []string
	for r := Role(0); r < numRoles; r++ {
		if a[r] != None {
			parts = append(parts, r.String()+":"+a[r].String())
		}
	}
	return strings.Join(parts, " ")
}

// A parses compact access text such as "PC:R MR:R US:RW PUSH:R" (roles
// not named have no access). It panics on bad text: it is used for
// package data only, which a test checks.
func A(s string) Rights {
	var out Rights
	for _, f := range strings.Fields(s) {
		role, rights, ok := strings.Cut(f, ":")
		if !ok {
			panic("is15959: access item without a colon: " + f)
		}
		var r Role = numRoles
		for i, n := range roleNames {
			if n == role {
				r = Role(i)
			}
		}
		if r == numRoles {
			panic("is15959: unknown role " + role)
		}
		for _, c := range rights {
			switch c {
			case 'R':
				out[r] |= Read
			case 'W':
				out[r] |= Write
			case 'X':
				out[r] |= Exec
			case '-':
			default:
				panic("is15959: unknown right " + string(c))
			}
		}
	}
	return out
}

// Object groups.
const (
	GroupNameplate     = "nameplate"
	GroupInstantaneous = "instantaneous"
	GroupEnergy        = "energy"
	GroupBlockLoad     = "blockload"
	GroupDailyLoad     = "dailyload"
	GroupBilling       = "billing"
	GroupEvents        = "events"
	GroupProgrammable  = "programmable"
	GroupScalers       = "scalers"
	GroupPush          = "push"
	GroupSecurity      = "security"
	GroupCommunication = "communication"
)

// Groups is every group name.
var Groups = []string{GroupNameplate, GroupInstantaneous, GroupEnergy, GroupBlockLoad, GroupDailyLoad,
	GroupBilling, GroupEvents, GroupProgrammable, GroupScalers, GroupPush, GroupSecurity, GroupCommunication}

// Interface classes.
const (
	ClassData             = 1
	ClassRegister         = 3
	ClassExtendedRegister = 4
	ClassDemandRegister   = 5
	ClassProfileGeneric   = 7
	ClassClock            = 8
	ClassScriptTable      = 9
	ClassSpecialDays      = 11
	ClassAssociationLN    = 15
	ClassImageTransfer    = 18
	ClassActivityCalendar = 20
	ClassRegisterMonitor  = 21
	ClassSingleAction     = 22
	ClassHDLCSetup        = 23
	ClassPushSetup        = 40
	ClassTCPUDPSetup      = 41
	ClassIPv4Setup        = 42
	ClassIPv6Setup        = 48
	ClassSecuritySetup    = 64
	ClassDisconnect       = 70
	ClassLimiter          = 71
)

// Object is one COSEM attribute a profile requires.
type Object struct {
	Name   string // point name; filled from Names when empty
	OBIS   string
	Class  uint16
	Attr   int8   // attribute read or written (2 when zero)
	Type   string // A-XDR type of the value, e.g. "long-unsigned"
	Unit   string // unit of the scaled value when the standard fixes one
	Group  string
	Access Rights
	Ref    string // clause or table
}

// Column is one capture object of a profile generic or push setup.
type Column struct {
	Name  string // filled from Names when empty
	OBIS  string
	Class uint16
	Attr  int8 // 2 when zero
}

// Profile is a profile generic object (class 7).
type Profile struct {
	Name    string
	OBIS    string
	Group   string
	Period  time.Duration // capture period; 0 for asynchronous or triggered capture
	Entries int           // entries the standard asks for (0: not stated)
	Capture []Column
	Scaler  string // OBIS of the profile's scaler profile, if any
	Access  Rights
	Ref     string
}

// Event is one event code.
type Event struct {
	Code int
	Name string
}

// EventLog is an event log profile with its event code object and codes.
type EventLog struct {
	Profile
	CodeOBIS string // the event code object (class 1) of this log
	Codes    []Event
}

// ESWBit is one bit of the event status word pushed by the event push.
type ESWBit struct {
	Bit         int
	Name        string
	Occurrence  int // event code of the occurrence (0: none)
	Restoration int // event code of the restoration (0: none)
}

// PushSetup is a push setup object (class 40) and what it pushes.
type PushSetup struct {
	Name    string
	OBIS    string
	Capture []Column
	Ref     string
}

// Association is one client association.
type Association struct {
	Role     Role
	Client   uint16 // client SAP
	OBIS     string // association LN object
	Auth     string // "none", "low" or an HLS mechanism name ("hls-gmac")
	Security string // APDU protection: none, authenticated, encrypted, authenticated-encrypted
	Setup    string // security setup object (class 64), "" without
	Ref      string
}

// Method is a command the standard provides: a method invocation, or an
// attribute write when Method is zero.
type Method struct {
	Name   string
	OBIS   string
	Class  uint16
	Method int8 // method id (0: a write of Attr)
	Attr   int8
	Type   string // parameter or value type
	Access Rights
	Ref    string
}

// Spec is one selectable profile.
type Spec struct {
	ID       string // settings value, e.g. "part2-3ph"
	Title    string
	Part     int
	Category string
	Phases   int
	Ref      string

	Associations []Association
	Suite        int // security suite (0: AES-GCM-128, AES-128 key wrap)
	Ciphering    string

	Objects  []Object
	Profiles []Profile
	Events   []EventLog
	ESW      []ESWBit
	Push     []PushSetup
	Methods  []Method
}

// Well-known objects.
const (
	ClockOBIS         = "0.0.1.0.0.255"
	DisconnectControl = "0.0.96.3.10.255"
	EventStatusWord   = "0.0.94.91.18.255"
)

var specs = map[string]*Spec{}

func register(s *Spec) {
	if specs[s.ID] != nil {
		panic("is15959: profile registered twice: " + s.ID)
	}
	s.fill()
	specs[s.ID] = s
}

// fill names objects and columns and defaults attributes.
func (s *Spec) fill() {
	name := func(n *string, obis string, class uint16, attr int8) {
		if *n == "" {
			*n = NameOf(obis, class, attr)
		}
	}
	for i := range s.Objects {
		o := &s.Objects[i]
		if o.Attr == 0 {
			o.Attr = 2
		}
		name(&o.Name, o.OBIS, o.Class, o.Attr)
	}
	cols := func(cs []Column) {
		for i := range cs {
			if cs[i].Attr == 0 {
				cs[i].Attr = 2
			}
			name(&cs[i].Name, cs[i].OBIS, cs[i].Class, cs[i].Attr)
		}
	}
	for i := range s.Profiles {
		cols(s.Profiles[i].Capture)
		name(&s.Profiles[i].Name, s.Profiles[i].OBIS, ClassProfileGeneric, 2)
	}
	for i := range s.Events {
		cols(s.Events[i].Capture)
		name(&s.Events[i].Name, s.Events[i].OBIS, ClassProfileGeneric, 2)
	}
	for i := range s.Push {
		cols(s.Push[i].Capture)
	}
}

// Get returns a profile by its settings ID.
func Get(id string) (*Spec, bool) {
	s, ok := specs[id]
	return s, ok
}

// IDs lists the profile IDs.
func IDs() []string {
	out := make([]string, 0, len(specs))
	for id := range specs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Association returns the association of a role.
func (s *Spec) Association(r Role) (Association, bool) {
	for _, a := range s.Associations {
		if a.Role == r {
			return a, true
		}
	}
	return Association{}, false
}

// RoleOf returns the role of a client SAP.
func (s *Spec) RoleOf(client uint16) (Role, bool) {
	for _, a := range s.Associations {
		if a.Client == client {
			return a.Role, true
		}
	}
	return 0, false
}

// Object returns the object with an OBIS code and attribute.
func (s *Spec) Object(obis string, attr int8) *Object {
	for i := range s.Objects {
		if s.Objects[i].OBIS == obis && s.Objects[i].Attr == attr {
			return &s.Objects[i]
		}
	}
	return nil
}

// Profile returns the profile generic object (profiles and event logs)
// with an OBIS code.
func (s *Spec) Profile(obis string) *Profile {
	for i := range s.Profiles {
		if s.Profiles[i].OBIS == obis {
			return &s.Profiles[i]
		}
	}
	for i := range s.Events {
		if s.Events[i].OBIS == obis {
			return &s.Events[i].Profile
		}
	}
	return nil
}

// EventLog returns the event log with an OBIS code.
func (s *Spec) EventLog(obis string) *EventLog {
	for i := range s.Events {
		if s.Events[i].OBIS == obis {
			return &s.Events[i]
		}
	}
	return nil
}

// EventName names an event code of any of the profile's logs.
func (s *Spec) EventName(code int) (string, bool) {
	for _, l := range s.Events {
		for _, e := range l.Codes {
			if e.Code == code {
				return e.Name, true
			}
		}
	}
	return "", false
}

// ESWBit returns an event status word bit.
func (s *Spec) ESWBit(bit int) (ESWBit, bool) {
	for _, b := range s.ESW {
		if b.Bit == bit {
			return b, true
		}
	}
	return ESWBit{}, false
}

// PushSetup returns the push setup with an OBIS code.
func (s *Spec) PushSetup(obis string) *PushSetup {
	for i := range s.Push {
		if s.Push[i].OBIS == obis {
			return &s.Push[i]
		}
	}
	return nil
}

// Method returns a command by name.
func (s *Spec) Method(name string) *Method {
	for i := range s.Methods {
		if s.Methods[i].Name == name {
			return &s.Methods[i]
		}
	}
	return nil
}

// Access returns the rights on an attribute (method false) or a method
// (method true) of an object, from the objects, profiles, event logs and
// methods of the profile; ok is false when the profile does not list it.
func (s *Spec) Access(class uint16, obis string, id int8, method bool) (Rights, bool) {
	if method {
		for _, m := range s.Methods {
			if m.Method == id && m.OBIS == obis && m.Class == class {
				return m.Access, true
			}
		}
		return Rights{}, false
	}
	for _, m := range s.Methods {
		if m.Method == 0 && m.Attr == id && m.OBIS == obis && m.Class == class {
			return m.Access, true
		}
	}
	for _, o := range s.Objects {
		if o.OBIS == obis && o.Class == class && o.Attr == id {
			return o.Access, true
		}
	}
	if class == ClassProfileGeneric {
		if p := s.Profile(obis); p != nil {
			return p.Access, true // buffer, capture objects and the rest
		}
	}
	// Scaler_unit of a register listed with its value.
	if id != 0 && id == ScalerAttr(class) {
		for _, o := range s.Objects {
			if o.OBIS == obis && o.Class == class && o.Attr == 2 {
				a := o.Access
				for r := range a {
					a[r] &= Read
				}
				return a, true
			}
		}
	}
	return Rights{}, false
}

// ScalerAttr is the scaler_unit attribute of a class (IEC 62056-6-2:2023
// 4.3.2 to 4.3.4): 3 for the register and extended register, 4 for the
// demand register, whose attribute 3 is last_average_value; 0 otherwise.
func ScalerAttr(class uint16) int8 {
	switch class {
	case ClassRegister, ClassExtendedRegister:
		return 3
	case ClassDemandRegister:
		return 4
	}
	return 0
}

// IsTimeAttr reports the date-time attributes of the register classes:
// the extended register's capture_time (5), the demand register's
// capture_time (6) and start_time_current (7).
func IsTimeAttr(class uint16, attr int8) bool {
	return (class == ClassExtendedRegister && attr == 5) || (class == ClassDemandRegister && (attr == 6 || attr == 7))
}

// Groups lists the groups the profile has objects in, in Groups order.
func (s *Spec) Groups() []string {
	have := map[string]bool{}
	for _, o := range s.Objects {
		have[o.Group] = true
	}
	for _, p := range s.Profiles {
		have[p.Group] = true
	}
	if len(s.Events) > 0 {
		have[GroupEvents] = true
	}
	var out []string
	for _, g := range Groups {
		if have[g] {
			out = append(out, g)
		}
	}
	return out
}

// Count reports the catalogue size: objects (attributes), profiles, event
// logs, event codes, push setups and methods.
func (s *Spec) Count() (objects, profiles, logs, codes, push, methods int) {
	for _, l := range s.Events {
		codes += len(l.Codes)
	}
	return len(s.Objects), len(s.Profiles), len(s.Events), codes, len(s.Push), len(s.Methods)
}

// cols builds columns from OBIS codes of registers (class 3, attribute 2),
// after a clock column.
func clockThen(obis ...string) []Column {
	out := []Column{{OBIS: ClockOBIS, Class: ClassClock}}
	for _, o := range obis {
		out = append(out, reg(o))
	}
	return out
}

func reg(obis string) Column { return Column{OBIS: obis, Class: ClassRegister} }

// withoutOBIS returns cs without the columns whose OBIS is listed.
func withoutOBIS(cs []Column, obis ...string) []Column {
	var out []Column
	for _, c := range cs {
		if !slices.Contains(obis, c.OBIS) {
			out = append(out, c)
		}
	}
	return out
}
