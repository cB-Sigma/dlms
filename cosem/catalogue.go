package cosem

import (
	"strconv"

	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/obis"
)

// The built-in catalogue is IS 15959 as data (package is15959): Part 1
// categories A, B and C, Part 2 (with Amendments 1 and 2) single- and
// three-phase whole-current smart meters, and Part 3 CT and CT/PT smart
// meters. A meter's "profile" setting selects one; without it the Part 2
// smart meter of the meter's phases is used. Add or override objects per
// meter with "objects".

// Interface classes used here.
const (
	ClassData             = is15959.ClassData
	ClassRegister         = is15959.ClassRegister
	ClassExtendedRegister = is15959.ClassExtendedRegister
	ClassDemandRegister   = is15959.ClassDemandRegister
	ClassProfileGeneric   = is15959.ClassProfileGeneric
	ClassClock            = is15959.ClassClock
	ClassDisconnect       = is15959.ClassDisconnect
)

// Object is one COSEM attribute a client reads.
type Object struct {
	Name      string `json:"name"`
	OBIS      string `json:"obis"`
	Class     uint16 `json:"class"`
	Attribute int8   `json:"attribute,omitempty"` // default 2 (value or buffer)
	Unit      string `json:"unit,omitempty"`      // overrides the meter's scaler_unit
	Group     string `json:"-"`
}

// Groups a meter can read (settings "groups").
const (
	GroupNameplate     = is15959.GroupNameplate
	GroupInstantaneous = is15959.GroupInstantaneous
	GroupEnergy        = is15959.GroupEnergy
	GroupBlockLoad     = is15959.GroupBlockLoad
	GroupDailyLoad     = is15959.GroupDailyLoad
	GroupBilling       = is15959.GroupBilling
	GroupEvents        = is15959.GroupEvents
	GroupProgrammable  = is15959.GroupProgrammable
	GroupScalers       = is15959.GroupScalers
	GroupPush          = is15959.GroupPush
	GroupSecurity      = is15959.GroupSecurity
	GroupCommunication = is15959.GroupCommunication
)

// DisconnectControl is the disconnect control object (class 70).
const DisconnectControl = is15959.DisconnectControl

// ClockOBIS is the meter clock (class 8).
const ClockOBIS = is15959.ClockOBIS

// DefaultProfile is the profile of a meter without a "profile" setting.
func DefaultProfile(phases int) string {
	if phases == 1 {
		return "part2-1ph"
	}
	return "part2-3ph"
}

// profiled groups are read as their profile generic objects; the others as
// their objects. "energy" is the cumulative registers of the instantaneous
// list (the old catalogue's group).
var profiled = map[string]bool{GroupBlockLoad: true, GroupDailyLoad: true, GroupBilling: true, GroupEvents: true, GroupScalers: true}

// Catalogue returns the objects of the given groups of the Part 2 smart
// meter of the given phases (1 or 3).
func Catalogue(phases int, groups ...string) []Object {
	return ProfileCatalogue(DefaultProfile(phases), groups...)
}

// ProfileCatalogue returns what a client reads of the given groups of an
// IS 15959 profile: the objects of each group, and for block load, daily
// load, billing, events and scalers their profile generic buffers.
func ProfileCatalogue(profile string, groups ...string) []Object {
	sp, ok := is15959.Get(profile)
	if !ok {
		return nil
	}
	want := map[string]bool{}
	for _, g := range groups {
		want[g] = true
	}
	var out []Object
	seen := map[string]bool{}
	add := func(o Object) {
		k := o.OBIS + "/" + strconv.Itoa(int(o.Attribute))
		if !seen[k] {
			seen[k] = true
			out = append(out, o)
		}
	}
	for _, o := range sp.Objects {
		g := o.Group
		if want[GroupEnergy] && g == GroupInstantaneous && isEnergy(o.OBIS) {
			g = GroupEnergy
		}
		if !want[g] || profiled[g] {
			continue
		}
		add(Object{Name: o.Name, OBIS: o.OBIS, Class: o.Class, Attribute: o.Attr, Group: g})
	}
	for _, p := range sp.Profiles {
		if want[p.Group] && profiled[p.Group] {
			add(Object{Name: p.Name, OBIS: p.OBIS, Class: ClassProfileGeneric, Attribute: 2, Group: p.Group})
		}
	}
	if want[GroupEvents] {
		for _, l := range sp.Events {
			add(Object{Name: l.Name, OBIS: l.OBIS, Class: ClassProfileGeneric, Attribute: 2, Group: GroupEvents})
		}
	}
	return out
}

// isEnergy reports cumulative energy and maximum demand registers.
func isEnergy(obis string) bool {
	f, err := ParseOBIS(obis)
	return err == nil && f[0] == 1 && (f[3] == 8 || f[3] == 6)
}

// NameOf returns the catalogue name of an attribute; for an object the
// catalogue does not list, the name the OBIS model derives (IEC
// 62056-6-1:2023, package obis) with the class's attribute suffix; and
// the OBIS code for a code without a standard meaning (manufacturer,
// utility, country specific or reserved). The class picks the row where
// one code names objects of several classes (IEC 62056-6-2:2023 clause 6).
func NameOf(code string, class uint16, attr int8) string {
	if n := is15959.NameOf(code, class, attr); n != code {
		return n
	}
	c, err := obis.Parse(code)
	if err != nil || c.String() != code {
		return code
	}
	if base := obis.NameFor(c, class); base != "" {
		return is15959.AttrName(base, code, class, attr)
	}
	return code
}

// units maps the COSEM unit enumeration (IEC 62056-6-2:2023 4.3.2,
// Table 5) to unit symbols. Codes the table does not assign (58, 59, 66
// to 69, 73 to 252) and 253 (reserved) are reported as "unit-<n>"; 255
// (no unit, a count) is the empty unit. 14, 16 and 18 are the deprecated
// corrected volume units, given their volume symbols.
var units = map[uint8]string{
	1: "a", 2: "mo", 3: "wk", 4: "d", 5: "h", 6: "min", 7: "s", 8: "deg", 9: "Cel", 10: "currency",
	11: "m", 12: "m/s", 13: "m3", 14: "m3", 15: "m3/h", 16: "m3/h", 17: "m3/d", 18: "m3/d", 19: "l", 20: "kg",
	21: "N", 22: "Nm", 23: "Pa", 24: "bar", 25: "J", 26: "J/h", 27: "W", 28: "VA", 29: "var", 30: "Wh",
	31: "VAh", 32: "varh", 33: "A", 34: "C", 35: "V", 36: "V/m", 37: "F", 38: "Ohm", 39: "Ohm.m2/m", 40: "Wb",
	41: "T", 42: "A/m", 43: "H", 44: "Hz", 45: "1/Wh", 46: "1/varh", 47: "1/VAh", 48: "V2h", 49: "A2h", 50: "kg/s",
	51: "S", 52: "K", 53: "1/V2h", 54: "1/A2h", 55: "1/m3", 56: "%", 57: "Ah",
	60: "Wh/m3", 61: "J/m3", 62: "mol%", 63: "g/m3", 64: "Pa.s", 65: "J/kg",
	70: "dBm", 71: "dBuV", 72: "dB",
	254: "other", 255: "",
}

// ScalerAttr is the scaler_unit attribute of a class: 3 for the register
// and extended register, 4 for the demand register (IEC 62056-6-2:2023
// 4.3.2 to 4.3.4); 0 for classes without one.
func ScalerAttr(class uint16) int8 {
	switch class {
	case ClassRegister, ClassExtendedRegister:
		return 3
	case ClassDemandRegister:
		return 4
	}
	return 0
}

// ScaledValue reports the attributes scaled by the scaler_unit: the value
// of a register or extended register, and the current and last average
// values of a demand register.
func ScaledValue(class uint16, attr int8) bool {
	switch class {
	case ClassRegister, ClassExtendedRegister:
		return attr == 2
	case ClassDemandRegister:
		return attr == 2 || attr == 3
	}
	return false
}

// UnitSymbol is the symbol of a COSEM unit code (IEC 62056-6-2 unit
// table), empty for codes without one.
func UnitSymbol(u uint8) string {
	if s, ok := units[u]; ok {
		return s
	}
	return "unit-" + strconv.Itoa(int(u))
}
