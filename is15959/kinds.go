package is15959

import (
	"strconv"
	"strings"
)

// kindOf gives the value type and unit of a catalogue object from its OBIS
// code (value groups C and D per IEC 62056-6-1 and the India-specific
// codes of IS 15959). The standards fix the unit (tables' unit columns and
// notes) but mostly not the A-XDR type; the types here are the usual ones
// and only the simulator relies on them: a client should read whatever type the
// meter sends and scales registers by the meter's scaler_unit.
func kindOf(obis string) (typ, unit string) {
	switch obis {
	case ClockOBIS, "0.0.0.1.2.255":
		return "date-time", ""
	case "0.0.96.1.0.255", "0.0.96.1.1.255", "0.0.96.1.2.255", "1.0.0.2.0.255", "0.0.42.0.0.255",
		"0.0.94.91.11.255", "0.0.94.91.12.255", "0.0.96.13.1.255", "0.0.96.13.2.255":
		return "octet-string", ""
	case "0.0.94.91.9.255", "0.0.0.1.1.255", "0.0.94.96.19.255":
		return "unsigned", ""
	case "0.0.96.1.4.255", "1.0.0.4.2.255", "1.0.0.4.3.255", "0.0.96.7.0.255", "0.0.94.91.0.255", "0.0.96.2.0.255":
		return "long-unsigned", ""
	case "0.0.0.1.0.255":
		return "double-long-unsigned", ""
	case "1.0.0.8.0.255", "1.0.0.8.4.255", "1.0.0.8.5.255":
		return "long-unsigned", "s"
	case "0.0.94.91.8.255", "0.0.94.91.13.255", "0.0.94.91.14.255":
		return "double-long-unsigned", "min"
	case "1.0.94.91.1.255", "1.0.94.91.2.255":
		return "double-long-unsigned", "kvarh"
	case "1.0.94.91.14.255":
		return "long-unsigned", "A"
	case "1.0.13.0.0.255":
		return "long-unsigned", ""
	case EventStatusWord, "0.0.94.91.26.255":
		return "bit-string", ""
	}
	if strings.HasPrefix(obis, "0.0.96.11.") {
		return "long-unsigned", ""
	}
	f := strings.Split(obis, ".")
	if len(f) != 6 || f[0] != "1" {
		return "", ""
	}
	c, _ := strconv.Atoi(f[2])
	d, _ := strconv.Atoi(f[3])
	switch c {
	case 12, 32, 52, 72:
		return "long-unsigned", "V"
	case 11, 31, 51, 71, 91:
		return "long-unsigned", "A"
	case 13, 33, 53, 73:
		return "long", ""
	case 14:
		return "long-unsigned", "Hz"
	}
	switch d {
	case 7: // instantaneous power
		switch c {
		case 1, 2:
			return "double-long", "kW"
		case 3, 4:
			return "double-long", "kvar"
		case 9, 10:
			return "double-long-unsigned", "kVA"
		}
	case 6: // maximum demand
		switch c {
		case 1, 2:
			return "double-long-unsigned", "kW"
		case 9, 10:
			return "double-long-unsigned", "kVA"
		}
	case 8, 9, 29: // energy: cumulative, billing period, block
		switch c {
		case 1, 2:
			return "double-long-unsigned", "kWh"
		case 16:
			return "double-long", "kWh"
		case 5, 6, 7, 8:
			return "double-long-unsigned", "kvarh"
		case 9, 10:
			return "double-long-unsigned", "kVAh"
		}
	}
	return "", ""
}

// objs builds catalogue objects from capture columns (skipping the clock
// and repeated OBIS codes), typed and with units, in one group.
func objs(cols []Column, group string, access Rights, ref string) []Object {
	var out []Object
	seen := map[string]bool{}
	for _, c := range cols {
		attr := c.Attr
		if attr == 0 {
			attr = 2
		}
		k := c.OBIS + "/" + strconv.Itoa(int(attr))
		if seen[k] {
			continue
		}
		seen[k] = true
		typ, unit := kindOf(c.OBIS)
		if IsTimeAttr(c.Class, attr) {
			typ, unit = "date-time", ""
		}
		out = append(out, Object{OBIS: c.OBIS, Class: c.Class, Attr: attr, Type: typ, Unit: unit, Group: group, Access: access, Ref: ref})
	}
	return out
}

// obj is one typed object.
func obj(obis string, class uint16, group string, access Rights, ref string) Object {
	typ, unit := kindOf(obis)
	return Object{OBIS: obis, Class: class, Attr: 2, Type: typ, Unit: unit, Group: group, Access: access, Ref: ref}
}

// md is a maximum demand register column pair: value and capture time.
func md(obis string) []Column {
	return []Column{{OBIS: obis, Class: ClassExtendedRegister, Attr: 2}, {OBIS: obis, Class: ClassExtendedRegister, Attr: 5}}
}

// tz lists the TOU zone registers 1..n of a base code ("1.0.1.8").
func tz(base string, n int) []string {
	var out []string
	for e := 1; e <= n; e++ {
		out = append(out, base+"."+strconv.Itoa(e)+".255")
	}
	return out
}

func regs(obis ...string) []Column {
	out := make([]Column, len(obis))
	for i, o := range obis {
		cls := uint16(ClassRegister)
		switch o {
		case "0.0.96.7.0.255", "0.0.94.91.0.255", "0.0.0.1.0.255", "0.0.96.2.0.255":
			cls = ClassData
		}
		out[i] = Column{OBIS: o, Class: cls}
	}
	return out
}

func mds(obis ...string) []Column {
	var out []Column
	for _, o := range obis {
		out = append(out, md(o)...)
	}
	return out
}

func cat(parts ...[]Column) []Column {
	var out []Column
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// scalerProfile is a scaler profile: attribute 3 of each register column.
func scalerProfile(obis string, of []Column, group string, access Rights, ref string) Profile {
	var cols []Column
	seen := map[string]bool{}
	for _, c := range of {
		if c.Class != ClassRegister && c.Class != ClassExtendedRegister && c.Class != ClassDemandRegister {
			continue
		}
		if seen[c.OBIS] {
			continue
		}
		seen[c.OBIS] = true
		cols = append(cols, Column{OBIS: c.OBIS, Class: c.Class, Attr: ScalerAttr(c.Class)})
	}
	return Profile{OBIS: obis, Group: GroupScalers, Entries: 1, Capture: cols, Access: access, Ref: ref}
}
