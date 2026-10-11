package is15959

import "time"

// IS 15959 Part 1:2011 (reaffirmed 2016): the Indian companion
// specification for DLMS/COSEM energy meters, categories A (feeder and
// distribution transformer audit, annex C), B (boundary, bank, ring fence
// and ABT, import and export, annex D) and C (HV and LV CT/PT consumers,
// annex E); annex F (name plate and programmable parameters) and annex G
// (events) are common. Part 1 defines no category D: categories D1 and D2
// (whole-current smart meters) are Part 2's and D3 and D4 (CT and CT/PT
// smart meters) Part 3's.

// Access rights Part 1 gives by group (clause 5.2, annexes C-3, D-3.2,
// E-3.1, F-1.1, F-2, G-1.2).
var (
	p1Read     = A("MR:R US:R")
	p1Clock    = A("PC:R MR:R US:RW")
	p1Serial   = A("PC:R MR:R US:R")
	p1Settings = A("MR:R US:RW")
	p1Exec     = A("US:X")
	p1Public   = A("PC:R MR:R US:R")
)

// p1Associations: clause 5, table 3; security clause 7 (basic security,
// no APDU ciphering, is mandatory; advanced security optional, with the
// security setups of table 6).
var p1Associations = []Association{
	{Role: PC, Client: 16, OBIS: "0.0.40.0.1.255", Auth: "none", Security: "none", Ref: "Part 1 clause 5.2.1, table 3"},
	{Role: MR, Client: 32, OBIS: "0.0.40.0.2.255", Auth: "low", Security: "none", Setup: "0.0.43.0.1.255", Ref: "Part 1 clause 5.2.2, table 3, clause 7.5.1.2, table 6"},
	{Role: US, Client: 48, OBIS: "0.0.40.0.3.255", Auth: "hls-aes", Security: "none", Setup: "0.0.43.0.2.255", Ref: "Part 1 clause 5.2.3, table 3, clause 7.5.1.3 (AES-128 challenge processing), table 6"},
}

// Part 1 name plate (annex F table 30) and mandatory objects (table 2).
func p1Nameplate() []Object {
	return []Object{
		obj("0.0.96.1.0.255", ClassData, GroupNameplate, p1Serial, "Part 1 annex F table 30"),
		obj("0.0.96.1.1.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30"),
		obj("1.0.0.2.0.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30"),
		obj("0.0.94.91.9.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30 (0: three-phase three-wire, 1: three-phase four-wire)"),
		obj("1.0.0.4.2.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30"),
		obj("1.0.0.4.3.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30"),
		obj("0.0.96.1.4.255", ClassData, GroupNameplate, p1Read, "Part 1 annex F table 30"),
		obj("0.0.42.0.0.255", ClassData, GroupNameplate, p1Public, "Part 1 clause 5.1 table 2 (logical device name, FLAG ID first)"),
	}
}

// Part 1 programmable parameters (annex F-2 table 31) and billing
// objects (clauses 9 to 11).
func p1Programmable() []Object {
	o := []Object{
		{OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Group: GroupInstantaneous, Access: p1Clock, Ref: "Part 1 annex F-2 table 31"},
		obj("1.0.0.8.0.255", ClassData, GroupProgrammable, p1Settings, "Part 1 annex F-2 table 31 note 2 (seconds)"),
		obj("1.0.0.8.4.255", ClassData, GroupProgrammable, p1Settings, "Part 1 annex F-2 table 31 note 2 (seconds); annex C-5.1 recording interval 1"),
		{OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupProgrammable, Access: p1Settings, Ref: "Part 1 clause 10.2 table 15, annex F-2 table 31 (execution_time)"},
		{OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Group: GroupProgrammable, Access: p1Settings, Ref: "Part 1 clause 9.3 table 12, clause 9.9, annex F-2 table 31 (activate_passive_calendar_time)"},
		obj("0.0.0.1.0.255", ClassData, GroupBilling, p1Read, "Part 1 clause 11.2 table 17"),
		obj("0.0.0.1.1.255", ClassData, GroupBilling, p1Read, "Part 1 clause 11.2 table 18"),
	}
	return o
}

// p1Methods: the commands Part 1 provides.
func p1Methods() []Method {
	return []Method{
		{Name: "set-clock", OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Access: p1Clock, Ref: "Part 1 annex F-2 table 31"},
		{Name: "billing-reset", OBIS: "0.0.10.0.1.255", Class: ClassScriptTable, Method: 1, Type: "long-unsigned", Access: p1Exec, Ref: "Part 1 clauses 10.3, 10.4 table 16 (MD reset / end of billing script)"},
		{Name: "billing-dates", OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p1Settings, Ref: "Part 1 clause 10.2 table 15"},
		{Name: "demand-integration-period", OBIS: "1.0.0.8.0.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p1Settings, Ref: "Part 1 annex F-2 table 31"},
		{Name: "profile-capture-period", OBIS: "1.0.0.8.4.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p1Settings, Ref: "Part 1 annex F-2 table 31"},
		{Name: "tou-calendar-name", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 6, Type: "octet-string", Access: p1Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-seasons", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 7, Type: "array", Access: p1Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-weeks", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 8, Type: "array", Access: p1Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-days", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 9, Type: "array", Access: p1Settings, Ref: "Part 1 clauses 9.7, 9.8, 9.9 (script ids 1-16 energy, 17-32 demand)"},
		{Name: "tou-activation", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Access: p1Settings, Ref: "Part 1 clause 9.9"},
		{Name: "reader-password", OBIS: "0.0.40.0.2.255", Class: ClassAssociationLN, Attr: 7, Type: "octet-string", Access: A("US:W"), Ref: "Part 1 clause 7.5.1.2"},
		{Name: "hls-secret", OBIS: "0.0.40.0.3.255", Class: ClassAssociationLN, Method: 2, Type: "octet-string", Access: p1Exec, Ref: "Part 1 clause 7.5.1.3 (change_HLS_secret)"},
		{Name: "disconnect", OBIS: DisconnectControl, Class: ClassDisconnect, Method: 1, Type: "integer", Access: p1Exec, Ref: "Part 1 clause 14 table 20 (where remote disconnection is required)"},
		{Name: "reconnect", OBIS: DisconnectControl, Class: ClassDisconnect, Method: 2, Type: "integer", Access: p1Exec, Ref: "Part 1 clause 14 table 20"},
	}
}

// p1Capture is the event capture list (annex G table 39): the clock and
// code (added by eventLog) then these registers.
var p1Capture = []string{"1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255",
	"1.0.72.7.0.255", "1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.1.8.0.255"}

// p1Events: the seven logs of clause 8 tables 9 and 11 (e = 0..6) with
// the codes of annex G tables 32 to 38. Power, transaction, non-rollover
// and control logs capture only the time and code (tables 34, 35, 37, 38).
func p1Events() []EventLog {
	return []EventLog{
		eventLog(0, span(1, 12), p1Read, "Part 1 clause 8, annex G table 32, capture table 39", p1Capture...),
		eventLog(1, span(51, 68), p1Read, "Part 1 clause 8, annex G table 33, capture table 39", p1Capture...),
		eventLog(2, []int{101, 102}, p1Read, "Part 1 clause 8, annex G table 34"),
		eventLog(3, span(151, 155), p1Read, "Part 1 clause 8, annex G table 35"),
		eventLog(4, span(201, 206), p1Read, "Part 1 clause 8, annex G table 36, capture table 39", p1Capture...),
		eventLog(5, []int{251}, p1Read, "Part 1 clause 8, annex G table 37"),
		eventLog(6, []int{301, 302}, p1Read, "Part 1 clause 8 table 9 note 1, annex G table 38 (only with remote load control)"),
	}
}

// p1EventScalers is the event scaler profile (annex G-2).
func p1EventScalers() Profile {
	return scalerProfile("1.0.94.91.7.255", regs(p1Capture...), GroupEvents, p1Read, "Part 1 annex G-2")
}

// Category A instantaneous parameters (annex C table 22). Line voltages of
// three-phase three-wire meters (V_RY, V_BY) use the phase voltage codes.
var p1AInstant = cat(
	[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
	regs("1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255", "1.0.72.7.0.255",
		"1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
		"1.0.1.7.0.255", "1.0.3.7.0.255", "1.0.1.8.0.255", "1.0.5.8.0.255", "1.0.8.8.0.255", "1.0.9.8.0.255",
		"0.0.96.7.0.255", "0.0.94.91.8.255", "0.0.94.91.0.255", "0.0.0.1.0.255", "0.0.96.2.0.255", "0.0.0.1.2.255"),
	mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
)

// Category A block load profile (annex C table 23); row ii is printed
// 1.0.31.87.0.255, read as the block average 1.0.31.27.0.255 (finding).
var p1ABlock = clockThen("1.0.31.27.0.255", "1.0.51.27.0.255", "1.0.71.27.0.255", "1.0.32.27.0.255", "1.0.52.27.0.255",
	"1.0.72.27.0.255", "1.0.1.29.0.255", "1.0.5.29.0.255", "1.0.8.29.0.255", "1.0.9.29.0.255")

// Category B instantaneous parameters (annex D table 24).
var p1BInstant = cat(
	[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
	regs("1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255", "1.0.72.7.0.255",
		"1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
		"1.0.1.7.0.255", "1.0.3.7.0.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255",
		"0.0.96.7.0.255", "0.0.94.91.8.255", "0.0.94.91.0.255", "0.0.0.1.0.255", "0.0.96.2.0.255", "0.0.0.1.2.255"),
)

// Category B block load (annex D table 25) and daily load (table 26).
var (
	p1BBlock = clockThen("1.0.14.27.0.255", "1.0.32.27.0.255", "1.0.52.27.0.255", "1.0.72.27.0.255", "1.0.1.29.0.255",
		"1.0.16.29.0.255", "1.0.2.29.0.255", "1.0.5.29.0.255", "1.0.6.29.0.255", "1.0.7.29.0.255", "1.0.8.29.0.255")
	p1BDaily = clockThen("1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255", "1.0.94.91.1.255",
		"1.0.94.91.2.255", "1.0.5.8.0.255", "1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255")
)

// Category C instantaneous parameters (annex E table 27); signed reactive
// power is printed 1.0.37.7.0.255, read as 1.0.3.7.0.255 as in tables 22
// and 24 (finding).
var p1CInstant = cat(
	[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
	regs("1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255", "1.0.72.7.0.255",
		"1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
		"1.0.1.7.0.255", "1.0.3.7.0.255", "0.0.96.7.0.255", "0.0.94.91.8.255", "0.0.94.91.0.255", "0.0.0.1.0.255",
		"0.0.96.2.0.255", "0.0.0.1.2.255", "1.0.1.8.0.255", "1.0.5.8.0.255", "1.0.8.8.0.255", "1.0.9.8.0.255"),
)

// Category C block load (annex E table 28) and billing (table 29).
var (
	p1CBlock   = p1ABlock
	p1CBilling = cat(
		regs("0.0.0.1.2.255", "1.0.13.0.0.255", "1.0.1.8.0.255"), regs(tz("1.0.1.8", 8)...),
		regs("1.0.5.8.0.255", "1.0.8.8.0.255", "1.0.9.8.0.255"), regs(tz("1.0.9.8", 8)...),
		mds("1.0.1.6.0.255"), mds(tz("1.0.1.6", 8)...), mds("1.0.9.6.0.255"), mds(tz("1.0.9.6", 8)...),
	)
)

func p1Spec(id, cat, title, ref string, instant, block, daily, billing []Column, blockPeriod time.Duration) *Spec {
	s := &Spec{ID: id, Title: title, Part: 1, Category: cat, Phases: 3, Ref: ref,
		Associations: p1Associations, Ciphering: "none"}
	s.Objects = append(s.Objects, p1Nameplate()...)
	s.Objects = append(s.Objects, p1Programmable()...)
	inst := objs(instant, GroupInstantaneous, p1Read, ref)
	for i := range inst {
		if inst[i].OBIS == ClockOBIS {
			inst[i].Access = p1Clock
		}
	}
	s.Objects = append(s.Objects, inst...)
	s.Profiles = append(s.Profiles,
		Profile{OBIS: "1.0.94.91.0.255", Group: GroupInstantaneous, Capture: instant, Scaler: "1.0.94.91.3.255", Access: p1Read, Ref: ref},
		scalerProfile("1.0.94.91.3.255", instant, GroupScalers, p1Read, ref),
		Profile{OBIS: "1.0.99.1.0.255", Group: GroupBlockLoad, Period: blockPeriod, Capture: block, Scaler: "1.0.94.91.4.255", Access: p1Read, Ref: ref},
		scalerProfile("1.0.94.91.4.255", block, GroupScalers, p1Read, ref),
	)
	s.Objects = append(s.Objects, objs(block[1:], GroupBlockLoad, p1Read, ref)...)
	if daily != nil {
		s.Profiles = append(s.Profiles,
			Profile{OBIS: "1.0.99.2.0.255", Group: GroupDailyLoad, Period: 24 * time.Hour, Capture: daily, Scaler: "1.0.94.91.5.255", Access: p1Read, Ref: ref},
			scalerProfile("1.0.94.91.5.255", daily, GroupScalers, p1Read, ref))
		s.Objects = append(s.Objects, obj("1.0.0.8.5.255", ClassData, GroupProgrammable, p1Read, "Part 1 annex D-5.1 recording interval 2 (class not stated; data assumed)"))
	}
	if billing != nil {
		s.Profiles = append(s.Profiles,
			Profile{OBIS: "1.0.98.1.0.255", Group: GroupBilling, Entries: 6, Capture: billing, Scaler: "1.0.94.91.6.255", Access: p1Read, Ref: ref},
			scalerProfile("1.0.94.91.6.255", billing, GroupScalers, p1Read, ref))
	}
	s.Events = p1Events()
	s.Objects = append(s.Objects, eventCodeObjects(s.Events, p1Read, "Part 1 clause 8.1 tables 8, 9")...)
	s.Profiles = append(s.Profiles, p1EventScalers())
	s.Methods = p1Methods()
	s.dedupe()
	return s
}

func init() {
	register(p1Spec("part1-category-A", "A", "IS 15959 Part 1 category A (feeder and distribution transformer audit meter)",
		"Part 1 annexes A-1.1, C, F, G", p1AInstant, p1ABlock, nil, nil, 15*time.Minute))
	register(p1Spec("part1-category-B", "B", "IS 15959 Part 1 category B (boundary, bank, ring fence and ABT meter)",
		"Part 1 annexes A-1.2, D, F, G", p1BInstant, p1BBlock, p1BDaily, nil, 15*time.Minute))
	register(p1Spec("part1-category-C", "C", "IS 15959 Part 1 category C (HV and LV CT/PT consumer meter)",
		"Part 1 annexes A-1.3, E, F, G", p1CInstant, p1CBlock, nil, p1CBilling, 15*time.Minute))
}

// dedupe keeps the first object for each OBIS code and attribute (an
// object listed in several tables keeps the first table's rights).
func (s *Spec) dedupe() {
	seen := map[string]bool{}
	out := s.Objects[:0]
	for _, o := range s.Objects {
		a := o.Attr
		if a == 0 {
			a = 2
		}
		k := o.OBIS + "/" + string(rune('0'+a))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, o)
	}
	s.Objects = out
}
