package is15959

import "time"

// IS 15959 Part 3:2017: smart meters operated through CTs or CTs and PTs,
// category D3 (HV and LV consumers, clauses 11 to 16) and D4 (boundary,
// bank, ring fence and ABT meters, clauses 17 to 26). Associations, push,
// advanced security, the communication profile and firmware upgrade are
// Part 2's (Part 3 clauses 2 to 9); remote connect and disconnect do not
// apply (clause 10), so there is no disconnect control, limiter or
// control event log.

var (
	p3Read     = A("MR:R US:R")
	p3Instant  = A("MR:R US:R PUSH:R")
	p3Clock    = A("PC:R MR:R US:RW PUSH:R")
	p3Serial   = A("PC:R MR:R US:R")
	p3Settings = A("MR:R US:RW")
	p3Events   = A("MR:R US:R PUSH:R")
	p3Exec     = A("US:X")
)

// D3 and D4 instantaneous parameters (tables 1 and 14, identical codes).
var p3Instant3 = cat(
	[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
	regs("1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255", "1.0.72.7.0.255",
		"1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
		"1.0.1.7.0.255", "1.0.3.7.0.255", "0.0.96.7.0.255", "0.0.94.91.8.255", "0.0.94.91.0.255", "0.0.0.1.0.255",
		"0.0.96.2.0.255", "0.0.0.1.2.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.5.8.0.255", "1.0.6.8.0.255",
		"1.0.7.8.0.255", "1.0.8.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255"),
	mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
)

var (
	// D3 block load (table 2), daily load (table 3), billing (table 4).
	p3D3Block = clockThen("1.0.31.27.0.255", "1.0.51.27.0.255", "1.0.71.27.0.255", "1.0.32.27.0.255", "1.0.52.27.0.255",
		"1.0.72.27.0.255", "1.0.1.29.0.255", "1.0.2.29.0.255", "1.0.5.29.0.255", "1.0.6.29.0.255", "1.0.7.29.0.255",
		"1.0.8.29.0.255", "1.0.9.29.0.255", "1.0.10.29.0.255")
	p3D3Daily   = clockThen("1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255")
	p3D3Billing = cat(
		regs("0.0.0.1.2.255", "1.0.13.0.0.255", "1.0.1.8.0.255"), regs(tz("1.0.1.8", 8)...),
		regs("1.0.9.8.0.255"), regs(tz("1.0.9.8", 8)...),
		mds("1.0.1.6.0.255"), mds(tz("1.0.1.6", 8)...), mds("1.0.9.6.0.255"), mds(tz("1.0.9.6", 8)...),
		regs("0.0.94.91.13.255", "1.0.2.8.0.255", "1.0.10.8.0.255", "1.0.5.8.0.255", "1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255"),
	)
	// D4 block load (table 15), daily load (table 16), billing (table 17).
	p3D4Block = clockThen("1.0.14.27.0.255", "1.0.31.27.0.255", "1.0.51.27.0.255", "1.0.71.27.0.255", "1.0.32.27.0.255",
		"1.0.52.27.0.255", "1.0.72.27.0.255", "1.0.1.29.0.255", "1.0.2.29.0.255", "1.0.16.29.0.255", "1.0.5.29.0.255",
		"1.0.6.29.0.255", "1.0.7.29.0.255", "1.0.8.29.0.255", "1.0.9.29.0.255", "1.0.10.29.0.255")
	p3D4Daily = clockThen("1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255", "1.0.94.91.1.255",
		"1.0.94.91.2.255", "1.0.5.8.0.255", "1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255")
	p3D4Billing = cat(
		regs("0.0.0.1.2.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255", "1.0.5.8.0.255",
			"1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255", "0.0.94.91.13.255"),
		mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
		regs("1.0.13.0.0.255"),
	)
	// Event capture (tables 11 and 24).
	p3Capture = []string{"1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255",
		"1.0.72.7.0.255", "1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "0.0.94.91.0.255"}
)

// p3Events: six logs, e = 0..5 (clause 15, table 11 note 7; clause 25
// says 0..6, a finding), codes of tables 5 to 10 (D3) and 18 to 23 (D4).
func p3EventLogs(d4 bool) []EventLog {
	tx := []int{151, 152, 153, 154, 155, 156, 157, 161, 162, 163, 164, 165, 166, 167, 169, 177, 178}
	ref := "Part 3 clause 15, tables 5 to 11"
	if d4 {
		tx = []int{151, 154, 155, 156, 157, 161, 162, 163, 164, 165, 166, 169}
		ref = "Part 3 clause 25, tables 18 to 24"
	}
	return []EventLog{
		eventLog(0, span(1, 12), p3Events, ref+" (voltage)", p3Capture...),
		eventLog(1, span(51, 68), p3Events, ref+" (current)", p3Capture...),
		eventLog(2, []int{101, 102}, p3Events, ref+" (power)"),
		eventLog(3, tx, p3Events, ref+" (transaction)"),
		eventLog(4, []int{201, 202, 203, 204, 205, 206, 209, 210, 215, 216}, p3Events, ref+" (other)", p3Capture...),
		eventLog(5, []int{251}, p3Events, ref+" (non-rollover)"),
	}
}

func p3Programmable(d4 bool) []Object {
	o := []Object{
		{OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Group: GroupInstantaneous, Access: p3Clock, Ref: "Part 3 tables 13, 26"},
		{OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupProgrammable, Access: p3Settings, Ref: "Part 3 tables 13, 26"},
		{OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Group: GroupProgrammable, Access: p3Settings, Ref: "Part 3 tables 13, 26 note 3"},
		{OBIS: "0.0.22.0.0.255", Class: ClassHDLCSetup, Attr: 9, Type: "long-unsigned", Group: GroupCommunication, Access: A("MR:RW US:RW"), Ref: "Part 3 tables 13, 26 and notes 6, 4 (RS-485 device address, RS-485 meters only)"},
		{OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Attr: 6, Type: "enum", Group: GroupProgrammable, Access: p2Firmware, Ref: "Part 3 tables 13, 26 (FW association only)"},
		{OBIS: "0.0.15.0.2.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupProgrammable, Access: p2FWSched, Ref: "Part 3 tables 13, 26 notes 8, 10"},
		obj("0.0.94.91.26.255", ClassData, GroupPush, p3Settings, "Part 3 tables 13, 26"),
		obj("0.0.0.1.1.255", ClassData, GroupBilling, p3Read, "Part 1 clause 11.2 table 18"),
		obj("1.0.0.8.5.255", ClassData, GroupProgrammable, p3Read, "Part 3 clauses 13, 19 (recording interval 2, fixed 24 h)"),
	}
	if !d4 {
		o = append(o,
			obj("1.0.0.8.0.255", ClassData, GroupProgrammable, p3Settings, "Part 3 table 13 note 2 (seconds; 1800 default, 900)"),
			obj("1.0.0.8.4.255", ClassData, GroupProgrammable, p3Settings, "Part 3 table 13 note 2 (seconds; 1800 default, 900)"),
			obj("0.0.94.96.19.255", ClassData, GroupProgrammable, p3Settings, "Part 3 table 13 note 7 (0: forwarded only, 1: import and export)"),
		)
	}
	return o
}

func p3Methods(d4 bool) []Method {
	m := []Method{
		{Name: "set-clock", OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Access: p3Clock, Ref: "Part 3 tables 13, 26"},
		{Name: "billing-reset", OBIS: "0.0.10.0.1.255", Class: ClassScriptTable, Method: 1, Type: "long-unsigned", Access: p3Exec, Ref: "Part 3 table 13 row xiv note 9, table 26 row xi"},
		{Name: "billing-dates", OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p3Settings, Ref: "Part 3 tables 13, 26"},
		{Name: "tou-calendar-name", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 6, Type: "octet-string", Access: p3Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-seasons", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 7, Type: "array", Access: p3Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-weeks", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 8, Type: "array", Access: p3Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-days", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 9, Type: "array", Access: p3Settings, Ref: "Part 1 clauses 9.7 to 9.9"},
		{Name: "tou-activation", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Access: p3Settings, Ref: "Part 1 clause 9.9"},
		{Name: "event-status-filter", OBIS: "0.0.94.91.26.255", Class: ClassData, Attr: 2, Type: "bit-string", Access: p3Settings, Ref: "Part 3 tables 13, 26"},
		{Name: "reader-password", OBIS: "0.0.40.0.2.255", Class: ClassAssociationLN, Attr: 7, Type: "octet-string", Access: A("US:W"), Ref: "Part 3 table 13 note 12"},
		{Name: "hls-secret", OBIS: "0.0.40.0.3.255", Class: ClassAssociationLN, Method: 2, Type: "octet-string", Access: p3Exec, Ref: "Part 3 table 13 note 11"},
		{Name: "firmware-hls-secret", OBIS: "0.0.40.0.5.255", Class: ClassAssociationLN, Method: 2, Type: "octet-string", Access: p3Exec, Ref: "Part 3 table 13 note 11"},
		{Name: "global-key-transfer", OBIS: "0.0.43.0.0.255", Class: ClassSecuritySetup, Method: 2, Type: "array", Access: p3Exec, Ref: "Part 3 table 13 row xi note 11"},
		{Name: "image-transfer-initiate", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 1, Type: "structure", Access: p2Firmware, Ref: "Part 3 table 13 row vii; Part 2 clause 9"},
		{Name: "image-block-transfer", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 2, Type: "structure", Access: p2Firmware, Ref: "Part 2 clause 9"},
		{Name: "image-verify", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 3, Type: "integer", Access: p2Firmware, Ref: "Part 2 clause 9"},
		{Name: "image-activate", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 4, Type: "integer", Access: p2Firmware, Ref: "Part 2 clause 9"},
		{Name: "rs485-address", OBIS: "0.0.22.0.0.255", Class: ClassHDLCSetup, Attr: 9, Type: "long-unsigned", Access: A("MR:RW US:RW"), Ref: "Part 3 table 13 row vi note 6, table 26 row iv note 4"},
		{Name: "image-activation-time", OBIS: "0.0.15.0.2.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p2FWSched, Ref: "Part 3 table 13 row xii notes 8, 10"},
	}
	if !d4 {
		m = append(m,
			Method{Name: "demand-integration-period", OBIS: "1.0.0.8.0.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p3Settings, Ref: "Part 3 table 13"},
			Method{Name: "profile-capture-period", OBIS: "1.0.0.8.4.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p3Settings, Ref: "Part 3 table 13"},
			Method{Name: "metering-mode", OBIS: "0.0.94.96.19.255", Class: ClassData, Attr: 2, Type: "unsigned", Access: p3Settings, Ref: "Part 3 table 13 note 7"},
		)
	}
	return m
}

func p3Spec(id, category, title string, d4 bool, block, daily, billing []Column, blockPeriod time.Duration, ref string) *Spec {
	s := &Spec{ID: id, Title: title, Part: 3, Category: category, Phases: 3, Ref: ref,
		Associations: p2Associations, Suite: 0, Ciphering: "service-specific (dedicated key); push: general-glo (Part 2)"}
	s.Objects = append(s.Objects, p2Nameplate("8: LT CT four-wire, 9: HT CT three-wire, 10: HT CT four-wire")...)
	for i := range s.Objects {
		s.Objects[i].Ref = "Part 3 tables 12, 25"
	}
	s.Objects = append(s.Objects, p3Programmable(d4)...)
	inst := objs(p3Instant3, GroupInstantaneous, p3Instant, ref)
	for i := range inst {
		if inst[i].OBIS == ClockOBIS {
			inst[i].Access = p3Clock
		}
	}
	s.Objects = append(s.Objects, inst...)
	s.Objects = append(s.Objects, objs(block[1:], GroupBlockLoad, p3Read, ref)...)
	s.Objects = append(s.Objects, objs(daily[1:], GroupDailyLoad, p3Read, ref)...)
	s.Objects = append(s.Objects, objs(billing, GroupBilling, p3Read, ref)...)
	// Push (Part 2 clause 6 applies, Part 3 clause 6).
	s.Objects = append(s.Objects,
		Object{OBIS: EventStatusWord, Class: ClassData, Attr: 2, Type: "bit-string", Group: GroupPush, Access: A("MR:R US:R PUSH:R"), Ref: "Part 2 clause 6.1.5 (Part 3 clause 6)"})
	for _, ps := range []string{PushPeriodic, PushEvent} {
		s.Objects = append(s.Objects, pushSetupObjects(ps, p2PushSetup)...)
	}
	s.Profiles = []Profile{
		{OBIS: "1.0.94.91.0.255", Group: GroupInstantaneous, Capture: p3Instant3, Scaler: "1.0.94.91.3.255", Access: p3Instant, Ref: ref},
		scalerProfile("1.0.94.91.3.255", p3Instant3, GroupScalers, p3Instant, ref),
		{OBIS: "1.0.99.1.0.255", Group: GroupBlockLoad, Period: blockPeriod, Capture: block, Scaler: "1.0.94.91.4.255", Access: p3Read, Ref: ref},
		scalerProfile("1.0.94.91.4.255", block, GroupScalers, p3Read, ref),
		{OBIS: "1.0.99.2.0.255", Group: GroupDailyLoad, Period: 24 * time.Hour, Capture: daily, Scaler: "1.0.94.91.5.255", Access: p3Read, Ref: ref},
		scalerProfile("1.0.94.91.5.255", daily, GroupScalers, p3Read, ref),
		{OBIS: "1.0.98.1.0.255", Group: GroupBilling, Entries: 6, Capture: billing, Scaler: "1.0.94.91.6.255", Access: p3Read, Ref: ref},
		scalerProfile("1.0.94.91.6.255", billing, GroupScalers, p3Read, ref),
		{OBIS: "0.0.94.91.10.255", Group: GroupNameplate, Entries: 1, Capture: dataCols(append([]Column(nil), p2NameplateCols...)), Access: p3Read, Ref: ref},
		scalerProfile("1.0.94.91.7.255", regs(p3Capture...), GroupEvents, p3Events, ref),
	}
	s.Events = p3EventLogs(d4)
	s.Objects = append(s.Objects, eventCodeObjects(s.Events, p3Events, "Part 3 clauses 15, 25 (event code objects)")...)
	s.ESW = append(append([]ESWBit(nil), p2ESW3...), p2ESWCommon...)
	for _, ps := range p2Push(p3Instant3) {
		if ps.OBIS == PushPeriodic || ps.OBIS == PushEvent {
			s.Push = append(s.Push, ps)
		}
	}
	s.Methods = p3Methods(d4)
	s.dedupe()
	return s
}

func init() {
	register(p3Spec("part3-ctpt", "D3", "IS 15959 Part 3 CT or CT/PT operated smart meter (D3)", false,
		p3D3Block, p3D3Daily, p3D3Billing, 30*time.Minute, "Part 3 clauses 11 to 16, tables 1 to 13"))
	register(p3Spec("part3-boundary", "D4", "IS 15959 Part 3 CT/PT operated boundary, bank, ring fence or ABT smart meter (D4)", true,
		p3D4Block, p3D4Daily, p3D4Billing, 15*time.Minute, "Part 3 clauses 17 to 26, tables 14 to 26"))
}
