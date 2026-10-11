package is15959

import "time"

// IS 15959 Part 2:2016 (reaffirmed 2021): smart meters, single-phase (D1)
// and three-phase (D2) whole current, with Amendment 1 (April 2017) and
// Amendment 2 (May 2017) applied. Clause references are to Part 2 unless
// they name Part 1; "Amd 1 item n" is the amendment's change n in the
// order printed.

// Access rights (clauses 11.1.1, 12 to 16, 17.1, 21.2, 22).
var (
	p2Read      = A("MR:R US:R")
	p2Instant   = A("MR:R US:R PUSH:R IHD:R")
	p2Clock     = A("PC:R MR:R US:RW PUSH:R IHD:R")
	p2Serial    = A("PC:R MR:R US:R")
	p2Settings  = A("MR:R US:RW")
	p2Events    = A("MR:R US:R PUSH:R")
	p2Exec      = A("US:X")
	p2Payment   = A("MR:R US:RW IHD:R")
	p2Firmware  = A("FW:RX")
	p2FWSched   = A("US:R FW:RW")
	p2PushSetup = A("MR:R US:RW PUSH:R")
	p2DispPush  = A("MR:R US:RW PUSH:R IHD:R")
	p2Display   = A("US:RW IHD:RW")
)

// p2Associations: table 2 as amended (Amd 1 items 2 to 5 and 21; Amd 2):
// MR, US and FW protect APDUs with service-specific ciphering under a
// dedicated key, PUSH and IHD with general global ciphering (clause 7.2 e)
// as changed by Amd 2); security suite 0 (AES-GCM-128, AES-128 key wrap,
// clause 7.2 c), unchanged by both amendments); association objects class
// 15 version 1 (Amd 1 item 20 made it 3, Amd 2 restored 1). Part 2 names
// the US and FW authentication "HLS" without a mechanism; Part 1 clause
// 7.5.1.3 gives AES-128 challenge processing with an HLS secret changed by
// change_HLS_secret (Part 2 table A13 row xvii), which is mechanism 2
// (hls-aes); a meter using HLS-GMAC is set with "authentication". The
// IHD association (table 1: pushes and reads utility messages, reads the
// objects it is given) has no authentication after Amd 1 item 2, encrypted
// APDUs under general global ciphering (clause 7.2 e) as amended) and its
// own factory-set global key, not the one the other associations share
// (clause 7.3.1, Amd 1 item 22).
var p2Associations = []Association{
	{Role: PC, Client: 16, OBIS: "0.0.40.0.1.255", Auth: "none", Security: "none", Ref: "Part 2 table 2"},
	{Role: MR, Client: 32, OBIS: "0.0.40.0.2.255", Auth: "low", Security: "encrypted", Setup: "0.0.43.0.2.255", Ref: "Part 2 table 2; clause 7.2 e) (Amd 1 item 21)"},
	{Role: US, Client: 48, OBIS: "0.0.40.0.3.255", Auth: "hls-aes", Security: "authenticated-encrypted", Setup: "0.0.43.0.3.255", Ref: "Part 2 table 2; clause 7.2 e) (Amd 1 item 21)"},
	{Role: Push, Client: 64, OBIS: "0.0.40.0.4.255", Auth: "none", Security: "encrypted", Setup: "0.0.43.0.4.255", Ref: "Part 2 table 2 (Amd 1 item 4); clause 7.2 e) general global ciphering (Amd 2)"},
	{Role: FW, Client: 80, OBIS: "0.0.40.0.5.255", Auth: "hls-aes", Security: "authenticated-encrypted", Setup: "0.0.43.0.5.255", Ref: "Part 2 table 2 (Amd 1 item 5); clause 9"},
	{Role: IHD, Client: 96, OBIS: "0.0.40.0.6.255", Auth: "none", Security: "encrypted", Setup: "0.0.43.0.6.255", Ref: "Part 2 tables 1, 2 (Amd 1 items 2, 3); clause 7.2 e) (Amd 2), 7.3.1"},
}

// Push setups (clause 6, table 3 and figure 2 as amended by Amd 1 items 7
// to 17: 0.b.25.9.0.255 with b = 0..4). The periodic push carries up to
// ten instantaneous parameters the buyer selects (clause 6.1.1): a head
// end reads push_object_list from the meter (Amd 1 item 6) and falls back to
// the first ten instantaneous parameters listed here.
const (
	PushPeriodic     = "0.0.25.9.0.255" // meter to head end, periodic (table 4)
	PushToDisplay    = "0.1.25.9.0.255" // head end to IHD (table 5)
	PushFromDisplay  = "0.2.25.9.0.255" // IHD to head end (table 6)
	PushMeterDisplay = "0.3.25.9.0.255" // meter to IHD (table 7)
	PushEvent        = "0.4.25.9.0.255" // meter to head end on events (table 8)
)

func p2Push(instant []Column) []PushSetup {
	head := []Column{{OBIS: "0.0.96.1.2.255", Class: ClassData}}
	id := func(obis string) Column { return Column{OBIS: obis, Class: ClassPushSetup, Attr: 1} }
	clock := Column{OBIS: ClockOBIS, Class: ClassClock}
	var ten []Column
	for _, c := range instant {
		if c.Class == ClassClock || c.Attr != 2 && c.Attr != 0 || len(ten) == 10 {
			continue
		}
		ten = append(ten, c)
	}
	return []PushSetup{
		{OBIS: PushPeriodic, Capture: cat(head, []Column{id(PushPeriodic), clock}, ten), Ref: "Part 2 clause 6.1.1 table 4 (Amd 1 item 14)"},
		{OBIS: PushToDisplay, Capture: []Column{clock, id(PushToDisplay), {OBIS: "0.0.96.13.1.255", Class: ClassData}}, Ref: "Part 2 clause 6.1.2 table 5 (Amd 1 items 15, 16)"},
		{OBIS: PushFromDisplay, Capture: cat(head, []Column{id(PushFromDisplay), clock, {OBIS: "0.0.96.13.2.255", Class: ClassData}}), Ref: "Part 2 clause 6.1.3 table 6 (Amd 1 items 15, 16)"},
		{OBIS: PushMeterDisplay, Capture: cat([]Column{clock, id(PushMeterDisplay), reg("1.0.1.9.0.255")}, ten[:4]), Ref: "Part 2 clause 6.1.4 table 7 (Amd 1 items 11, 12, 15, 16; four more buyer-selected objects, the first four here)"},
		{OBIS: PushEvent, Capture: cat(head, []Column{id(PushEvent), clock, {OBIS: EventStatusWord, Class: ClassData}}), Ref: "Part 2 clause 6.1.5 table 8 (Amd 1 item 17)"},
	}
}

// ESW bits (table 10 as amended by Amd 1 item 18): bit, occurrence and
// restoration codes. Bits not listed are reserved and sent as 0.
const (
	BitLastGasp    = 85
	BitFirstBreath = 86
)

func eswBit(bit, occ, rest int, name string) ESWBit {
	return ESWBit{Bit: bit, Name: name, Occurrence: occ, Restoration: rest}
}

var p2ESWCommon = []ESWBit{
	eswBit(3, 7, 8, "over-voltage"), eswBit(4, 9, 10, "low voltage"), eswBit(11, 67, 68, "over-current"),
	eswBit(81, 201, 202, "magnetic influence"), eswBit(82, 203, 204, "neutral disturbance"),
	eswBit(83, 251, 0, "meter cover opened"), eswBit(84, 301, 302, "load switch disconnected or connected"),
	eswBit(BitLastGasp, 0, 0, "last gasp (power failure)"), eswBit(BitFirstBreath, 0, 0, "first breath (power restored)"),
	eswBit(87, 0, 0, "billing count incremented (billing reset)"),
}

var p2ESW3 = []ESWBit{
	eswBit(0, 1, 2, "R-phase voltage missing"), eswBit(1, 3, 4, "Y-phase voltage missing"), eswBit(2, 5, 6, "B-phase voltage missing"),
	eswBit(5, 11, 12, "voltage unbalance"), eswBit(6, 51, 52, "R-phase current reversed"), eswBit(7, 53, 54, "Y-phase current reversed"),
	eswBit(8, 55, 56, "B-phase current reversed"), eswBit(9, 63, 64, "current unbalance"), eswBit(10, 65, 66, "current bypass"),
	eswBit(12, 205, 206, "low power factor"),
}

var p2ESW1 = []ESWBit{eswBit(51, 69, 70, "earth loading")}

// Common objects of both meters: communication setup (table 12), image
// transfer (tables 13 to 15, Amd 1 item 24), disconnect control (table
// 16), push setups and scripts (table 3), smart meter objects (table 11),
// ESW and its filter (tables 8, 9; Amd 1 item 19), security setups.
func p2Common() []Object {
	o := []Object{
		{OBIS: "0.0.22.0.0.255", Class: ClassHDLCSetup, Attr: 1, Type: "octet-string", Group: GroupCommunication, Access: p2Read, Ref: "Part 2 table 12"},
		{OBIS: "0.0.25.0.0.255", Class: ClassTCPUDPSetup, Attr: 1, Type: "octet-string", Group: GroupCommunication, Access: p2Read, Ref: "Part 2 table 12"},
		{OBIS: "0.0.25.7.0.255", Class: ClassIPv6Setup, Attr: 1, Type: "octet-string", Group: GroupCommunication, Access: p2Read, Ref: "Part 2 table 12"},
		{OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Attr: 6, Type: "enum", Group: GroupProgrammable, Access: p2Firmware, Ref: "Part 2 table 13 (Amd 1 item 24), clause 9"},
		{OBIS: "0.0.15.0.2.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupProgrammable, Access: p2FWSched, Ref: "Part 2 table 14; table A13 note 10 (Amd 1 item 37)"},
		{OBIS: "0.0.96.3.10.255", Class: ClassDisconnect, Attr: 2, Type: "boolean", Group: GroupInstantaneous, Access: p2Instant, Ref: "Part 2 table 16; tables A1 and A14 (1: connected, 0: disconnected; Amd 1 item 38)"},
		{OBIS: "0.0.96.3.10.255", Class: ClassDisconnect, Attr: 3, Type: "enum", Group: GroupInstantaneous, Access: p2Read, Ref: "Part 2 table 16 (control_state)"},
		{OBIS: "0.0.96.3.10.255", Class: ClassDisconnect, Attr: 4, Type: "enum", Group: GroupProgrammable, Access: p2Settings, Ref: "Part 2 tables A13, A27 (enable/disable load limit function on class 70; control_mode, finding F-162)"},
		obj("1.0.1.9.0.255", ClassRegister, GroupInstantaneous, p2Instant, "Part 2 clause 6.1.4 table 7 (kWh import of the current billing period, pushed to the IHD)"),
		{OBIS: "0.0.17.0.0.255", Class: ClassLimiter, Attr: 3, Type: "double-long-unsigned", Unit: "kW", Group: GroupInstantaneous, Access: A("MR:R US:RW PUSH:R"), Ref: "Part 2 tables A1, A13, A14, A27 (threshold_active, Amd 1 item 25)"},
		{OBIS: EventStatusWord, Class: ClassData, Attr: 2, Type: "bit-string", Group: GroupPush, Access: A("MR:R US:R PUSH:R"), Ref: "Part 2 clause 6.1.5 table 9"},
		{OBIS: "0.0.94.91.26.255", Class: ClassData, Attr: 2, Type: "bit-string", Group: GroupPush, Access: p2Settings, Ref: "Part 2 clause 6.1.5 (Amd 1 item 19)"},
		{OBIS: "0.0.96.13.1.255", Class: ClassData, Attr: 2, Type: "octet-string", Group: GroupPush, Access: p2Display, Ref: "Part 2 clause 6.1.6 table 11"},
		{OBIS: "0.0.96.13.2.255", Class: ClassData, Attr: 2, Type: "octet-string", Group: GroupPush, Access: p2Display, Ref: "Part 2 clause 6.1.6 table 11"},
		{OBIS: "0.0.10.0.108.255", Class: ClassScriptTable, Attr: 1, Type: "octet-string", Group: GroupPush, Access: p2Read, Ref: "Part 2 table 3 (push script table)"},
		{OBIS: "0.0.15.0.4.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupPush, Access: p2Settings, Ref: "Part 2 table 3 (periodic push schedule)"},
	}
	for _, ps := range []string{PushPeriodic, PushToDisplay, PushFromDisplay, PushMeterDisplay, PushEvent} {
		acc := p2PushSetup
		if ps != PushPeriodic && ps != PushEvent {
			acc = p2DispPush
		}
		o = append(o, pushSetupObjects(ps, acc)...)
	}
	for e := 2; e <= 6; e++ {
		o = append(o, Object{OBIS: "0.0.43.0." + string(rune('0'+e)) + ".255", Class: ClassSecuritySetup, Attr: 2, Type: "enum",
			Group: GroupSecurity, Access: A("MR:R US:R PUSH:R FW:R IHD:R"), Ref: "Part 2 table 2, clause 7.2 b), 7.3.1 (Amd 1 item 22)"})
	}
	return o
}

// Programmable parameters of D1 (table A13 as amended by Amd 1 items 35
// to 37) and D2 (table A27, the same 21 rows).
func p2Programmable() []Object {
	o := []Object{
		{OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Group: GroupInstantaneous, Access: p2Clock, Ref: "Part 2 tables A13, A27"},
		obj("1.0.0.8.0.255", ClassData, GroupProgrammable, p2Settings, "Part 2 tables A13, A27 note 2 (seconds; 1800 default, 900)"),
		obj("1.0.0.8.4.255", ClassData, GroupProgrammable, p2Settings, "Part 2 tables A13, A27 note 2 (seconds; 1800 default, 900 or 3600)"),
		obj("1.0.0.8.5.255", ClassData, GroupProgrammable, p2Read, "Part 2 clauses 13, 19 (recording interval 2, fixed 24 h)"),
		{OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Group: GroupProgrammable, Access: p2Settings, Ref: "Part 2 tables A13, A27"},
		{OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Group: GroupProgrammable, Access: p2Settings, Ref: "Part 2 tables A13, A27 note 3"},
		obj("0.0.0.1.1.255", ClassData, GroupBilling, p2Read, "Part 1 clause 11.2 table 18"),
	}
	{
		o = append(o,
			obj("0.0.94.96.19.255", ClassData, GroupProgrammable, p2Settings, "Part 2 table A13 row ix note 6 (0: forwarded only, 1: net metering; Amd 1 items 36, 37)"),
			obj("0.0.94.96.20.255", ClassData, GroupProgrammable, p2Payment, "Part 2 table A13 row x note 7 (0: post-paid, 1: pre-paid)"),
			Object{OBIS: "0.0.94.96.21.255", Class: ClassData, Attr: 2, Type: "double-long-unsigned", Group: GroupProgrammable, Access: p2Payment, Ref: "Part 2 table A13 row xi note 8"},
			Object{OBIS: "0.0.94.96.22.255", Class: ClassData, Attr: 2, Type: "date-time", Group: GroupProgrammable, Access: p2Payment, Ref: "Part 2 table A13 row xii note 9"},
			Object{OBIS: "0.0.94.96.23.255", Class: ClassData, Attr: 2, Type: "double-long-unsigned", Group: GroupProgrammable, Access: p2Payment, Ref: "Part 2 table A13 row xiii note 8"},
			Object{OBIS: "0.0.94.96.24.255", Class: ClassData, Attr: 2, Type: "double-long", Group: GroupProgrammable, Access: p2Payment, Ref: "Part 2 table A13 row xiv note 8"},
			Object{OBIS: "0.0.94.96.25.255", Class: ClassData, Attr: 2, Type: "date-time", Group: GroupProgrammable, Access: p2Payment, Ref: "Part 2 table A13 row xv note 9"},
		)
	}
	return o
}

// Methods both meters provide.
func p2Methods() []Method {
	m := []Method{
		{Name: "set-clock", OBIS: ClockOBIS, Class: ClassClock, Attr: 2, Type: "date-time", Access: p2Clock, Ref: "Part 2 tables A13, A27"},
		{Name: "disconnect", OBIS: DisconnectControl, Class: ClassDisconnect, Method: 1, Type: "integer", Access: p2Exec, Ref: "Part 2 clause 10 table 16"},
		{Name: "reconnect", OBIS: DisconnectControl, Class: ClassDisconnect, Method: 2, Type: "integer", Access: p2Exec, Ref: "Part 2 clause 10 table 16"},
		{Name: "load-limit", OBIS: "0.0.17.0.0.255", Class: ClassLimiter, Attr: 3, Type: "double-long-unsigned", Access: A("MR:R US:RW PUSH:R"), Ref: "Part 2 tables A13, A27 (Amd 1 item 25)"},
		{Name: "billing-reset", OBIS: "0.0.10.0.1.255", Class: ClassScriptTable, Method: 1, Type: "long-unsigned", Access: p2Exec, Ref: "Part 2 table A13 row xxi (Amd 1 item 36); Part 1 clause 10.4"},
		{Name: "billing-dates", OBIS: "0.0.15.0.0.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p2Settings, Ref: "Part 2 tables A13, A27"},
		{Name: "demand-integration-period", OBIS: "1.0.0.8.0.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p2Settings, Ref: "Part 2 tables A13, A27"},
		{Name: "profile-capture-period", OBIS: "1.0.0.8.4.255", Class: ClassData, Attr: 2, Type: "long-unsigned", Access: p2Settings, Ref: "Part 2 tables A13, A27"},
		{Name: "tou-calendar-name", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 6, Type: "octet-string", Access: p2Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-seasons", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 7, Type: "array", Access: p2Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-weeks", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 8, Type: "array", Access: p2Settings, Ref: "Part 1 clause 9.9"},
		{Name: "tou-days", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 9, Type: "array", Access: p2Settings, Ref: "Part 1 clauses 9.7 to 9.9"},
		{Name: "tou-activation", OBIS: "0.0.13.0.0.255", Class: ClassActivityCalendar, Attr: 10, Type: "date-time", Access: p2Settings, Ref: "Part 1 clause 9.9"},
		{Name: "event-status-filter", OBIS: "0.0.94.91.26.255", Class: ClassData, Attr: 2, Type: "bit-string", Access: p2Settings, Ref: "Part 2 clause 6.1.5 (Amd 1 item 19)"},
		{Name: "reader-password", OBIS: "0.0.40.0.2.255", Class: ClassAssociationLN, Attr: 7, Type: "octet-string", Access: A("US:W"), Ref: "Part 2 table A13 row xvi (Amd 1 item 36)"},
		{Name: "hls-secret", OBIS: "0.0.40.0.3.255", Class: ClassAssociationLN, Method: 2, Type: "octet-string", Access: p2Exec, Ref: "Part 2 table A13 row xvii"},
		{Name: "firmware-hls-secret", OBIS: "0.0.40.0.5.255", Class: ClassAssociationLN, Method: 2, Type: "octet-string", Access: p2Exec, Ref: "Part 2 table A13 row xvii"},
		{Name: "global-key-transfer", OBIS: "0.0.43.0.3.255", Class: ClassSecuritySetup, Method: 2, Type: "array", Access: A("US:X FW:X"), Ref: "Part 2 clause 7.3.1 (Amd 1 item 22), table A13 row xviii note 10"},
		{Name: "image-transfer-initiate", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 1, Type: "structure", Access: p2Firmware, Ref: "Part 2 clause 9 table 13"},
		{Name: "image-block-transfer", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 2, Type: "structure", Access: p2Firmware, Ref: "Part 2 clause 9 table 13"},
		{Name: "image-verify", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 3, Type: "integer", Access: p2Firmware, Ref: "Part 2 clause 9 table 13"},
		{Name: "image-activate", OBIS: "0.0.44.0.0.255", Class: ClassImageTransfer, Method: 4, Type: "integer", Access: p2Firmware, Ref: "Part 2 clause 9 table 13"},
		{Name: "image-activation-time", OBIS: "0.0.15.0.2.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p2FWSched, Ref: "Part 2 table 14; table A13 note 10"},
		{Name: "periodic-push-schedule", OBIS: "0.0.15.0.4.255", Class: ClassSingleAction, Attr: 4, Type: "array", Access: p2Settings, Ref: "Part 2 table 3"},
		{Name: "message-to-display", OBIS: "0.0.96.13.1.255", Class: ClassData, Attr: 2, Type: "octet-string", Access: p2Display, Ref: "Part 2 clause 6.1.6 table 11 (up to 128 bytes)"},
		{Name: "message-from-display", OBIS: "0.0.96.13.2.255", Class: ClassData, Attr: 2, Type: "octet-string", Access: p2Display, Ref: "Part 2 clause 6.1.6 table 11 (up to 128 bytes)"},
		{Name: "load-limit-function", OBIS: DisconnectControl, Class: ClassDisconnect, Attr: 4, Type: "enum", Access: p2Settings, Ref: "Part 2 tables A13, A27 (enable/disable load limit function; finding F-162)"},
	}
	{
		m = append(m,
			Method{Name: "metering-mode", OBIS: "0.0.94.96.19.255", Class: ClassData, Attr: 2, Type: "unsigned", Access: p2Settings, Ref: "Part 2 table A13 row ix note 6 (Amd 1)"},
			Method{Name: "payment-mode", OBIS: "0.0.94.96.20.255", Class: ClassData, Attr: 2, Type: "unsigned", Access: p2Payment, Ref: "Part 2 table A13 row x note 7 (Amd 1)"},
			Method{Name: "last-recharge-amount", OBIS: "0.0.94.96.21.255", Class: ClassData, Attr: 2, Type: "double-long-unsigned", Access: p2Payment, Ref: "Part 2 table A13 row xi note 8 (Amd 1)"},
			Method{Name: "last-recharge-time", OBIS: "0.0.94.96.22.255", Class: ClassData, Attr: 2, Type: "date-time", Access: p2Payment, Ref: "Part 2 table A13 row xii note 9 (Amd 1)"},
			Method{Name: "total-amount-at-last-recharge", OBIS: "0.0.94.96.23.255", Class: ClassData, Attr: 2, Type: "double-long-unsigned", Access: p2Payment, Ref: "Part 2 table A13 row xiii note 8 (Amd 1)"},
			Method{Name: "current-balance", OBIS: "0.0.94.96.24.255", Class: ClassData, Attr: 2, Type: "double-long", Access: p2Payment, Ref: "Part 2 table A13 row xiv note 8 (Amd 1)"},
			Method{Name: "current-balance-time", OBIS: "0.0.94.96.25.255", Class: ClassData, Attr: 2, Type: "date-time", Access: p2Payment, Ref: "Part 2 table A13 row xv note 9 (Amd 1)"},
		)
	}
	return m
}

// Nameplate (tables A12 and A26) and its profile.
func p2Nameplate(meterType string) []Object {
	return []Object{
		obj("0.0.96.1.0.255", ClassData, GroupNameplate, p2Serial, "Part 2 tables A12, A26"),
		obj("0.0.96.1.2.255", ClassData, GroupNameplate, A("MR:R US:R PUSH:R"), "Part 2 tables A12, A26 (FLAG ID and serial number)"),
		obj("0.0.96.1.1.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26"),
		obj("1.0.0.2.0.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26"),
		obj("0.0.94.91.9.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26 ("+meterType+")"),
		obj("0.0.94.91.11.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26"),
		obj("0.0.94.91.12.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26 (Ib-Imax)"),
		obj("0.0.96.1.4.255", ClassData, GroupNameplate, p2Read, "Part 2 tables A12, A26 (yyyy)"),
	}
}

var p2NameplateCols = regs("0.0.96.1.0.255", "0.0.96.1.2.255", "0.0.96.1.1.255", "1.0.0.2.0.255", "0.0.94.91.9.255",
	"0.0.94.91.11.255", "0.0.94.91.12.255", "0.0.96.1.4.255")

func dataCols(cs []Column) []Column {
	for i := range cs {
		cs[i].Class = ClassData
	}
	return cs
}

// D1: single-phase whole current (clause 11).
var (
	p2D1Instant = cat(
		[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
		regs("1.0.12.7.0.255", "1.0.11.7.0.255", "1.0.91.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
			"1.0.1.7.0.255", "1.0.1.8.0.255", "1.0.9.8.0.255"),
		mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
		regs("0.0.94.91.14.255", "0.0.94.91.0.255", "0.0.0.1.0.255", "0.0.96.2.0.255", "1.0.2.8.0.255", "1.0.10.8.0.255"),
		[]Column{{OBIS: DisconnectControl, Class: ClassDisconnect}, {OBIS: "0.0.17.0.0.255", Class: ClassLimiter, Attr: 3}},
	)
	// Table A2 with the average current of Amd 1 item 27.
	p2D1Block = clockThen("1.0.12.27.0.255", "1.0.1.29.0.255", "1.0.9.29.0.255", "1.0.2.29.0.255", "1.0.10.29.0.255", "1.0.11.27.0.255")
	// Table A3 with the clock of Amd 1 item 26.
	p2D1Daily   = clockThen("1.0.2.8.0.255", "1.0.10.8.0.255", "1.0.1.8.0.255", "1.0.9.8.0.255")
	p2D1Billing = cat(
		regs("0.0.0.1.2.255", "1.0.13.0.0.255", "1.0.1.8.0.255"), regs(tz("1.0.1.8", 4)...),
		regs("1.0.9.8.0.255"), regs(tz("1.0.9.8", 4)...),
		mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
		regs("0.0.94.91.13.255", "1.0.2.8.0.255", "1.0.10.8.0.255"),
	)
	// Table A11 with the tamper count of Amd 1 item 34.
	p2D1Capture = []string{"1.0.94.91.14.255", "1.0.12.7.0.255", "1.0.13.7.0.255", "1.0.1.8.0.255", "0.0.94.91.0.255"}
)

func p2D1Events() []EventLog {
	return []EventLog{
		eventLog(0, span(7, 10), p2Events, "Part 2 clause 15, table B1 (Amd 1 items 31, 32), capture table A11", p2D1Capture...),
		eventLog(1, []int{51, 52, 67, 68, 69, 70}, p2Events, "Part 2 clause 15, table A5 as replaced by Amd 1 item 33", p2D1Capture...),
		eventLog(2, []int{101, 102}, p2Events, "Part 2 clause 15, table A6"),
		eventLog(3, join(span(151, 155), span(157, 166)), p2Events, "Part 2 clause 15, table A7 (Amd 1 item 29; 156 unused)"),
		eventLog(4, join(span(201, 204), span(207, 216)), p2Events, "Part 2 clause 15, table A8 (Amd 1 item 30)", p2D1Capture...),
		eventLog(5, []int{251}, p2Events, "Part 2 clause 15, table A9"),
		eventLog(6, []int{301, 302}, p2Events, "Part 2 clause 15, table A10"),
	}
}

// D2: three-phase whole current (clause 17).
var (
	p2D2Instant = cat(
		[]Column{{OBIS: ClockOBIS, Class: ClassClock}},
		regs("1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255", "1.0.72.7.0.255",
			"1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.13.7.0.255", "1.0.14.7.0.255", "1.0.9.7.0.255",
			"1.0.1.7.0.255", "1.0.3.7.0.255", "0.0.96.7.0.255", "0.0.94.91.8.255", "0.0.94.91.0.255", "0.0.0.1.0.255",
			"0.0.96.2.0.255", "0.0.0.1.2.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.9.8.0.255", "1.0.10.8.0.255"),
		mds("1.0.1.6.0.255", "1.0.9.6.0.255"),
		[]Column{{OBIS: DisconnectControl, Class: ClassDisconnect}, {OBIS: "0.0.17.0.0.255", Class: ClassLimiter, Attr: 3}},
		regs("1.0.5.8.0.255", "1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255"),
	)
	// Table A15 without rows ix and x (Amd 1 item 41).
	p2D2Block = clockThen("1.0.31.27.0.255", "1.0.51.27.0.255", "1.0.71.27.0.255", "1.0.32.27.0.255", "1.0.52.27.0.255",
		"1.0.72.27.0.255", "1.0.1.29.0.255", "1.0.9.29.0.255", "1.0.2.29.0.255", "1.0.10.29.0.255")
	p2D2Daily   = clockThen("1.0.1.8.0.255", "1.0.9.8.0.255", "1.0.2.8.0.255", "1.0.10.8.0.255")
	p2D2Billing = cat(
		regs("0.0.0.1.2.255", "1.0.13.0.0.255", "1.0.1.8.0.255"), regs(tz("1.0.1.8", 8)...),
		regs("1.0.9.8.0.255"), regs(tz("1.0.9.8", 8)...),
		mds("1.0.1.6.0.255"), mds(tz("1.0.1.6", 8)...), mds("1.0.9.6.0.255"), mds(tz("1.0.9.6", 8)...),
		regs("0.0.94.91.13.255", "1.0.2.8.0.255", "1.0.10.8.0.255"),
		regs("1.0.5.8.0.255", "1.0.6.8.0.255", "1.0.7.8.0.255", "1.0.8.8.0.255"),
	)
	// Table A25 with row iii corrected by Amd 1 item 48 and the tamper
	// count the amended list carries.
	p2D2Capture = []string{"1.0.31.7.0.255", "1.0.51.7.0.255", "1.0.71.7.0.255", "1.0.32.7.0.255", "1.0.52.7.0.255",
		"1.0.72.7.0.255", "1.0.33.7.0.255", "1.0.53.7.0.255", "1.0.73.7.0.255", "1.0.1.8.0.255", "1.0.2.8.0.255", "0.0.94.91.0.255"}
)

func p2D2Events() []EventLog {
	return []EventLog{
		eventLog(0, span(1, 12), p2Events, "Part 2 clause 21, table A18, capture table A25", p2D2Capture...),
		eventLog(1, join(span(51, 56), span(63, 68)), p2Events, "Part 2 clause 21, table A19", p2D2Capture...),
		eventLog(2, []int{101, 102}, p2Events, "Part 2 clause 21, table A20"),
		eventLog(3, join(span(151, 155), span(157, 166)), p2Events, "Part 2 clause 21, table A21 (Amd 1 item 46)"),
		eventLog(4, join(span(201, 206), span(209, 216)), p2Events, "Part 2 clause 21, table A22 (Amd 1 item 47)", p2D2Capture...),
		eventLog(5, []int{251}, p2Events, "Part 2 clause 21, table A23"),
		eventLog(6, []int{301, 302}, p2Events, "Part 2 clause 21, table A24"),
	}
}

func p2Spec(id, category, title string, phases int, instant, block, daily, billing []Column, events []EventLog, capture []string, esw []ESWBit, meterType string, ref string) *Spec {
	s := &Spec{ID: id, Title: title, Part: 2, Category: category, Phases: phases, Ref: ref,
		Associations: p2Associations, Suite: 0, Ciphering: "service-specific (dedicated key); push: general-glo"}
	s.Objects = append(s.Objects, p2Nameplate(meterType)...)
	s.Objects = append(s.Objects, p2Programmable()...)
	inst := objs(instant, GroupInstantaneous, p2Instant, ref)
	for i := range inst {
		if inst[i].OBIS == ClockOBIS {
			inst[i].Access = p2Clock
		}
	}
	s.Objects = append(s.Objects, inst...)
	s.Objects = append(s.Objects, p2Common()...)
	s.Objects = append(s.Objects, objs(block[1:], GroupBlockLoad, p2Read, ref)...)
	s.Objects = append(s.Objects, objs(billing, GroupBilling, p2Read, ref)...)
	s.Profiles = []Profile{
		{OBIS: "1.0.94.91.0.255", Group: GroupInstantaneous, Capture: instant, Scaler: "1.0.94.91.3.255", Access: p2Instant, Ref: ref},
		scalerProfile("1.0.94.91.3.255", instant, GroupScalers, p2Instant, ref),
		{OBIS: "1.0.99.1.0.255", Group: GroupBlockLoad, Period: 30 * time.Minute, Capture: block, Scaler: "1.0.94.91.4.255", Access: p2Read, Ref: ref + "; capture period 1800 s by default"},
		scalerProfile("1.0.94.91.4.255", block, GroupScalers, p2Read, ref),
		{OBIS: "1.0.99.2.0.255", Group: GroupDailyLoad, Period: 24 * time.Hour, Capture: daily, Scaler: "1.0.94.91.5.255", Access: p2Read, Ref: ref},
		scalerProfile("1.0.94.91.5.255", daily, GroupScalers, p2Read, ref),
		{OBIS: "1.0.98.1.0.255", Group: GroupBilling, Entries: 6, Capture: billing, Scaler: "1.0.94.91.6.255", Access: p2Read, Ref: ref},
		scalerProfile("1.0.94.91.6.255", billing, GroupScalers, p2Read, ref),
		{OBIS: "0.0.94.91.10.255", Group: GroupNameplate, Entries: 1, Capture: dataCols(append([]Column(nil), p2NameplateCols...)), Access: p2Read, Ref: ref},
		scalerProfile("1.0.94.91.7.255", regs(capture...), GroupEvents, p2Events, ref),
	}
	s.Events = events
	s.Objects = append(s.Objects, eventCodeObjects(events, p2Events, "Part 2 clauses 15, 21 (event code objects)")...)
	s.ESW = append(append([]ESWBit(nil), esw...), p2ESWCommon...)
	s.Push = p2Push(instant)
	s.Methods = p2Methods()
	s.dedupe()
	return s
}

func init() {
	register(p2Spec("part2-1ph", "D1", "IS 15959 Part 2 single-phase whole-current smart meter (D1)", 1,
		p2D1Instant, p2D1Block, p2D1Daily, p2D1Billing, p2D1Events(), p2D1Capture, p2ESW1, "6: single-phase whole-current smart meter",
		"Part 2 clause 11, tables A1 to A13 and B1 as amended"))
	register(p2Spec("part2-3ph", "D2", "IS 15959 Part 2 three-phase whole-current smart meter (D2)", 3,
		p2D2Instant, p2D2Block, p2D2Daily, p2D2Billing, p2D2Events(), p2D2Capture, p2ESW3, "7: three-phase whole-current smart meter",
		"Part 2 clause 17, tables A14 to A27 as amended"))
}

// pushSetupObjects lists a push setup's settable attributes (figure 2:
// push_object_list, send_destination_and_method, communication_window,
// randomisation_start_interval, number_of_retries, repetition_delay).
func pushSetupObjects(obis string, acc Rights) []Object {
	ref := "Part 2 clause 6, figure 2, table 3 (Amd 1 items 6 to 17)"
	return []Object{
		{OBIS: obis, Class: ClassPushSetup, Attr: 2, Type: "array", Group: GroupPush, Access: acc, Ref: ref},
		{OBIS: obis, Class: ClassPushSetup, Attr: 3, Type: "structure", Group: GroupPush, Access: acc, Ref: ref},
		{OBIS: obis, Class: ClassPushSetup, Attr: 4, Type: "array", Group: GroupPush, Access: acc, Ref: ref},
		{OBIS: obis, Class: ClassPushSetup, Attr: 5, Type: "long-unsigned", Group: GroupPush, Access: acc, Ref: ref},
		{OBIS: obis, Class: ClassPushSetup, Attr: 6, Type: "unsigned", Group: GroupPush, Access: acc, Ref: ref},
		{OBIS: obis, Class: ClassPushSetup, Attr: 7, Type: "long-unsigned", Group: GroupPush, Access: acc, Ref: ref},
	}
}
