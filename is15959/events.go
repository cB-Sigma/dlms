package is15959

import (
	"fmt"
	"sort"
)

// eventNames names every event code the three parts define (our wording).
// Occurrence codes are odd and restorations even where a pair exists.
var eventNames = map[int]string{
	// Voltage related (Part 1 table 32, Part 2 table A6/A19, Part 3 table 5/18).
	1: "R-phase voltage missing", 2: "R-phase voltage restored",
	3: "Y-phase voltage missing", 4: "Y-phase voltage restored",
	5: "B-phase voltage missing", 6: "B-phase voltage restored",
	7: "over-voltage", 8: "over-voltage cleared",
	9: "low voltage", 10: "low voltage cleared",
	11: "voltage unbalance", 12: "voltage unbalance cleared",
	// Current related (Part 1 table 33).
	51: "R-phase current reversed", 52: "R-phase current reversal cleared",
	53: "Y-phase current reversed", 54: "Y-phase current reversal cleared",
	55: "B-phase current reversed", 56: "B-phase current reversal cleared",
	57: "R-phase CT open", 58: "R-phase CT open cleared",
	59: "Y-phase CT open", 60: "Y-phase CT open cleared",
	61: "B-phase CT open", 62: "B-phase CT open cleared",
	63: "current unbalance", 64: "current unbalance cleared",
	65: "current bypass", 66: "current bypass cleared",
	67: "over-current", 68: "over-current cleared",
	69: "earth loading", 70: "earth loading cleared",
	// Power related (Part 1 table 34).
	101: "power failure", 102: "power restored",
	// Transaction related (Part 1 table 35, Part 3 table 8).
	151: "clock changed", 152: "demand integration period changed", 153: "profile capture period changed",
	154: "billing dates changed", 155: "activity calendar changed", 156: "RS-485 address changed",
	157: "new firmware activated", 158: "load limit changed", 159: "load limit function enabled",
	160: "load limit function disabled", 161: "meter reader LLS secret changed", 162: "utility settings HLS key changed",
	163: "firmware HLS key changed", 164: "global key changed", 165: "ESW filter changed",
	166: "maximum demand reset", 167: "metering mode changed", 168: "push setup changed",
	169: "image activation schedule changed", 170: "push schedule changed",
	177: "changed to forwarded-only metering", 178: "changed to import-export metering",
	// Other (Part 1 table 36, Part 2 tables A8/A22 as amended, Part 3 table 9).
	201: "magnetic influence", 202: "magnetic influence cleared",
	203: "neutral disturbance", 204: "neutral disturbance cleared",
	205: "low power factor", 206: "low power factor cleared",
	207: "single-wire operation", 208: "single-wire operation cleared",
	209: "communication module removed", 210: "communication module refitted",
	211: "changed to post-paid mode", 212: "changed to pre-paid mode",
	213: "changed to forwarded-only metering", 214: "changed to import-export metering",
	215: "overload", 216: "overload cleared",
	// Non-rollover (Part 1 table 37).
	251: "meter cover opened",
	// Control (Part 1 table 38).
	301: "load disconnected", 302: "load connected",
}

// CodeName names an event code from any part.
func CodeName(code int) string {
	if n, ok := eventNames[code]; ok {
		return n
	}
	return fmt.Sprintf("event %d", code)
}

func evs(codes ...int) []Event {
	out := make([]Event, len(codes))
	for i, c := range codes {
		out[i] = Event{Code: c, Name: CodeName(c)}
	}
	return out
}

func span(from, to int) []int {
	var out []int
	for c := from; c <= to; c++ {
		out = append(out, c)
	}
	return out
}

func join(parts ...[]int) []int {
	var out []int
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// eventLog builds an event log e (0.0.99.98.e.255) with its code object
// (0.0.96.11.e.255) and capture objects: the clock, the code, then the
// listed registers.
func eventLog(e int, codes []int, access Rights, ref string, capture ...string) EventLog {
	codeOBIS := fmt.Sprintf("0.0.96.11.%d.255", e)
	cols := []Column{{OBIS: ClockOBIS, Class: ClassClock}, {OBIS: codeOBIS, Class: ClassData}}
	for _, c := range capture {
		cls := uint16(ClassRegister)
		if c == "0.0.94.91.0.255" || c == "0.0.96.7.0.255" {
			cls = ClassData
		}
		cols = append(cols, Column{OBIS: c, Class: cls})
	}
	return EventLog{
		Profile: Profile{OBIS: fmt.Sprintf("0.0.99.98.%d.255", e), Group: GroupEvents, Capture: cols,
			Scaler: "1.0.94.91.7.255", Access: access, Ref: ref},
		CodeOBIS: codeOBIS,
		Codes:    evs(codes...),
	}
}

// eventCodeObjects lists the event code objects of logs.
func eventCodeObjects(logs []EventLog, access Rights, ref string) []Object {
	var out []Object
	for _, l := range logs {
		out = append(out, Object{OBIS: l.CodeOBIS, Class: ClassData, Type: "long-unsigned", Group: GroupEvents, Access: access, Ref: ref})
	}
	return out
}

// EventInfo describes an event code for the readers of the logs (the
// console, the reports, IS 16444 checks): a stable key the console and the
// reports label it by, the log compartment it belongs to, whether it marks
// a condition starting or ending, and our tamper classification.
//
// Neither IS 16444 nor IS 15959 says which codes are tampers (IS 15959
// keeps a tamper count without listing what it counts; finding F-1921).
// Ours: supply and wiring interference and access to the meter (missing
// potential, voltage and current unbalance, current reversal, CT open,
// current bypass, earth loading, magnet, neutral disturbance, single-wire
// operation, communication module removal, cover open). Supply quality
// (over and low voltage, over-current, low power factor, overload), power,
// transaction and control events are not tampers.
type EventInfo struct {
	Code      int
	Key       string // camel case; codes with the same meaning share a key (177 and 213)
	Name      string // CodeName
	Category  string // voltage, current, power, transaction, other, nonRollover, control
	Kind      string // occurrence, restoration or single
	Condition string // the occurrence's key for both codes of a pair; Key otherwise
	Pair      int    // the other code of an occurrence and restoration pair (0: none)
	Tamper    bool
}

// Event categories: the IS 15959 event log compartments.
const (
	CategoryVoltage     = "voltage"
	CategoryCurrent     = "current"
	CategoryPower       = "power"
	CategoryTransaction = "transaction"
	CategoryOther       = "other"
	CategoryNonRollover = "nonRollover"
	CategoryControl     = "control"
)

// Event kinds.
const (
	KindOccurrence  = "occurrence"
	KindRestoration = "restoration"
	KindSingle      = "single"
)

var eventInfo = func() map[int]EventInfo {
	out := map[int]EventInfo{}
	pair := func(occ int, key, cat string, tamper bool) {
		out[occ] = EventInfo{Code: occ, Key: key, Name: CodeName(occ), Category: cat, Kind: KindOccurrence, Condition: key, Pair: occ + 1, Tamper: tamper}
		out[occ+1] = EventInfo{Code: occ + 1, Key: key + "Cleared", Name: CodeName(occ + 1), Category: cat, Kind: KindRestoration, Condition: key, Pair: occ, Tamper: tamper}
	}
	single := func(code int, key, cat string, tamper bool) {
		out[code] = EventInfo{Code: code, Key: key, Name: CodeName(code), Category: cat, Kind: KindSingle, Condition: key, Tamper: tamper}
	}
	pair(1, "voltageMissingL1", CategoryVoltage, true)
	pair(3, "voltageMissingL2", CategoryVoltage, true)
	pair(5, "voltageMissingL3", CategoryVoltage, true)
	pair(7, "overVoltage", CategoryVoltage, false)
	pair(9, "lowVoltage", CategoryVoltage, false)
	pair(11, "voltageUnbalance", CategoryVoltage, true)
	pair(51, "currentReversedL1", CategoryCurrent, true)
	pair(53, "currentReversedL2", CategoryCurrent, true)
	pair(55, "currentReversedL3", CategoryCurrent, true)
	pair(57, "ctOpenL1", CategoryCurrent, true)
	pair(59, "ctOpenL2", CategoryCurrent, true)
	pair(61, "ctOpenL3", CategoryCurrent, true)
	pair(63, "currentUnbalance", CategoryCurrent, true)
	pair(65, "currentBypass", CategoryCurrent, true)
	pair(67, "overCurrent", CategoryCurrent, false)
	pair(69, "earthLoading", CategoryCurrent, true)
	pair(101, "powerFailure", CategoryPower, false)
	for code, key := range map[int]string{
		151: "clockChanged", 152: "demandIntegrationPeriodChanged", 153: "profileCapturePeriodChanged",
		154: "billingDatesChanged", 155: "activityCalendarChanged", 156: "rs485AddressChanged",
		157: "firmwareActivated", 158: "loadLimitChanged", 159: "loadLimitEnabled", 160: "loadLimitDisabled",
		161: "readerSecretChanged", 162: "utilityKeyChanged", 163: "firmwareKeyChanged", 164: "globalKeyChanged",
		165: "eswFilterChanged", 166: "mdReset", 167: "meteringModeChanged", 168: "pushSetupChanged",
		169: "imageActivationScheduleChanged", 170: "pushScheduleChanged",
		177: "forwardedOnlyMetering", 178: "importExportMetering",
	} {
		single(code, key, CategoryTransaction, false)
	}
	pair(201, "magneticInfluence", CategoryOther, true)
	pair(203, "neutralDisturbance", CategoryOther, true)
	pair(205, "lowPowerFactor", CategoryOther, false)
	pair(207, "singleWireOperation", CategoryOther, true)
	pair(209, "commModuleRemoved", CategoryOther, true)
	single(211, "postPaidMode", CategoryOther, false)
	single(212, "prePaidMode", CategoryOther, false)
	single(213, "forwardedOnlyMetering", CategoryOther, false)
	single(214, "importExportMetering", CategoryOther, false)
	pair(215, "overload", CategoryOther, false)
	single(251, "coverOpened", CategoryNonRollover, true)
	single(301, "loadDisconnected", CategoryControl, false)
	single(302, "loadConnected", CategoryControl, false)
	return out
}()

// Info describes an event code; false for a code no part defines.
func Info(code int) (EventInfo, bool) {
	e, ok := eventInfo[code]
	return e, ok
}

// EventInfos lists every event code the three parts define, by code.
func EventInfos() []EventInfo {
	out := make([]EventInfo, 0, len(eventInfo))
	for c := range eventNames {
		out = append(out, eventInfo[c])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Keys of the event status word bits that are not an event code's
// occurrence (Part 2 table 10 as amended, bits 84 to 87).
const (
	KeyLoadSwitchChanged = "loadSwitchChanged"
	KeyLastGasp          = "lastGasp"
	KeyFirstBreath       = "firstBreath"
	KeyBillingReset      = "billingReset"
)

// ESWKey is the key of an event status word bit: its occurrence's
// condition, or one of the Key constants for bits 84 to 87.
func ESWKey(b ESWBit) string {
	switch {
	case b.Bit == BitLastGasp:
		return KeyLastGasp
	case b.Bit == BitFirstBreath:
		return KeyFirstBreath
	case b.Bit == 87:
		return KeyBillingReset
	case b.Occurrence == 301:
		return KeyLoadSwitchChanged
	}
	if e, ok := Info(b.Occurrence); ok {
		return e.Condition
	}
	return ""
}

// LabelKeys lists every key the console labels (event codes and event
// status word bits), sorted.
func LabelKeys() []string {
	seen := map[string]bool{KeyLoadSwitchChanged: true, KeyLastGasp: true, KeyFirstBreath: true, KeyBillingReset: true}
	for _, e := range eventInfo {
		seen[e.Key] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
