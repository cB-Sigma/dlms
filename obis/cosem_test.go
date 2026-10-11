package obis_test

import (
	"slices"
	"testing"

	"github.com/cB-Sigma/dlms/obis"
)

// Covers: SIG-IPE-1243
func TestCOSEMAbstractObjects(t *testing.T) {
	// IEC 62056-6-2:2023 6.2.5 to 6.2.41: the COSEM objects of A 0, C 0 to
	// 89, with their names and interface classes.
	for code, want := range map[string]struct {
		name    string
		classes []uint16
	}{
		"0.0.1.0.0.255":     {"clock", []uint16{8}},
		"0.0.1.1.0.255":     {"unixClock", []uint16{1}},
		"0.0.1.6.0.255":     {"weeksClock", []uint16{1}},
		"0.0.2.1.0.255":     {"autoConnect", []uint16{29}},
		"0.0.10.0.0.255":    {"globalResetScript", []uint16{9}},
		"0.0.10.0.1.255":    {"billingScript", []uint16{9}},
		"0.0.10.0.100.255":  {"tariffScript", []uint16{9}},
		"0.0.10.0.108.255":  {"pushScript", []uint16{9}},
		"0.0.10.0.125.255":  {"broadcastScript", []uint16{9}},
		"0.0.11.0.0.255":    {"specialDaysTable", []uint16{11}},
		"0.0.12.0.1.255":    {"scheduleE1", []uint16{10}},
		"0.0.13.0.0.255":    {"activityCalendar", []uint16{20}},
		"0.0.14.0.0.255":    {"registerActivation", []uint16{6}},
		"0.0.15.0.0.255":    {"billingSchedule", []uint16{22}},
		"0.0.15.0.4.255":    {"pushSchedule", []uint16{22}},
		"0.0.16.0.1.255":    {"registerMonitorE1", []uint16{21}},
		"0.0.16.1.9.255":    {"alarmMonitor10", []uint16{21}},
		"0.0.16.2.0.255":    {"parameterMonitor", []uint16{65}},
		"0.0.17.0.0.255":    {"limiter", []uint16{71}},
		"0.0.18.0.0.255":    {"arrayManager", []uint16{123}},
		"0.0.19.0.0.255":    {"account0", []uint16{111}},
		"0.0.19.11.2.255":   {"credit1E2", []uint16{112}},
		"0.0.19.40.0.255":   {"tokenGateway0E0", []uint16{115}},
		"0.0.19.52.2.255":   {"maxVendLimit2", []uint16{1}},
		"0.0.20.0.1.255":    {"electricalPortSetup", []uint16{19}},
		"0.0.21.0.5.255":    {"readoutProfile1", []uint16{7}},
		"0.0.22.0.0.255":    {"hdlcSetup", []uint16{23}},
		"0.0.23.3.9.255":    {"twistedPairReadout7", []uint16{7}},
		"0.0.24.1.0.255":    {"mbusClient", []uint16{72}},
		"0.0.24.2.3.255":    {"mbusValue3", []uint16{4}},
		"0.0.31.0.0.255":    {"wirelessModeQChannel", []uint16{73}},
		"0.0.25.1.0.255":    {"ipv4Setup", []uint16{42}},
		"0.0.25.9.0.255":    {"pushSetup", []uint16{40}},
		"0.2.25.9.0.255":    {"pushSetupCh2", []uint16{40}},
		"0.0.25.11.0.255":   {"lteMonitoring", []uint16{151}},
		"0.0.25.15.0.255":   {"schcLoRaWanDiagnostic", []uint16{129}},
		"0.0.26.6.0.255":    {"sfskReportingSystems", []uint16{56}},
		"0.0.27.2.0.255":    {"llcType3Setup", []uint16{59}},
		"0.0.28.7.0.255":    {"primeApplicationId", []uint16{86}},
		"0.0.29.2.0.255":    {"g3AdaptationSetup", []uint16{92}},
		"0.0.30.4.1.255":    {"zigbeeTunnelSetupE1", []uint16{105}},
		"0.0.32.3.0.255":    {"iso14908Diagnostic", []uint16{133}},
		"0.0.33.3.0.255":    {"hsplcHdlcSsasSetup", []uint16{143}},
		"0.0.34.3.0.255":    {"mplDiagnostic", []uint16{98}},
		"0.0.40.0.0.255":    {"currentAssociation", []uint16{12, 15}},
		"0.0.40.0.3.255":    {"association3", []uint16{12, 15}},
		"0.0.41.0.0.255":    {"sapAssignment", []uint16{17}},
		"0.0.42.0.0.255":    {"logicalDeviceName", []uint16{1, 3}},
		"0.0.43.0.2.255":    {"securitySetupE2", []uint16{64}},
		"0.0.43.1.2.255":    {"invocationCounterE2", []uint16{1, 3}},
		"0.0.43.2.0.255":    {"dataProtection", []uint16{30}},
		"0.0.44.0.0.255":    {"imageTransfer", []uint16{18}},
		"0.0.44.1.0.255":    {"functionControl", []uint16{122}},
		"0.0.44.2.0.255":    {"commPortProtection", []uint16{124}},
		"0.0.65.0.5.255":    {"standardTable5", []uint16{26}},
		"0.0.65.1.0.255":    {"standardTable128", []uint16{26}},
		"0.0.65.31.127.255": {"manufacturerTable2047", []uint16{26}},
		"0.0.65.48.0.255":   {"pendingManufacturerTable0", []uint16{26}},
		"0.0.66.0.0.255":    {"compactData", []uint16{62}},
		// 6.2.42 to 6.2.64: classes of the IEC 62056-6-1 Table 8 and 9 objects.
		"0.0.96.1.0.255":    {"deviceId1", []uint16{1, 3, 4}},
		"0.0.96.1.255.255":  {"completeDeviceId", []uint16{7, 61}},
		"0.0.96.3.10.255":   {"disconnectControl", []uint16{70}},
		"0.0.96.3.25.255":   {"arbitrator6", []uint16{68}},
		"0.0.96.5.0.255":    {"internalOperatingStatus", []uint16{1, 3, 4, 63, 7, 61}},
		"0.0.96.10.1.255":   {"statusRegister1", []uint16{1, 3, 4, 63}},
		"0.0.96.9.0.255":    {"ambientTemperature", []uint16{3, 4}},
		"0.0.97.97.255.255": {"errorRegisters", []uint16{7, 61}},
		"0.0.97.98.255.255": {"alarmRegisters", []uint16{7, 61}},
		"0.0.99.98.0.255":   {"eventLog", []uint16{7}},
	} {
		i := describe(t, code)
		if i.Kind != obis.Standard || i.Name != want.name || !slices.Equal(i.Classes, want.classes) {
			t.Errorf("%s: %s %q %v (%s), want %q %v", code, i.Kind, i.Name, i.Classes, i.Problem, want.name, want.classes)
		}
	}
	// Codes clause 6 does not list are reserved (6.1): C gaps of Table 52,
	// unlisted D and E of listed C.
	for _, code := range []string{"0.0.3.0.0.255", "0.0.9.0.0.255", "0.0.35.0.0.255", "0.0.45.0.0.255", "0.0.64.0.0.255",
		"0.0.67.0.0.255", "0.0.89.0.0.255", "0.0.1.7.0.255", "0.0.2.0.1.255", "0.0.10.0.2.255", "0.0.10.0.112.255",
		"0.0.15.0.8.255", "0.0.16.1.10.255", "0.0.19.30.0.255", "0.0.20.0.2.255", "0.0.25.8.0.255", "0.0.26.4.0.255",
		"0.1.40.0.0.255", "0.0.40.1.0.255", "0.1.42.0.0.255", "0.0.65.64.0.255", "0.0.1.0.0.3"} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s accepted as %s %q, want reserved", code, i.Kind, i.Name)
		}
	}
	// One code, objects of different classes (6.2.19, 6.2.21): the class decides.
	c := obis.MustParse("0.0.21.0.1.255")
	if n := obis.NameFor(c, 7); n != "displayReadout" {
		t.Errorf("0.0.21.0.1.255 class 7 → %q", n)
	}
	if n := obis.NameFor(c, 1); n != "readoutParametersE1" {
		t.Errorf("0.0.21.0.1.255 class 1 → %q", n)
	}
	if n := obis.NameFor(obis.MustParse("0.0.23.3.2.255"), 1); n != "twistedPairReadoutParametersE2" {
		t.Errorf("0.0.23.3.2.255 class 1 → %q", n)
	}
	if n := obis.NameFor(c, 99); n != "displayReadout" {
		t.Errorf("0.0.21.0.1.255 unknown class → %q, want the first row", n)
	}
}

// Covers: SIG-IPE-1244
func TestCOSEMElectricityClasses(t *testing.T) {
	// IEC 62056-6-2:2023 6.3.1 Table 53, 6.3.2 to 6.3.7, Tables 55 and 56.
	for code, want := range map[string][]uint16{
		"1.0.1.8.0.255":     {3, 4},        // time integral
		"1.0.32.7.0.255":    {3},           // instantaneous
		"1.0.1.6.0.255":     {3, 4, 7},     // maximum
		"1.0.1.4.0.255":     {5, 3, 21},    // current average
		"1.0.1.5.0.255":     {3, 5, 21},    // last average
		"1.0.12.35.0.0":     {1, 3, 4, 21}, // over limit threshold
		"1.0.12.36.0.255":   {1, 3, 4},     // occurrence counter
		"1.0.0.0.255.255":   {7, 61},       // electricity ID-s
		"1.0.0.4.2.255":     {3, 4},        // CT ratio
		"1.0.0.8.4.255":     {1, 3, 4},     // recording interval
		"1.0.0.11.1.255":    {1, 3},        // measurement algorithm
		"1.0.96.1.255.255":  {7, 61},       // metering point ID-s
		"1.0.96.10.2.255":   {1, 3, 4, 63}, // electricity status
		"1.0.98.1.0.255":    {7},           // billing period data
		"1.0.99.1.0.255":    {7},           // load profile
		"1.0.12.32.255.255": {61},          // UNIPEDE register table
	} {
		if i := describe(t, code); !slices.Equal(i.Classes, want) {
			t.Errorf("%s: classes %v (%s %s), want %v", code, i.Classes, i.Kind, i.Problem, want)
		}
	}
	// Table 55 and 56 carry harmonic E with threshold, average and time
	// threshold D codes, and time thresholds numbered by F (F-266).
	for code, class := range map[string]string{
		"1.0.32.35.5.255": "harmonic 5", "1.0.12.4.124.255": "total harmonic distortion", "1.0.31.43.3.0": "harmonic 3",
		"1.0.101.4.7.255": "harmonic 7", "1.0.1.4.7.255": "rate 7", "1.0.101.8.7.255": "rate 7",
	} {
		if i := describe(t, code); !i.Valid() || i.Class != class {
			t.Errorf("%s: %q (%s), want %q", code, i.Class, i.Problem, class)
		}
	}
	if i := describe(t, "1.0.12.44.0.2"); i.Period != "threshold 3" {
		t.Errorf("time threshold F: %+v", i)
	}
}
