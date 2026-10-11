package obis_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/dlms/obis"
)

func describe(t *testing.T, s string) obis.Info {
	t.Helper()
	c, err := obis.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return obis.Describe(c)
}

// kinds checks the kind (and, when given, the owner) of each code.
func kinds(t *testing.T, want map[string]string) {
	t.Helper()
	for code, w := range want {
		kind, owner, _ := strings.Cut(w, "/")
		i := describe(t, code)
		if string(i.Kind) != kind || owner != "" && i.Owner != owner {
			t.Errorf("%s: kind %s owner %q (%s), want %s", code, i.Kind, i.Owner, i.Problem, w)
		}
	}
}

// Covers: SIG-IPE-1230
func TestValueGroupsAAndB(t *testing.T) {
	// 5.1 Table 3: media 0, 1, 4 to 9 and 15; 5.2 Table 4: B 0 to 64
	// channels, 65-127 utility, 128-199 manufacturer, 200-255 reserved.
	for code, medium := range map[string]string{
		"0.0.96.1.0.255": "abstract objects", "1.0.1.8.0.255": "electricity", "4.0.1.0.0.255": "heat cost allocator",
		"5.0.1.0.0.255": "thermal energy, cooling", "6.0.1.0.0.255": "thermal energy, heat", "7.0.3.0.0.255": "gas",
		"8.0.1.0.0.255": "cold water", "9.0.1.0.0.255": "hot water", "15.0.1.8.0.255": "other media",
	} {
		if i := describe(t, code); i.Medium != medium || !i.Valid() {
			t.Errorf("%s: medium %q valid %v, want %q", code, i.Medium, i.Valid(), medium)
		}
	}
	for _, code := range []string{"2.0.1.8.0.255", "3.0.1.8.0.255", "10.0.1.8.0.255", "14.0.1.8.0.255", "16.0.1.8.0.255", "255.0.1.8.0.255"} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s: medium %q accepted, want reserved", code, i.Medium)
		} else if err := obis.Validate(i.Code); !errors.Is(err, obis.ErrReserved) {
			t.Errorf("%s: Validate = %v", code, err)
		}
	}
	if i := describe(t, "1.2.1.8.0.255"); i.Channel != "channel 2" || i.Name != "activeEnergyImportCh2" {
		t.Errorf("channel 2: %+v", i)
	}
	if i := describe(t, "1.64.32.7.0.255"); i.Channel != "channel 64" || !i.Valid() {
		t.Errorf("channel 64: %+v", i)
	}
	kinds(t, map[string]string{"1.65.1.8.0.255": "utility", "0.127.96.1.0.255": "utility", "1.128.1.8.0.255": "manufacturer",
		"1.199.1.8.0.255": "manufacturer", "1.200.1.8.0.255": "reserved", "1.255.1.8.0.255": "reserved"})
}

// Covers: SIG-IPE-1231
func TestManufacturerUtilityConsortiaCountry(t *testing.T) {
	kinds(t, map[string]string{
		// 4.2: any group in its manufacturer range makes the whole code so.
		"1.0.128.8.0.255": "manufacturer", "1.0.199.8.0.255": "manufacturer", "1.0.240.8.0.255": "manufacturer",
		"1.0.200.8.0.255": "reserved", "1.0.1.128.0.255": "manufacturer", "1.0.1.254.0.255": "manufacturer",
		"1.0.1.8.128.255": "manufacturer", "1.0.1.8.0.128": "manufacturer", "1.0.1.8.0.254": "manufacturer",
		"0.0.240.0.0.255": "manufacturer",
		// Table 2, Tables 8 and 20: C 96, D 50-99, B 0-64.
		"0.0.96.50.0.255": "manufacturer", "0.0.96.99.9.9": "manufacturer", "1.0.96.51.1.255": "manufacturer",
		"0.0.96.49.0.255": "reserved", "0.0.96.100.0.255": "reserved",
		// 5.2: B 65-127 makes the whole code utility specific.
		"1.100.1.8.0.255": "utility", "0.65.96.1.0.255": "utility",
		// 5.4.2 Table 6: consortia, D 1 (STS Association) only.
		"0.0.93.1.0.255": "consortia/STS Association", "1.0.93.1.5.7": "consortia/STS Association", "0.0.93.2.0.255": "reserved",
		// 5.4.3 Table 7: country, D is the country; E and F are theirs.
		"0.0.94.91.0.255": "country/India", "1.0.94.91.14.255": "country/India", "0.0.94.96.19.255": "country/Saudi Arabia",
		"0.0.94.49.1.0": "country/Germany", "1.0.94.44.0.255": "country/United Kingdom", "0.0.94.0.0.255": "country/Finland",
		"0.0.94.17.0.255": "country/Qatar", "0.0.94.4.0.255": "reserved", "0.0.94.93.0.255": "reserved", "0.0.94.99.0.255": "reserved",
		// Table 20 codes kept for Germany.
		"1.0.0.5.1.255": "country/Germany", "1.0.0.9.3.255": "country/Germany",
	})
}

// Covers: SIG-IPE-1232
func TestElectricityQuantityAndProcessing(t *testing.T) {
	// 7.1 Table 13 (with phases L1 = +20, L2 = +40, L3 = +60 for C 1-20,
	// and +1 to +3 for 100 and 104) and 7.2 Table 14.
	for code, want := range map[string][2]string{
		"1.0.1.8.0.255":   {"active power import (QI+QIV)", "time integral 1 (from the origin)"},
		"1.0.2.6.0.255":   {"active power export (QII+QIII)", "maximum 1"},
		"1.0.5.8.0.255":   {"reactive power QI", "time integral 1 (from the origin)"},
		"1.0.9.4.0.255":   {"apparent power import (QI+QIV)", "current average 1"},
		"1.0.31.7.0.255":  {"current (C 11: any phase), L1", "instantaneous value"},
		"1.0.52.27.0.255": {"voltage (C 12: any phase), L2", "current average 5 (recording interval 1)"},
		"1.0.73.7.0.255":  {"power factor, L3", "instantaneous value"},
		"1.0.57.7.0.255":  {"active power QI, L2", "instantaneous value"}, // Table 13 note d: 57, not 58
		"1.0.80.29.0.255": {"active power QIV, L3", "time integral 5 (current recording interval 1)"},
		"1.0.86.7.0.255":  {"power factor, export, L2", "instantaneous value"},
		"1.0.91.7.0.255":  {"neutral current", "instantaneous value"},
		"1.0.103.8.0.255": {"reactive power inductive (QI+QIII), L3", "time integral 1 (from the origin)"},
		"1.0.105.7.0.255": {"reactive power capacitive (QII+QIV), L1", "instantaneous value"},
		"1.0.125.7.0.255": {"line voltage L2-L3", "instantaneous value"},
		"1.0.16.58.0.255": {"active power, import less export", "time integral 4 (test)"},
		"1.0.14.55.0.255": {"supply frequency", "test average"},
		"1.0.88.8.0.255":  {"ampere-squared hours (all quadrants)", "time integral 1 (from the origin)"},
		"1.0.13.0.0.255":  {"power factor", "billing period average"},
		"1.0.1.46.0.255":  {"active power import (QI+QIV)", "contracted value"},
	} {
		i := describe(t, code)
		if i.Kind != obis.Standard || i.Quantity != want[0] || i.Processing != want[1] {
			t.Errorf("%s: %s %q / %q (%s), want %q / %q", code, i.Kind, i.Quantity, i.Processing, i.Problem, want[0], want[1])
		}
	}
	// Reserved C (Table 13 gaps) and D (Table 14 gaps) for A = 1.
	for _, code := range []string{"1.0.95.7.0.255", "1.0.108.7.0.255", "1.0.123.7.0.255", "1.0.127.7.0.255", "1.0.241.7.0.255",
		"1.0.1.47.0.255", "1.0.1.48.0.255", "1.0.1.57.0.255", "1.0.1.59.0.255", "1.0.1.127.0.255", "1.0.1.255.0.255",
		"1.0.0.12.0.255", "1.0.96.1.10.255", "1.0.99.4.0.255"} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s accepted as %s %q, want reserved", code, i.Kind, i.Quantity)
		}
	}
}

// Covers: SIG-IPE-1233
func TestElectricityValueGroupE(t *testing.T) {
	for code, class := range map[string]string{
		// 7.3.2 Table 15: tariff rates 1 to 63, 0 total.
		"1.0.1.8.0.255": "total", "1.0.1.8.1.255": "rate 1", "1.0.1.8.63.255": "rate 63",
		// 7.3.3 Table 16: harmonics of these C with D 7, 24 or 56.
		"1.0.32.7.1.255": "harmonic 1", "1.0.12.7.120.255": "harmonic 120", "1.0.31.24.5.255": "harmonic 5",
		"1.0.91.56.124.255": "total harmonic distortion", "1.0.11.7.125.255": "total demand distortion",
		"1.0.35.7.126.255": "all harmonics", "1.0.90.7.127.255": "all harmonics to nominal",
		// Other C and D read E as a rate.
		"1.0.1.7.5.255": "rate 5", "1.0.32.27.3.255": "rate 3",
		// 7.3.4 Table 17: E = 10 x reference + measured.
		"1.0.81.7.1.255": "angle of U2 to U1", "1.0.81.7.4.255": "angle of I1 to U1", "1.0.81.7.15.255": "angle of I2 to U2",
		"1.0.81.7.26.255": "angle of I3 to U3", "1.0.81.7.40.255": "angle of U1 to I1", "1.0.81.7.77.255": "angle of I0 to I0",
		// 7.3.5 Table 18, with the L2 and L3 blocks.
		"1.0.83.8.1.255": "active line losses import", "1.0.83.8.28.255": "compensated reactive net export",
		"1.0.83.8.49.255": "L1 ampere-squared hours", "1.0.83.8.51.255": "L2 active line losses import",
		"1.0.83.8.70.255": "L2 volt-squared hours", "1.0.83.8.73.255": "L3 active line losses",
		"1.0.83.8.90.255": "L3 volt-squared hours",
		// 7.3.6 Table 19: depth class x 10 + duration class, D 32.
		"1.0.12.32.0.255": "dip depth 10-15 %, duration 0.01-0.1 s", "1.0.72.32.45.255": "dip depth 90-100 %, duration 20-60 s",
		"1.0.124.32.23.255": "dip depth 30-60 %, duration 1-3 s",
	} {
		i := describe(t, code)
		if !i.Valid() || i.Class != class {
			t.Errorf("%s: class %q (%s), want %q", code, i.Class, i.Problem, class)
		}
	}
	for _, code := range []string{
		"1.0.1.8.64.255", "1.0.1.8.100.255", // Table 15: 64-127 reserved
		"1.0.32.7.121.255", "1.0.32.7.123.255", // Table 16: 121-123 reserved
		"1.0.81.7.3.255", "1.0.81.7.8.255", "1.0.81.7.30.255", "1.0.81.7.80.255", // Table 17: no index 3, 8, 9 or 8x
		"1.0.83.8.0.255", "1.0.83.8.29.255", "1.0.83.8.30.255", "1.0.83.8.91.255", "1.0.83.8.127.255", // Table 18
		"1.0.12.32.6.255", "1.0.12.32.50.255", // Table 19
	} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s accepted (%q), want reserved", code, i.Class)
		}
	}
	// Table 18 has no manufacturer range, but 4.2 makes E 128-254
	// manufacturer specific in every table.
	kinds(t, map[string]string{"1.0.83.8.200.255": "manufacturer"})
}

// Covers: SIG-IPE-1234
func TestValueGroupF(t *testing.T) {
	for code, period := range map[string]string{
		"1.0.1.8.0.0":     "billing period with counter value 0",
		"1.0.1.8.0.99":    "billing period with counter value 99",
		"1.0.1.6.1.101":   "last 1 billing period(s)",
		"1.0.9.8.0.125":   "last 25 billing period(s)",
		"1.0.1.8.0.126":   "unspecified number of last billing periods",
		"1.0.13.0.0.3":    "billing period with counter value 3",
		"1.0.1.8.0.255":   "",
		"1.0.11.35.0.0":   "threshold 1", // 7.4.2 example: over limit threshold 1 for current
		"1.0.11.37.0.0":   "threshold 1",
		"1.0.32.31.0.4":   "threshold 5",
		"0.0.0.1.2.3":     "billing period with counter value 3",
		"0.0.0.1.0.126":   "unspecified number of last billing periods",
		"1.0.0.4.2.1":     "billing period with counter value 1",
		"1.0.0.1.2.101":   "last 1 billing period(s)",
		"0.0.98.1.0.255":  "",
		"1.0.99.1.0.255":  "",
		"1.0.0.8.0.255":   "",
		"0.0.96.1.0.255":  "",
		"1.0.0.2.1.1":     "",
		"1.0.94.91.0.255": "",
	} {
		i := describe(t, code)
		if !i.Valid() || i.Period != period {
			t.Errorf("%s: period %q (%s), want %q", code, i.Period, i.Problem, period)
		}
	}
	for _, code := range []string{
		"1.0.1.8.0.100", "1.0.1.8.0.127", // Table A.2: 100 and 127 are not billing codes
		"1.0.1.7.0.0", "1.0.1.4.0.1", "1.0.1.29.0.0", // D not in the 7.4.1 list
		"1.0.11.35.0.101",                            // 7.4.2: no historical values of threshold quantities
		"0.0.96.1.0.0", "1.0.0.1.1.3", "1.0.0.9.1.0", // F not used by these objects
	} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s accepted (%q), want reserved", code, i.Period)
		}
	}
}

// Covers: SIG-IPE-1235
func TestAbstractObjects(t *testing.T) {
	for code, name := range map[string]string{
		// 6.1 Table 8.
		"0.0.0.1.0.255": "billingPeriodCounter", "0.0.0.1.1.255": "availableBillingPeriods", "0.0.0.1.2.255": "billingPeriodTime",
		"0.0.0.1.2.4": "billingPeriodTime_b04", "0.0.0.1.5.255": "billingPeriodTime2", "0.0.0.2.8.255": "activeFirmwareSignature",
		"0.0.0.9.1.255": "localTime", "0.0.96.1.255.255": "completeDeviceId", "0.0.96.1.0.255": "deviceId1",
		"0.0.96.1.9.255": "deviceId10", "0.0.96.1.10.255": "meteringPointId", "0.0.96.2.0.255": "configChanges",
		"0.0.96.2.13.255": "lastFirmwareActivationTime", "0.0.96.3.10.255": "disconnectControl", "0.0.96.3.29.255": "arbitrator10",
		"0.0.96.4.3.255": "internalControlStatus3", "0.0.96.6.11.255": "auxVoltage", "0.0.96.7.0.255": "powerFailures",
		"0.0.96.7.21.255": "powerFailuresAnyPhase", "0.0.96.7.20.255": "longPowerFailureThreshold", "0.0.96.8.63.255": "operatingTimeT63",
		"0.0.96.9.0.255": "ambientTemperature", "0.0.96.10.10.255": "statusRegister10", "0.0.96.11.0.255": "eventCode1",
		"0.0.96.11.99.255": "eventCode100", "0.0.96.12.5.255": "gsmFieldStrength", "0.0.96.13.1.255": "consumerMessageDisplay",
		"0.0.96.14.15.255": "activeTariff16", "0.0.96.15.99.255": "eventCounter100", "0.0.96.16.9.255": "profileEntrySignature10",
		"0.0.96.17.127.255": "profileEntryCounter128", "0.0.96.20.0.255": "meterOpenCount", "0.0.96.20.33.255": "commTamperTotalDuration",
		"0.1.96.1.0.255": "deviceId1Ch1",
		// 6.2 Table 9.
		"0.0.97.97.0.255": "errorRegister1", "0.0.97.98.9.255": "alarmRegister10", "0.0.97.98.10.255": "alarmFilter1",
		"0.0.97.98.29.255": "alarmDescriptor10",
		// 6.3 Table 10, 6.4 Table 11, 6.5 Table 12.
		"0.0.98.1.0.255": "billingPeriodData", "0.0.98.2.3.255": "billingPeriodData2E3", "0.0.98.10.0.255": "registerTable",
		"0.0.99.1.0.255": "loadProfile1", "0.0.99.3.0.255": "testLoadProfile", "0.0.99.13.0.255": "gsmDiagnosticProfile",
		"0.0.99.18.0.255": "lteMonitoringProfile", "0.0.99.98.0.255": "eventLog", "0.0.99.98.6.255": "eventLogE6",
	} {
		i := describe(t, code)
		if i.Kind != obis.Standard || i.Name != name {
			t.Errorf("%s: %s %q (%s), want %q", code, i.Kind, i.Name, i.Problem, name)
		}
	}
	kinds(t, map[string]string{
		// Table 5: C 0-89 are COSEM objects of IEC 62056-6-2:2023 6.2
		// (standard where 6.2 lists them, reserved otherwise), 127 inactive.
		"0.0.1.0.0.255": "standard", "0.0.40.0.1.255": "standard", "0.4.25.9.0.255": "standard", "0.0.89.0.0.255": "reserved",
		"0.0.127.0.0.255": "inactive",
		// Unallocated rows of Tables 5 and 8 to 12.
		"0.0.90.0.0.255": "reserved", "0.0.95.0.0.255": "reserved", "0.0.100.0.0.255": "reserved",
		"0.0.96.12.0.255": "reserved", "0.0.96.12.2.255": "reserved", "0.0.96.13.2.255": "reserved", "0.0.96.20.4.255": "reserved",
		"0.0.96.20.34.255": "reserved", "0.200.96.7.0.255": "reserved", "0.0.96.10.0.255": "reserved", "0.0.96.14.16.255": "reserved",
		"0.0.97.97.10.255": "reserved", "0.0.97.98.30.255": "reserved", "0.0.99.3.1.255": "reserved", "0.0.99.97.0.255": "reserved",
		"0.0.96.1.11.255": "reserved", "0.1.96.1.10.255": "standard", "0.1.96.7.0.255": "standard", // F-267
	})
}

// Covers: SIG-IPE-1236
func TestElectricityObjects(t *testing.T) {
	for code, name := range map[string]string{
		// 7.5.1 Table 20.
		"1.0.0.0.255.255": "completeElectricityId", "1.0.0.0.0.255": "electricityId1", "1.0.0.1.0.255": "electricityBillingPeriodCounter",
		"1.0.0.2.0.255": "electricityActiveFirmwareId", "1.0.0.2.1.1": "parameterRecordNumberLine1", "1.0.0.3.9.255": "ampereSquaredHoursPulseConstant",
		"1.0.0.4.2.255": "ctRatio", "1.0.0.4.3.255": "vtRatio", "1.0.0.4.7.2": "transformerRatioDenominator_b02",
		"1.0.0.6.4.255": "powerQualityReferenceVoltage", "1.0.0.7.12.255": "apparentEnergyExportInputConstant",
		"1.0.0.8.0.255": "measurementPeriod1", "1.0.0.8.4.255": "recordingInterval1", "1.0.0.8.5.255": "recordingInterval2",
		"1.0.0.8.8.255": "harmonicsMeasurementPeriod", "1.0.0.9.5.255": "weekDay", "1.0.0.9.16.255": "billingResetLockout2",
		"1.0.0.10.3.255": "lineReactanceLossCoefficient", "1.0.0.11.7.255": "powerFactorAlgorithm", "1.0.96.1.9.255": "electricityMeteringPointId10",
		"1.0.96.5.5.255": "meterStarted", "1.0.96.10.3.255": "auxSupplyStatus",
		// 7.5.2 to 7.5.5 Tables 21 to 24.
		"1.0.97.97.0.255": "electricityErrorRegister", "1.0.98.1.0.255": "electricityBillingPeriodData", "1.0.99.1.0.255": "electricityLoadProfile1",
		"1.0.99.2.0.255": "electricityLoadProfile2", "1.0.99.10.2.255": "voltageSwellsProfile", "1.0.99.11.5.255": "voltageHarmonicProfileH5",
		"1.0.99.97.0.255": "powerFailureLog", "1.0.99.99.1.255": "certificationLogE1", "1.0.12.32.255.255": "voltageDipsTable",
		"1.0.72.32.255.255": "voltageDipsTableL3", "1.0.81.7.255.255": "angleTable", "1.0.98.10.1.255": "electricityRegisterTableE1",
	} {
		i := describe(t, code)
		if i.Kind != obis.Standard || i.Name != name {
			t.Errorf("%s: %s %q (%s), want %q", code, i.Kind, i.Name, i.Problem, name)
		}
	}
	kinds(t, map[string]string{
		"1.0.0.2.1.2": "reserved", "1.0.0.2.1.127": "reserved", "1.0.0.2.1.128": "manufacturer", "1.0.0.2.5.255": "reserved",
		"1.0.0.9.17.255": "reserved", "1.0.0.11.0.255": "reserved", "1.1.96.1.0.255": "standard", "1.1.96.10.0.255": "standard", "1.200.96.10.0.255": "reserved",
		"1.0.99.10.4.255": "reserved", "1.0.99.13.1.255": "reserved",
	})
}

// Covers: SIG-IPE-1237
func TestOtherMedia(t *testing.T) {
	kinds(t, map[string]string{
		// 8.2 Table 25 for A = 15; D, E, F are left for later (8.3 to 8.5).
		"15.0.0.0.0.255": "media", "15.0.1.8.0.255": "media", "15.0.10.0.0.255": "media", "15.0.11.7.0.255": "media",
		"15.0.20.0.0.255": "media", "15.0.21.0.0.255": "reserved", "15.0.127.0.0.255": "reserved",
		// Table 25 gives C 128-254 to manufacturers where 4.2 gives 128-199 and 240 (F-262).
		"15.0.128.0.0.255": "manufacturer", "15.0.210.0.0.255": "manufacturer", "15.0.254.0.0.255": "manufacturer",
		"15.0.255.0.0.255": "reserved",
		// A = 4 to 9: EN 13757-1:2021 clause 11 (TestEN137571Media).
		"7.0.3.0.0.255": "standard", "8.0.1.0.0.255": "standard", "7.0.200.0.0.255": "reserved", "7.0.96.60.0.255": "manufacturer", "9.70.1.0.0.255": "utility",
		"7.0.94.49.0.255": "country/Germany",
	})
	if i := describe(t, "15.0.3.0.0.255"); i.Quantity != "solar" || i.Name != "" {
		t.Errorf("15.0.3: %+v", i)
	}
}

// Covers: SIG-IPE-1238
func TestReducedIDCodes(t *testing.T) {
	for in, want := range map[string]string{
		// A.1: C and D mandatory; A, B, E, F optional; groups 0-99.
		"1.8.0": "1.0.1.8.0.255", "1.8.1*03": "1.0.1.8.1.3", "1.8.1&12": "1.0.1.8.1.12", "1-0:1.8.0": "1.0.1.8.0.255",
		"1-1:1.8.0*99": "1.1.1.8.0.99", "1:32.7": "1.0.32.7.0.255", "0.9.1": "1.0.0.9.1.255", "1.8.0.255": "1.0.1.8.0.255",
		"1.8.0*255": "1.0.1.8.0.255",
		// A.2 Table A.1: C, F, L, P stand for 96 to 99 in C and D.
		"C.1.0": "0.0.96.1.0.255", "F.F": "0.0.97.97.0.255", "F.F.0": "0.0.97.97.0.255", "P.01": "0.0.99.1.0.255",
		"L.1.0": "0.0.98.1.0.255", "c.7.0": "0.0.96.7.0.255", "1-0:C.1.0": "1.0.96.1.0.255", "1-0:P.98": "1.0.99.98.0.255",
		" 32.7.0 ": "1.0.32.7.0.255",
	} {
		r, err := obis.ParseReduced(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := r.Code().String(); got != want {
			t.Errorf("%q → %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{"", "1", "1.8.0.0.0", "100.8.0", "1.100.0", "1.8.100", "1.8.0*100", "1.8.0*1a", "X.1.0",
		"1.C.0.1", "1.8.C", "256-0:1.8.0", "1-:1.8.0", "-1.8.0", "1..0"} {
		if r, err := obis.ParseReduced(in); err == nil {
			t.Errorf("%q accepted as %+v", in, r)
		}
	}
	r, _ := obis.ParseReduced("1-0:1.8.2&07")
	if !r.Manual || r.String() != "1-0:1.8.2&07" {
		t.Errorf("manual reset: %+v %s", r, r)
	}
	if r, _ := obis.ParseReduced("1.8.0"); r.String() != "1.8.0" || r.Manual {
		t.Errorf("1.8.0 → %s", r)
	}
	// ParseAny takes both forms; Parse needs all six groups, 0 to 255.
	for in, want := range map[string]string{"1.0.1.8.0.255": "1.0.1.8.0.255", "1-0:1.8.0*255": "1.0.1.8.0.255", "C.1.0": "0.0.96.1.0.255"} {
		if c, err := obis.ParseAny(in); err != nil || c.String() != want {
			t.Errorf("ParseAny(%q) = %s, %v", in, c, err)
		}
	}
	for _, in := range []string{"1.0.1.8.0", "1.0.1.8.0.256", "1.0.1.8.0.-1", "1.0.1.8.0.0255", "a.0.1.8.0.255"} {
		if _, err := obis.Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

// Covers: SIG-IPE-1239
func TestDerivedNames(t *testing.T) {
	// A code with a standard meaning gets a name from its value groups;
	// the names match the IS 15959 catalogue's style where they overlap.
	for code, name := range map[string]string{
		"1.0.1.8.0.255": "activeEnergyImport", "1.0.1.8.3.255": "activeEnergyImportT3", "1.0.2.8.0.4": "activeEnergyExport_b04",
		"1.0.1.8.0.101": "activeEnergyImport_last1", "1.0.1.8.0.126": "activeEnergyImport_lastN", "1.0.12.7.0.255": "voltage",
		"1.0.32.7.0.255": "voltageL1", "1.0.51.7.0.255": "currentL2", "1.0.73.7.0.255": "powerFactorL3", "1.0.14.7.0.255": "frequency",
		"1.0.12.27.0.255": "voltageAvg", "1.0.1.29.0.255": "activeEnergyImportBlock", "1.0.16.29.0.255": "activeEnergyNetBlock",
		"1.0.1.9.0.255": "activeEnergyImportPeriod", "1.0.5.8.0.255": "reactiveEnergyQ1", "1.0.9.7.0.255": "apparentPowerImport",
		"1.0.1.6.0.255": "activePowerImportMax1", "1.0.1.6.2.3": "activePowerImportMax1T2_b03", "1.0.13.0.0.255": "powerFactorBillingAvg",
		"1.0.21.7.0.255": "activePowerImportL1", "1.0.91.7.0.255": "neutralCurrent", "1.0.12.7.124.255": "voltageTHD",
		"1.0.32.7.5.255": "voltageL1H5", "1.0.81.7.1.255": "angleU2RefU1", "1.0.81.7.40.255": "angleU1RefI1",
		"1.0.83.8.9.255": "lossesActive", "1.0.83.8.62.255": "lossesReactiveLineL2", "1.0.12.32.23.255": "voltageUnderLimitCountDip23",
		"1.0.11.35.0.0": "currentOverLimitThreshold_th1", "1.0.88.8.0.255": "ampereSquaredHours",
		"1.0.11.8.0.255": "currentIntegral", "1.0.82.8.0.255": "unitlessIntegral", "1.0.124.7.0.255": "voltageL1L2",
		"1.2.12.7.0.255": "voltageCh2", "0.0.96.7.0.255": "powerFailures", "0.0.96.1.0.255": "deviceId1",
		"0.0.99.98.2.255": "eventLogE2", "1.0.99.1.0.255": "electricityLoadProfile1", "0.0.99.1.0.255": "loadProfile1",
	} {
		c := obis.MustParse(code)
		if got := obis.Name(c); got != name {
			t.Errorf("%s → %q, want %q", code, got, name)
		}
	}
	// No name for codes whose meaning is not standard.
	for _, code := range []string{"0.0.89.0.0.255", "0.0.94.91.0.255", "1.0.128.8.0.255", "1.100.1.8.0.255", "0.0.93.1.0.255",
		"0.0.96.50.0.255", "7.0.9.0.0.255", "15.0.1.0.0.255", "0.0.127.0.0.255", "1.0.95.7.0.255"} {
		if got := obis.Name(obis.MustParse(code)); got != "" {
			t.Errorf("%s → %q, want no name", code, got)
		}
	}
}

// Covers: SIG-IPE-1239
func TestDerivedNamesAreUnique(t *testing.T) {
	// Different codes never derive the same name, across media too, so
	// configured objects never share a point: an electricity object that
	// an abstract table also defines is prefixed (0.0.99.1.0.255 is
	// loadProfile1, 1.0.99.1.0.255 electricityLoadProfile1). Walk the C and
	// D values of A = 0 and A = 1 over representative E, F and B values;
	// TestEveryObjectRowNamesUniquely walks every row in full.
	var n int
	seen := map[string]string{}
	for _, a := range []byte{0, 1} {
		for b := 0; b <= 1; b++ {
			for c := 0; c <= 127; c++ {
				for d := 0; d <= 127; d++ {
					for _, e := range []int{0, 1, 5, 20, 33, 63, 124, 255} {
						for _, f := range []int{255, 0, 101} {
							code := obis.Code{a, byte(b), byte(c), byte(d), byte(e), byte(f)}
							name := obis.Name(code)
							if name == "" {
								continue
							}
							n++
							if prev, dup := seen[name]; dup {
								t.Fatalf("%s and %s both derive %q", prev, code, name)
							}
							seen[name] = code.String()
						}
					}
				}
			}
		}
	}
	if n < 10000 {
		t.Fatalf("only %d named codes", n)
	}
	t.Logf("%d distinct derived names", n)
}

// Covers: SIG-IPE-1230
func TestModelCounts(t *testing.T) {
	// The model has what the tables have; this pins the transcription.
	s := obis.Stats()
	want := obis.Counts{Media: 9, Countries: 69, Consortia: 1, ElectricityC: 103, ElectricityD: 56, Harmonics: 124, AngleCodes: 49,
		LossCodes: 88, DipClasses: 30, ObjectRows: 616, MediaC: 90, MediaD: 321}
	if s != want {
		t.Errorf("model counts %+v, want %+v", s, want)
	}
}
