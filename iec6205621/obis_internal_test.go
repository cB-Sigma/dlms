package iec6205621

import (
	"testing"

	"github.com/cB-Sigma/dlms/obis"
)

// readoutAlias pairs the adapter's names with the name the OBIS model
// derives for the same reduced code where they differ; each pair was
// checked against IEC 62056-6-1:2023 (tables named).
var readoutAlias = map[string]string{
	"serialNumber":          "deviceId1",                       // Table 8: device ID 1, the manufacturing number
	"deviceAddress":         "electricityId1",                  // Table 20: electricity ID 1 (0.0.0 with A 1)
	"deviceAddress2":        "electricityId2",                  // Table 20
	"errorRegister":         "errorRegister1",                  // Table 9: F.F is 0.0.97.97.0
	"time":                  "electricityLocalTime",            // Table 20: 1.b.0.9.1
	"date":                  "electricityLocalDate",            // Table 20: 1.b.0.9.2
	"billingCount":          "electricityBillingPeriodCounter", // Table 20: 1.b.0.1.0
	"billingDate":           "electricityBillingPeriodTime",    // Table 20: 1.b.0.1.2
	"lastProgrammed":        "lastConfigChangeTime",            // Table 8: 0.b.96.2.1
	"activePower":           "activePowerImport",               // Table 13: C 1 (QI+QIV)
	"reactivePower":         "reactivePowerImport",             // Table 13: C 3 (QI+QII)
	"apparentPower":         "apparentPowerImport",             // Table 13: C 9 (QI+QIV)
	"activePowerL1":         "activePowerImportL1",             // Table 13: C 21
	"activePowerL2":         "activePowerImportL2",             // Table 13: C 41
	"activePowerL3":         "activePowerImportL3",             // Table 13: C 61
	"phaseCurrent":          "current",                         // Table 13: C 11, any phase
	"maxDemandActive":       "activePowerImportMax1",           // Table 14: D 6, maximum 1
	"maxDemandActiveExport": "activePowerExportMax1",
	"maxDemandApparent":     "apparentPowerImportMax1",
	"demandActive":          "activePowerImportAvg1", // Table 14: D 4, current average 1
}

// Covers: SIG-IPE-1241
func TestReadoutTableAgainstIEC6205661(t *testing.T) {
	for code, q := range obisTable {
		r, err := obis.ParseReduced(code)
		if err != nil {
			t.Errorf("%s is not a reduced ID code (annex A.1): %v", code, err)
			continue
		}
		i := obis.Describe(r.Code())
		if i.Kind != obis.Standard {
			t.Errorf("%s (%s) → %s is %s (%s): no standard meaning to name", code, q.Name, r.Code(), i.Kind, i.Problem)
			continue
		}
		if q.Name != i.Name && readoutAlias[q.Name] != i.Name {
			t.Errorf("%s: name %q, OBIS meaning %q (%s)", code, q.Name, i.Name, i.Ref)
		}
	}
}

// Covers: SIG-IPE-1241
func TestReadoutNamesFromOBISModel(t *testing.T) {
	for addr, want := range map[string]string{
		// Corrected: C.1.1 is device ID 2 (Table 8), not a firmware version;
		// Table 17 puts the reference first: E 01 is U(L2) against U(L1).
		"C.1.1": "deviceId2", "81.7.1": "angleU2RefU1", "81.7.2": "angleU3RefU1", "1-0:81.7.4": "angleI1RefU1",
		// Not in the table: named from the model, with the billing suffix.
		"32.27.0": "voltageL1Avg", "1-0:52.7.0*02": "voltageL2_b02", "1.29.0": "activeEnergyImportBlock",
		"1.8.5": "activeEnergyImportT5", "13.0.0&07": "powerFactorBillingAvg_b07", "C.7.21": "powerFailuresAnyPhase",
		"P.98": "eventLog", "0.8.0": "measurementPeriod1", "0.9.6": "lastResetTime", "32.7.3": "voltageL1H3",
		// No standard meaning: the code itself.
		"C.51.1": "C.51.1", "C.50.0": "C.50.0", "0.4.2*1": "ctRatio_b1", "99.99.9": "99.99.9", "1.8.64": "1.8.64",
		"94.91.0": "94.91.0", "garbage": "garbage",
	} {
		if got := PointName(addr); got != want {
			t.Errorf("PointName(%q) = %q, want %q", addr, got, want)
		}
	}
	if q, ok := LookupOBIS("81.7.1"); !ok || q.Unit != "deg" {
		t.Errorf("81.7.1 → %+v", q)
	}
}
