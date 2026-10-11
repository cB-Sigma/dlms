package is15959

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/cB-Sigma/dlms/obis"
)

// catalogueCodes is every OBIS code the catalogue uses: the objects,
// profiles, capture columns, event logs and their code objects, push
// setups, commands, associations and security setups of every profile,
// and every code the point names cover.
func catalogueCodes() map[string]string {
	out := map[string]string{}
	add := func(code, where string) {
		if code != "" && out[code] == "" {
			out[code] = where
		}
	}
	for _, id := range IDs() {
		sp, _ := Get(id)
		for _, o := range sp.Objects {
			add(o.OBIS, id+" object")
		}
		cols := func(cs []Column, where string) {
			for _, c := range cs {
				add(c.OBIS, where)
			}
		}
		for _, p := range sp.Profiles {
			add(p.OBIS, id+" profile")
			add(p.Scaler, id+" scaler profile")
			cols(p.Capture, id+" capture of "+p.OBIS)
		}
		for _, l := range sp.Events {
			add(l.OBIS, id+" event log")
			add(l.CodeOBIS, id+" event code")
			cols(l.Capture, id+" capture of "+l.OBIS)
		}
		for _, p := range sp.Push {
			add(p.OBIS, id+" push setup")
			cols(p.Capture, id+" push list of "+p.OBIS)
		}
		for _, m := range sp.Methods {
			add(m.OBIS, id+" command "+m.Name)
		}
		for _, a := range sp.Associations {
			add(a.OBIS, id+" association")
			add(a.Setup, id+" security setup")
		}
	}
	for code := range names {
		add(code, "names")
	}
	for _, p := range pushNames {
		add(p.obis, "push names")
	}
	for base := range tou {
		for e := 1; e <= 8; e++ {
			add(fmt.Sprintf("%s.%d.255", base, e), "TOU names")
		}
	}
	for k := range attrNames {
		code, _, _ := strings.Cut(k, "/")
		add(code, "attribute names")
	}
	return out
}

// Country codes of IS 15959 that IEC 62056-6-1:2023 Table 7 does not give
// to India (D 91): finding F-260. Kept, since Indian meters use them.
var notIndia = map[string]bool{
	"0.0.94.96.19.255": true, "0.0.94.96.20.255": true, "0.0.94.96.21.255": true, "0.0.94.96.22.255": true,
	"0.0.94.96.23.255": true, "0.0.94.96.24.255": true, "0.0.94.96.25.255": true,
}

// Codes of IS 15959 in ranges IEC 62056-6-1:2023 leaves unallocated:
// finding F-261. Kept, since Indian meters use them.
var reservedInIEC = map[string]bool{"0.0.96.13.2.255": true}

// Covers: SIG-IPE-1240
func TestCatalogueOBISCodesAgainstIEC6205661(t *testing.T) {
	codes := catalogueCodes()
	keys := make([]string, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	count := map[obis.Kind]int{}
	for _, code := range keys {
		c, err := obis.Parse(code)
		if err != nil || c.String() != code {
			t.Errorf("%s (%s) is not a canonical six-group OBIS code: %v", code, codes[code], err)
			continue
		}
		i := obis.Describe(c)
		count[i.Kind]++
		switch i.Kind {
		case obis.Standard:
			// A meaning IEC 62056-6-1 or IEC 62056-6-2 clause 6 defines.
		case obis.Country:
			// IS 15959's own objects are India's: C 94, D 91 (5.4.3 Table 7).
			if i.Owner != "India" && !notIndia[code] {
				t.Errorf("%s (%s) is country specific for %s, not India", code, codes[code], i.Owner)
			}
			if i.Owner == "India" && notIndia[code] {
				t.Errorf("%s is listed in notIndia but is India's", code)
			}
		case obis.Reserved:
			if !reservedInIEC[code] {
				t.Errorf("%s (%s) is reserved: %s", code, codes[code], i.Problem)
			}
		default:
			t.Errorf("%s (%s) is %s, which a companion standard should not use", code, codes[code], i.Kind)
		}
		if reservedInIEC[code] && i.Kind != obis.Reserved {
			t.Errorf("%s is listed in reservedInIEC but is %s", code, i.Kind)
		}
	}
	t.Logf("%d codes: %v", len(keys), count)
}

// sameMeaning pairs catalogue names with the name the OBIS model derives
// for the same code where the two differ; every pair was checked against
// IEC 62056-6-1:2023 and IS 15959. The catalogue keeps the names IS 15959
// users know.
var sameMeaning = map[string]string{
	"billingCount":            "billingPeriodCounter",        // Table 8, 0.b.0.1.0
	"billingDate":             "billingPeriodTime",           // Table 8, 0.b.0.1.2: time stamp of the most recent billing period
	"serialNumber":            "deviceId1",                   // Table 8, device ID 1 is the manufacturing number
	"manufacturer":            "deviceId2",                   // Table 8 leaves device IDs 2 to 10 to the user; IS 15959 puts the manufacturer name in 2
	"deviceId":                "deviceId3",                   // IS 15959: the utility's device ID in device ID 3
	"yearOfManufacture":       "deviceId5",                   // IS 15959: year of manufacture in device ID 5
	"programmingCount":        "configChanges",               // Table 8, 0.b.96.2.0
	"messageToDisplay":        "consumerMessageDisplay",      // Table 8, 0.b.96.13.1
	"firmwareVersion":         "electricityActiveFirmwareId", // Table 20, 1.b.0.2.0 (formerly the configuration program version)
	"demandIntegrationPeriod": "measurementPeriod1",          // Table 20, 1.b.0.8.0: measurement period for averaging scheme 1
	"profileCapturePeriod":    "recordingInterval1",          // Table 20, 1.b.0.8.4
	"dailyCapturePeriod":      "recordingInterval2",          // Table 20, 1.b.0.8.5
	"billingPowerFactor":      "powerFactorBillingAvg",       // Table 14, D 0: billing period average
	"phaseCurrent":            "current",                     // Table 13, C 11: current, any phase
	"phaseCurrentAvg":         "currentAvg",                  // Table 14, D 27: current average 5
	"activePower":             "activePowerImport",           // C 1; IS 15959 signs it (F-265)
	"reactivePower":           "reactivePowerImport",         // C 3; IS 15959 signs it (F-265)
	"apparentPower":           "apparentPowerImport",         // C 9 (QI+QIV)
	"maxDemandActive":         "activePowerImportMax1",       // D 6: maximum 1
	"maxDemandApparent":       "apparentPowerImportMax1",
	"maxDemandActiveExport":   "activePowerExportMax1",
	"maxDemandApparentExport": "apparentPowerExportMax1",
	"billingProfile":          "electricityBillingPeriodData", // Table 22, 1.b.98.1
	"blockLoadProfile":        "electricityLoadProfile1",      // Table 23, recording period 1
	"dailyLoadProfile":        "electricityLoadProfile2",      // Table 23, recording period 2
	"voltageEventCode":        "eventCode1",                   // Table 8, 0.b.96.11.e: event code objects 1 to 100
	"currentEventCode":        "eventCode2",
	"powerEventCode":          "eventCode3",
	"transactionEventCode":    "eventCode4",
	"otherEventCode":          "eventCode5",
	"nonRolloverEventCode":    "eventCode6",
	"controlEventCode":        "eventCode7",
	"voltageEvents":           "eventLog", // Table 12, 0.b.99.98.e: event logs
	"currentEvents":           "eventLogE1",
	"powerEvents":             "eventLogE2",
	"transactionEvents":       "eventLogE3",
	"otherEvents":             "eventLogE4",
	"nonRolloverEvents":       "eventLogE5",
	"controlEvents":           "eventLogE6",
	// IEC 62056-6-2:2023 clause 6 COSEM objects: IS 15959 names the role
	// of each instance where 6-2 numbers it.
	"billingScripts":          "billingScript",         // 6.2.7, MDI reset / end of billing period
	"tariffScripts":           "tariffScript",          // 6.2.7
	"imageActivationScripts":  "imageActivationScript", // 6.2.7
	"pushScripts":             "pushScript",            // 6.2.7
	"billingDates":            "billingSchedule",       // 6.2.12, end of billing period schedule
	"periodicPushSchedule":    "pushSchedule",          // 6.2.12
	"loadLimit":               "limiter",               // 6.2.15
	"periodicPushSetup":       "pushSetup",             // 6.2.24; IS 15959 numbers its push setups by B
	"displayPushSetup":        "pushSetupCh1",
	"displayReplyPushSetup":   "pushSetupCh2",
	"meterToDisplayPushSetup": "pushSetupCh3",
	"eventPushSetup":          "pushSetupCh4",
	"publicAssociation":       "association1", // 6.2.33: association instances 1 to n
	"readerAssociation":       "association2",
	"settingsAssociation":     "association3",
	"pushAssociation":         "association4",
	"firmwareAssociation":     "association5",
	"displayAssociation":      "association6",
	"securitySetup1":          "securitySetupE1", // 6.2.36
	"securitySetup2":          "securitySetupE2",
	"securitySetup3":          "securitySetupE3",
	"securitySetup4":          "securitySetupE4",
	"securitySetup5":          "securitySetupE5",
	"securitySetup6":          "securitySetupE6",
}

// Covers: SIG-IPE-1240
func TestCatalogueNamesMatchOBISMeaning(t *testing.T) {
	for code := range catalogueCodes() {
		c, err := obis.Parse(code)
		if err != nil {
			continue
		}
		derived := obis.Name(c)
		if derived == "" {
			continue // country specific or COSEM context: no standard name
		}
		name := NameOf(code, 0, 0) // the object, not one attribute
		if name == code {
			t.Errorf("%s has a standard meaning (%s) but no catalogue name", code, derived)
			continue
		}
		if name == derived {
			continue
		}
		// TOU zones: the base register's pair with the zone's T<n>.
		base, zone := name, ""
		if i := strings.LastIndex(name, "T"); i > 0 && c.E() >= 1 && c.E() <= 8 && name[i+1:] == fmt.Sprint(c.E()) {
			base, zone = name[:i], name[i:]
		}
		if want, ok := sameMeaning[base]; !ok || want+zone != derived {
			t.Errorf("%s: catalogue name %q, OBIS meaning %q (%s): not a reviewed pair", code, name, derived, obis.Describe(c).Ref)
		}
	}
}

// Covers: SIG-IPE-1240
func TestTOUNamesOnlyForCurrentValues(t *testing.T) {
	// Value group F other than 255 is a billing period (IEC 62056-6-1:2023
	// 7.4.1): a TOU register of a past period is not the current one.
	if got := NameOf("1.0.1.8.3.255", ClassRegister, 2); got != "activeEnergyImportT3" {
		t.Errorf("current TOU zone 3 → %q", got)
	}
	for _, code := range []string{"1.0.1.8.3.0", "1.0.1.8.3.101", "1.0.9.6.1.5"} {
		if got := NameOf(code, ClassRegister, 2); got != code {
			t.Errorf("%s (a billing period) → %q, want its code", code, got)
		}
	}
}
