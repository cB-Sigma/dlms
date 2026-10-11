package is15959

import (
	"fmt"
	"strings"
)

// Point names: one name per OBIS code across every profile, in camel case,
// phases as L1, L2, L3 (R, Y, B), reactive energy by quadrant, TOU zones as
// T1..T8, block averages with "Avg", block energies with "Block". A
// register's value is its name; other attributes get a suffix (MD capture
// time: "Time"; scaler_unit: "Scaler").
var names = map[string]string{
	// Name plate and identification.
	"0.0.96.1.0.255":   "serialNumber",
	"0.0.96.1.1.255":   "manufacturer",
	"0.0.96.1.2.255":   "deviceId",
	"0.0.96.1.4.255":   "yearOfManufacture",
	"1.0.0.2.0.255":    "firmwareVersion",
	"0.0.94.91.9.255":  "meterType",
	"0.0.94.91.11.255": "category",
	"0.0.94.91.12.255": "currentRating",
	"1.0.0.4.2.255":    "ctRatio",
	"1.0.0.4.3.255":    "vtRatio",
	"0.0.42.0.0.255":   "logicalDeviceName",

	// Instantaneous.
	ClockOBIS:          "clock",
	"1.0.12.7.0.255":   "voltage",
	"1.0.11.7.0.255":   "phaseCurrent",
	"1.0.91.7.0.255":   "neutralCurrent",
	"1.0.32.7.0.255":   "voltageL1",
	"1.0.52.7.0.255":   "voltageL2",
	"1.0.72.7.0.255":   "voltageL3",
	"1.0.31.7.0.255":   "currentL1",
	"1.0.51.7.0.255":   "currentL2",
	"1.0.71.7.0.255":   "currentL3",
	"1.0.33.7.0.255":   "powerFactorL1",
	"1.0.53.7.0.255":   "powerFactorL2",
	"1.0.73.7.0.255":   "powerFactorL3",
	"1.0.13.7.0.255":   "powerFactor",
	"1.0.14.7.0.255":   "frequency",
	"1.0.9.7.0.255":    "apparentPower",
	"1.0.1.7.0.255":    "activePower",
	"1.0.3.7.0.255":    "reactivePower",
	"1.0.13.0.0.255":   "billingPowerFactor",
	"0.0.96.7.0.255":   "powerFailures",
	"0.0.94.91.8.255":  "powerFailureDuration",
	"0.0.94.91.13.255": "powerOnDuration",
	"0.0.94.91.14.255": "powerOnDurationTotal",
	"0.0.94.91.0.255":  "tamperCount",
	"0.0.0.1.0.255":    "billingCount",
	"0.0.0.1.1.255":    "availableBillingPeriods",
	"0.0.96.2.0.255":   "programmingCount",
	"0.0.0.1.2.255":    "billingDate",
	"0.0.96.3.10.255":  "disconnectControl",
	"0.0.17.0.0.255":   "loadLimit",
	"0.0.94.96.19.255": "meteringMode",
	"0.0.94.91.26.255": "eventStatusFilter",
	EventStatusWord:    "eventStatusWord",
	"0.0.96.13.1.255":  "messageToDisplay",
	"0.0.96.13.2.255":  "messageFromDisplay",

	// Cumulative energy.
	"1.0.1.8.0.255":   "activeEnergyImport",
	"1.0.2.8.0.255":   "activeEnergyExport",
	"1.0.9.8.0.255":   "apparentEnergyImport",
	"1.0.10.8.0.255":  "apparentEnergyExport",
	"1.0.5.8.0.255":   "reactiveEnergyQ1",
	"1.0.6.8.0.255":   "reactiveEnergyQ2",
	"1.0.7.8.0.255":   "reactiveEnergyQ3",
	"1.0.8.8.0.255":   "reactiveEnergyQ4",
	"1.0.1.9.0.255":   "activeEnergyImportPeriod",
	"1.0.1.6.0.255":   "maxDemandActive",
	"1.0.2.6.0.255":   "maxDemandActiveExport",
	"1.0.9.6.0.255":   "maxDemandApparent",
	"1.0.10.6.0.255":  "maxDemandApparentExport",
	"1.0.94.91.1.255": "reactiveEnergyHighVoltage",
	"1.0.94.91.2.255": "reactiveEnergyLowVoltage",

	// Block (interval) averages and energies.
	"1.0.12.27.0.255": "voltageAvg",
	"1.0.11.27.0.255": "phaseCurrentAvg",
	"1.0.14.27.0.255": "frequencyAvg",
	"1.0.32.27.0.255": "voltageL1Avg",
	"1.0.52.27.0.255": "voltageL2Avg",
	"1.0.72.27.0.255": "voltageL3Avg",
	"1.0.31.27.0.255": "currentL1Avg",
	"1.0.51.27.0.255": "currentL2Avg",
	"1.0.71.27.0.255": "currentL3Avg",
	"1.0.1.29.0.255":  "activeEnergyImportBlock",
	"1.0.2.29.0.255":  "activeEnergyExportBlock",
	"1.0.16.29.0.255": "activeEnergyNetBlock",
	"1.0.9.29.0.255":  "apparentEnergyImportBlock",
	"1.0.10.29.0.255": "apparentEnergyExportBlock",
	"1.0.5.29.0.255":  "reactiveEnergyQ1Block",
	"1.0.6.29.0.255":  "reactiveEnergyQ2Block",
	"1.0.7.29.0.255":  "reactiveEnergyQ3Block",
	"1.0.8.29.0.255":  "reactiveEnergyQ4Block",

	// Profiles.
	"1.0.94.91.0.255":  "instantaneousProfile",
	"1.0.99.1.0.255":   "blockLoadProfile",
	"1.0.99.2.0.255":   "dailyLoadProfile",
	"1.0.98.1.0.255":   "billingProfile",
	"0.0.94.91.10.255": "nameplateProfile",
	"1.0.94.91.3.255":  "instantaneousScalers",
	"1.0.94.91.4.255":  "blockLoadScalers",
	"1.0.94.91.5.255":  "dailyLoadScalers",
	"1.0.94.91.6.255":  "billingScalers",
	"1.0.94.91.7.255":  "eventScalers",

	// Event codes and logs.
	"0.0.96.11.0.255": "voltageEventCode",
	"0.0.96.11.1.255": "currentEventCode",
	"0.0.96.11.2.255": "powerEventCode",
	"0.0.96.11.3.255": "transactionEventCode",
	"0.0.96.11.4.255": "otherEventCode",
	"0.0.96.11.5.255": "nonRolloverEventCode",
	"0.0.96.11.6.255": "controlEventCode",
	"0.0.99.98.0.255": "voltageEvents",
	"0.0.99.98.1.255": "currentEvents",
	"0.0.99.98.2.255": "powerEvents",
	"0.0.99.98.3.255": "transactionEvents",
	"0.0.99.98.4.255": "otherEvents",
	"0.0.99.98.5.255": "nonRolloverEvents",
	"0.0.99.98.6.255": "controlEvents",

	// Programmable parameters and schedules.
	"1.0.0.8.0.255":    "demandIntegrationPeriod",
	"1.0.0.8.4.255":    "profileCapturePeriod",
	"1.0.0.8.5.255":    "dailyCapturePeriod",
	"0.0.15.0.0.255":   "billingDates",
	"0.0.15.0.2.255":   "imageActivationSchedule",
	"0.0.13.0.0.255":   "activityCalendar",
	"0.0.10.0.100.255": "tariffScripts",
	"0.0.10.0.1.255":   "billingScripts",
	"0.0.10.0.107.255": "imageActivationScripts",
	"0.0.10.0.108.255": "pushScripts",
	"0.0.44.0.0.255":   "imageTransfer",
	"0.0.22.0.0.255":   "hdlcSetup",
	"0.0.25.0.0.255":   "tcpUdpSetup",
	"0.0.25.1.0.255":   "ipv4Setup",
	"0.0.25.7.0.255":   "ipv6Setup",

	// Associations and security.
	"0.0.40.0.0.255": "currentAssociation",
	"0.0.40.0.1.255": "publicAssociation",
	"0.0.40.0.2.255": "readerAssociation",
	"0.0.40.0.3.255": "settingsAssociation",
	"0.0.40.0.4.255": "pushAssociation",
	"0.0.40.0.5.255": "firmwareAssociation",
	"0.0.40.0.6.255": "displayAssociation",
	"0.0.43.0.0.255": "securitySetup",
	"0.0.43.0.1.255": "securitySetup1",
	"0.0.43.0.2.255": "securitySetup2",
	"0.0.43.0.3.255": "securitySetup3",
	"0.0.43.0.4.255": "securitySetup4",
	"0.0.43.0.5.255": "securitySetup5",
	"0.0.43.0.6.255": "securitySetup6",

	// Prepayment (Part 2 table A13 as amended).
	"0.0.94.96.20.255": "paymentMode",
	"0.0.94.96.21.255": "lastRechargeAmount",
	"0.0.94.96.22.255": "lastRechargeTime",
	"0.0.94.96.23.255": "totalAmountAtLastRecharge",
	"0.0.94.96.24.255": "currentBalance",
	"0.0.94.96.25.255": "currentBalanceTime",
	"1.0.94.91.14.255": "loadCurrent",
	"0.0.15.0.4.255":   "periodicPushSchedule",
}

// tou names the TOU zone registers (E = 1..8) of a base register.
var tou = map[string]string{
	"1.0.1.8": "activeEnergyImport", "1.0.9.8": "apparentEnergyImport",
	"1.0.1.6": "maxDemandActive", "1.0.9.6": "maxDemandApparent",
	"1.0.2.8": "activeEnergyExport", "1.0.10.8": "apparentEnergyExport",
}

// attrSuffix names attributes other than the value, by class (IEC
// 62056-6-2:2023 4.3.2 to 4.3.4).
var attrSuffix = map[uint16]map[int8]string{
	ClassRegister:         {3: "Scaler"},
	ClassExtendedRegister: {3: "Scaler", 4: "Status", 5: "Time"},
	ClassDemandRegister:   {3: "Last", 4: "Scaler", 5: "Status", 6: "Time", 7: "Start", 8: "Period", 9: "Periods"},
}

// NameOf returns the point name of an attribute: the OBIS code's name
// (with a suffix for attributes other than the value), or the OBIS code
// when it has none.
func NameOf(obis string, class uint16, attr int8) string {
	base, ok := names[obis]
	if !ok && strings.HasSuffix(obis, ".255") { // TOU zones of the current values only
		if i := strings.LastIndex(obis, "."); i > 0 {
			if j := strings.LastIndex(obis[:i], "."); j > 0 {
				var e int
				if _, err := fmt.Sscanf(obis[j+1:i], "%d", &e); err == nil && e >= 1 && e <= 8 {
					if b, ok := tou[obis[:j]]; ok {
						base = fmt.Sprintf("%sT%d", b, e)
					}
				}
			}
		}
	}
	if base == "" {
		for _, p := range pushNames {
			if p.obis == obis {
				base = p.name
			}
		}
	}
	if base == "" {
		return obis
	}
	return AttrName(base, obis, class, attr)
}

// AttrName names an attribute of an object whose value (or primary
// attribute) is called base: base itself, or base with the class's
// attribute suffix ("Scaler", "Time", ...), or "<base>Attr<n>". SigmaM2M's
// DLMS adapter uses it with the names the OBIS model (package obis)
// derives for objects the catalogue does not list.
func AttrName(base, obis string, class uint16, attr int8) string {
	if n, ok := attrNames[obis+"/"+fmt.Sprint(attr)]; ok {
		return n
	}
	if attr == 0 || attr == primaryAttr(class) {
		return base
	}
	if s, ok := attrSuffix[class][attr]; ok {
		return base + s
	}
	if class == ClassPushSetup {
		if n, ok := pushAttrNames[attr]; ok {
			return base + n
		}
	}
	return fmt.Sprintf("%sAttr%d", base, attr)
}

// pushNames names the push setup objects.
var pushNames = []struct{ obis, name string }{
	{"0.0.25.9.0.255", "periodicPushSetup"},
	{"0.1.25.9.0.255", "displayPushSetup"},
	{"0.2.25.9.0.255", "displayReplyPushSetup"},
	{"0.3.25.9.0.255", "meterToDisplayPushSetup"},
	{"0.4.25.9.0.255", "eventPushSetup"},
}

// primaryAttr is the attribute a class's object is named by: its value,
// or the one attribute the catalogue reads of it.
func primaryAttr(class uint16) int8 {
	switch class {
	case ClassLimiter:
		return 3 // threshold_active
	case ClassSingleAction:
		return 4 // execution_time
	case ClassActivityCalendar:
		return 10 // activate_passive_calendar_time
	case ClassImageTransfer:
		return 6 // image_transfer_status
	case ClassHDLCSetup, ClassTCPUDPSetup, ClassIPv4Setup, ClassIPv6Setup, ClassScriptTable:
		return 1
	}
	return 2
}

// attrNames names particular attributes.
var attrNames = map[string]string{
	"0.0.96.3.10.255/3": "disconnectControlState",
	"0.0.96.3.10.255/4": "disconnectControlMode",
	"0.0.22.0.0.255/9":  "rs485Address",
	"0.0.44.0.0.255/2":  "imageBlockSize",
	"0.0.44.0.0.255/4":  "imageFirstMissingBlock",
}

// pushAttrNames suffixes push setup attributes.
var pushAttrNames = map[int8]string{1: "Id", 2: "Objects", 3: "Destination", 4: "Window", 5: "Randomisation", 6: "Retries", 7: "RepetitionDelay"}
