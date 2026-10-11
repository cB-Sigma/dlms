package iec6205621

import (
	"strconv"
	"strings"

	"github.com/cB-Sigma/dlms/obis"
)

// OBIS codes (IEC 62056-6-1) as meters print them in readouts: usually the
// reduced form C.D.E ("1.8.0"), sometimes with the medium and channel
// ("1-0:1.8.0") and a billing period ("1.8.0*03" or "1.8.0&03"). The names
// follow the DLMS catalogue (package cosem); the units are the ones the quantity is
// normally given in and are used only when the meter sends none. Codes the
// table does not list are named from the OBIS model (package obis, IEC
// 62056-6-1:2023 annex A.1): "32.27.0" is voltageL1Avg. Codes without a
// standard meaning (manufacturer, utility, country or reserved ones, such
// as C.51.1) keep their code.

// Quantity is a known OBIS code's point name and default unit.
type Quantity struct {
	Name string
	Unit string
}

var obisTable = map[string]Quantity{
	"C.1.0": {"serialNumber", ""}, "0.0.0": {"deviceAddress", ""}, "0.0.1": {"deviceAddress2", ""},
	"C.1.1": {"deviceId2", ""}, "F.F": {"errorRegister", ""}, "F.F.0": {"errorRegister", ""},
	"0.9.1": {"time", ""}, "0.9.2": {"date", ""}, "0.1.0": {"billingCount", ""}, "0.1.2": {"billingDate", ""},
	"C.7.0": {"powerFailures", ""}, "C.2.1": {"lastProgrammed", ""},

	"1.8.0": {"activeEnergyImport", "kWh"}, "2.8.0": {"activeEnergyExport", "kWh"},
	"1.8.1": {"activeEnergyImportT1", "kWh"}, "1.8.2": {"activeEnergyImportT2", "kWh"},
	"1.8.3": {"activeEnergyImportT3", "kWh"}, "1.8.4": {"activeEnergyImportT4", "kWh"},
	"2.8.1": {"activeEnergyExportT1", "kWh"}, "2.8.2": {"activeEnergyExportT2", "kWh"},
	"3.8.0": {"reactiveEnergyImport", "kvarh"}, "4.8.0": {"reactiveEnergyExport", "kvarh"},
	"5.8.0": {"reactiveEnergyQ1", "kvarh"}, "6.8.0": {"reactiveEnergyQ2", "kvarh"},
	"7.8.0": {"reactiveEnergyQ3", "kvarh"}, "8.8.0": {"reactiveEnergyQ4", "kvarh"},
	"9.8.0": {"apparentEnergyImport", "kVAh"}, "10.8.0": {"apparentEnergyExport", "kVAh"},
	"15.8.0": {"activeEnergyAbsolute", "kWh"}, "16.8.0": {"activeEnergyNet", "kWh"},

	"1.6.0": {"maxDemandActive", "kW"}, "2.6.0": {"maxDemandActiveExport", "kW"},
	"9.6.0": {"maxDemandApparent", "kVA"}, "1.4.0": {"demandActive", "kW"},

	"1.7.0": {"activePower", "kW"}, "2.7.0": {"activePowerExport", "kW"},
	"3.7.0": {"reactivePower", "kvar"}, "4.7.0": {"reactivePowerExport", "kvar"},
	"9.7.0": {"apparentPower", "kVA"}, "15.7.0": {"activePowerAbsolute", "kW"},
	"21.7.0": {"activePowerL1", "kW"}, "41.7.0": {"activePowerL2", "kW"}, "61.7.0": {"activePowerL3", "kW"},
	"12.7.0": {"voltage", "V"}, "11.7.0": {"phaseCurrent", "A"}, "91.7.0": {"neutralCurrent", "A"},
	"32.7.0": {"voltageL1", "V"}, "52.7.0": {"voltageL2", "V"}, "72.7.0": {"voltageL3", "V"},
	"31.7.0": {"currentL1", "A"}, "51.7.0": {"currentL2", "A"}, "71.7.0": {"currentL3", "A"},
	"13.7.0": {"powerFactor", ""}, "33.7.0": {"powerFactorL1", ""}, "53.7.0": {"powerFactorL2", ""},
	"73.7.0": {"powerFactorL3", ""}, "14.7.0": {"frequency", "Hz"},
	"81.7.1": {"angleU2RefU1", "deg"}, "81.7.2": {"angleU3RefU1", "deg"},
	"81.7.4": {"angleI1RefU1", "deg"}, "81.7.15": {"angleI2RefU2", "deg"}, "81.7.26": {"angleI3RefU3", "deg"},
}

// textCodes are identifiers, dates and status words: their values stay
// text even when they are all digits.
var textCodes = map[string]bool{"C.1.0": true, "C.1.1": true, "0.0.0": true, "0.0.1": true, "F.F": true, "F.F.0": true,
	"0.9.1": true, "0.9.2": true, "0.1.2": true, "C.2.1": true}

// IsText reports whether an address's value is an identifier or status
// word rather than a quantity.
func IsText(addr string) bool {
	code, _ := NormaliseOBIS(addr)
	return textCodes[strings.ToUpper(code)]
}

// NormaliseOBIS splits a readout address into its reduced code and a
// billing period suffix: "1-0:1.8.0*03" → "1.8.0", "03". Addresses that
// are not OBIS codes come back unchanged.
func NormaliseOBIS(addr string) (code, billing string) {
	code = strings.TrimSpace(addr)
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[i+1:]
	}
	if i := strings.IndexAny(code, "*&"); i >= 0 {
		code, billing = code[:i], code[i+1:]
		if billing == "255" {
			billing = ""
		}
	}
	// Full dotted codes keep only C.D.E: "1.0.1.8.0.255", "1.8.0.255".
	switch parts := strings.Split(code, "."); {
	case len(parts) == 6:
		code = strings.Join(parts[2:5], ".")
	case len(parts) == 4 && parts[3] == "255":
		code = strings.Join(parts[:3], ".")
	}
	return code, billing
}

// LookupOBIS returns the known quantity for a readout address.
func LookupOBIS(addr string) (Quantity, bool) {
	code, _ := NormaliseOBIS(addr)
	q, ok := obisTable[strings.ToUpper(code)]
	if !ok {
		q, ok = obisTable[code]
	}
	return q, ok
}

// PointName is the container name for a readout address: the table's
// name, else the name the OBIS model derives (with "_b<nn>" for a billing
// period), else the code itself.
func PointName(addr string) string {
	code, billing := NormaliseOBIS(addr)
	name := code
	derived := false
	if q, ok := LookupOBIS(addr); ok {
		name = q.Name
	} else if n := derivedName(addr); n != "" {
		name, derived = n, true
	}
	// A name from the OBIS model already names its channel.
	if ch := channelOf(addr); ch > 1 && !derived {
		name += "_ch" + strconv.Itoa(ch)
	}
	if billing != "" {
		name += "_b" + billing
	}
	return name
}

// channelOf returns value group B of an address written with it
// ("1-2:1.8.0" or "1.2.1.8.0.255"), or -1. Channels 0 and 1 keep the
// plain name, so single-channel meters are named as before; other
// channels get "_ch<B>" after a table name or a bare code, so a
// multi-channel meter's quantities do not collide.
func channelOf(addr string) int {
	a := strings.TrimSpace(addr)
	b := ""
	if i := strings.IndexByte(a, ':'); i >= 0 {
		if j := strings.IndexByte(a[:i], '-'); j >= 0 {
			b = a[j+1 : i]
		}
	} else {
		if i := strings.IndexAny(a, "*&"); i >= 0 {
			a = a[:i]
		}
		if parts := strings.Split(a, "."); len(parts) == 6 {
			b = parts[1]
		}
	}
	n, err := strconv.Atoi(b)
	if err != nil || n < 0 || n > 255 {
		return -1
	}
	return n
}

// derivedName names an address from the OBIS model, without its billing
// period (PointName adds that as "_b<nn>").
func derivedName(addr string) string {
	c, err := obis.ParseAny(addr)
	if err != nil {
		return ""
	}
	c[5] = 255
	return obis.Name(c)
}
