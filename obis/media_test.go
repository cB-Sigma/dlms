package obis_test

import (
	"testing"

	"github.com/cB-Sigma/dlms/obis"
)

type mediaWant struct{ name, quantity, processing, class, period string }

func checkMedia(t *testing.T, cases map[string]mediaWant) {
	t.Helper()
	for code, w := range cases {
		i := describe(t, code)
		if i.Kind != obis.Standard || i.Name != w.name || w.quantity != "" && i.Quantity != w.quantity ||
			w.processing != "" && i.Processing != w.processing || w.class != "" && i.Class != w.class || w.period != "" && i.Period != w.period {
			t.Errorf("%s: %s %q q=%q p=%q e=%q f=%q (%s), want %+v", code, i.Kind, i.Name, i.Quantity, i.Processing, i.Class, i.Period, i.Problem, w)
		}
	}
}

// Covers: SIG-IPE-2130
func TestEN137571ExamplesAsVectors(t *testing.T) {
	// The example tables of EN 13757-1:2021 (Tables 22, 30, 52 and 44,
	// Figure 6, annex A), with VZ read as 3 and VZ-1 as 2.
	checkMedia(t, map[string]mediaWant{
		// Table 22 (heat cost allocators).
		"4.0.1.0.0.255":   {"hcaUnratedIntegral", "unrated integral", "current value", "total", ""},
		"4.0.2.0.0.255":   {"hcaRatedIntegral", "rated integral", "current value", "total", ""},
		"4.0.2.2.0.3":     {"hcaRatedIntegralSetDate_b03", "", "set date value", "", "billing period with counter value 3"},
		"4.0.1.3.0.2":     {"hcaUnratedIntegralBillingDate_b02", "", "billing date value", "", ""},
		"4.0.2.1.0.102":   {"hcaRatedIntegralPeriodical_last2", "", "periodical value", "", "last 2 billing period(s)"},
		"4.0.3.0.255.255": {"hcaRadiatorTemperatureNoRate", "radiator surface temperature", "current value", "", ""},
		"4.0.3.4.255.255": {"hcaRadiatorTemperatureMinNoRate", "", "minimum", "", ""},
		"4.0.5.6.255.255": {"hcaFlowTemperatureTestNoRate", "", "test value", "", ""},
		"4.0.7.5.255.255": {"hcaRoomTemperatureMaxNoRate", "", "maximum", "", ""},
		// Table 30 (thermal energy); A.2 and Figure 6.
		"6.0.1.0.0.255":    {"heatEnergy", "energy", "current value", "total", ""},
		"5.0.1.0.0.255":    {"coolingEnergy", "energy", "current value", "total", ""},
		"6.0.1.0.1.255":    {"heatEnergyT1", "", "", "rate 1", ""},
		"6.0.1.1.0.102":    {"heatEnergyPeriodical1_last2", "", "periodical value 1", "", ""},
		"6.0.1.3.1.3":      {"heatEnergyBillingDateT1_b03", "", "billing date value", "rate 1", ""},
		"6.0.1.5.255.255":  {"heatEnergyMax1NoRate", "", "maximum 1", "", ""},
		"6.0.9.12.255.2":   {"heatFlowRatePeriodical2NoRate_b02", "flow rate", "periodical value 2", "", ""},
		"6.0.8.5.255.2":    {"heatPowerMax1NoRate_b02", "power", "", "", ""},
		"6.0.1.25.255.255": {"heatEnergyMissingDurationNoRate", "", "missing data duration", "", ""},
		"6.0.12.6.255.255": {"heatTemperatureDifferenceTestNoRate", "temperature difference", "test value", "", ""},
		"6.0.0.2.10.255":   {"heatFlowTemperatureSensorSerial", "", "", "", ""},
		"6.0.99.1.1.255":   {"heatConsumptionProfile1", "", "", "", ""},
		"6.0.97.97.0.255":  {"heatErrorRegister0", "", "", "", ""},
		"6.0.97.97.2.255":  {"heatErrorRegister2", "", "", "", ""},
		"5.0.10.0.255.255": {"coolingFlowTemperatureNoRate", "inlet (flow) temperature", "", "", ""},
		// Table 52 (water); A.4.
		"8.0.1.0.0.255": {"coldWaterVolume", "accumulated volume", "current value", "total", ""},
		"9.0.1.0.1.255": {"hotWaterVolumeT1", "", "", "rate 1", ""},
		"8.0.1.1.0.102": {"coldWaterVolumePeriodical_last2", "", "periodical value", "", ""},
		"8.0.2.5.0.2":   {"coldWaterFlowRateMax_b02", "flow rate", "maximum", "", ""},
		"9.0.3.3.0.101": {"hotWaterForwardTemperatureBillingDate_last1", "forward temperature", "billing date value", "", "last 1 billing period(s)"},
		// A.3: forward absolute volume of a meter, converter, logger, direct energy.
		"7.0.3.0.0.255":  {"gasMeterVolumeFwd", "meter volume, forward, absolute", "index at metering conditions", "total", ""},
		"7.0.13.0.0.255": {"gasConverterVolumeFwd", "", "", "", ""},
		"7.0.23.0.0.255": {"gasLoggerVolumeFwd", "", "", "", ""},
		"7.0.33.0.0.255": {"gasEnergyFwd", "", "", "", ""},
		// Table 44 examples: profiles named from the value they capture.
		"7.0.99.11.17.255": {"gasConverterVolumeFwdUndisturbedLastDiffMp2BaseProfile", "", "last index difference over measurement period 2, at base conditions", "", ""},
		"7.0.99.41.43.255": {"gasTemperatureLastAvgPi2BaseProfile", "", "average, last interval, process interval 2, at base conditions", "", ""},
		"7.0.99.43.19.255": {"gasFlowRateLastAvgAp1Profile", "", "last average, averaging period 1", "", ""},
		// 11.3.4.3.2: the sliding demand sub-periods object.
		"7.0.0.8.35.255": {"gasSubPeriods", "", "", "", ""},
	})
}

// Covers: SIG-IPE-2131
func TestEN137571MediaTables(t *testing.T) {
	checkMedia(t, map[string]mediaWant{
		// Gas Table 32: indexes and index differences, all four billing periods.
		"7.0.1.1.0.255":    {"gasMeterVolumeFwdUndisturbedCorrected", "", "index, corrected", "", ""},
		"7.0.12.3.0.255":   {"gasConverterVolumeFwdDisturbedRedundant", "", "index, redundant (logger)", "", ""},
		"7.0.3.8.0.255":    {"gasMeterVolumeFwdDiffMp1Base", "", "index difference over measurement period 1, at base conditions", "", ""},
		"7.0.13.26.0.3":    {"gasConverterVolumeFwdBp1Base_b03", "", "historical index, billing period 1, at base conditions", "", ""},
		"7.0.13.41.0.255":  {"gasConverterVolumeFwdMaxMp3Bp1Base", "", "", "", ""},
		"7.0.13.62.0.255":  {"gasConverterVolumeFwdMaxBp1Bp2Base", "", "maximum index difference over billing period 1 in Bp2, at base conditions", "", ""},
		"7.0.33.98.63.255": {"gasEnergyFwdMaxMp3Bp4BaseT63", "", "", "rate 63", ""},
		"7.0.66.84.0.255":  {"gasMassRevDiffBp4", "", "", "", ""},
		// Table 33 flow rate, Table 34 process values (E 0 only).
		"7.0.43.13.0.255": {"gasFlowRateStd", "flow rate", "instantaneous, at standard conditions", "", ""},
		"7.0.43.54.0.255": {"gasFlowRateMaxBp1Ap2Std", "", "", "", ""},
		"7.0.43.70.0.255": {"gasFlowRateLastAvgAp4Std", "", "", "", ""},
		"7.0.42.3.0.255":  {"gasPressureBackup", "absolute pressure", "backup value", "", ""},
		"7.0.44.92.0.255": {"gasSoundVelocityAvgBetweenEventsStd", "", "", "", ""},
		// Tables 35, 38, 39: conversion factors with averages; method with rates.
		"7.0.52.0.13.255": {"gasConversionFactorAvgAp2", "conversion factor", "current value at metering conditions", "average, current interval, averaging period 2", ""},
		"7.0.54.2.1.255":  {"gasSuperiorCalorificValueBaseWeighted", "", "", "weighted value", ""},
		"7.0.53.12.5.255": {"gasCompressibilityFactorMethodT5", "", "calculation method", "rate 5", ""},
		// Tables 36, 40: gas analysis.
		"7.0.70.67.0.255":  {"gasMethane", "natural gas analysis", "methane", "process independent current value", ""},
		"7.0.70.10.28.255": {"gasSuperiorWobbeIndexAvgBetweenEvents", "", "", "", ""},
		// Thermal Table 24 thresholds and averages.
		"6.1.8.10.0.255": {"heatPowerAvgCh1", "", "current average", "", ""},
		"5.0.2.22.0.255": {"coolingVolumeOverLimitCount", "", "over limit occurrences", "", ""},
		// General objects of Tables 18, 26, 41, 48.
		"4.0.0.4.3.255":   {"hcaRoomSideCouplingFactor", "", "", "", ""},
		"4.0.0.1.10.255":  {"hcaSetDate", "", "", "", ""},
		"5.0.0.8.22.255":  {"coolingPeriodicalPeriod2", "", "", "", ""},
		"6.0.0.5.7.255":   {"heatRateThresholdT7", "", "", "", ""},
		"7.0.0.1.2.4":     {"gasBillingPeriodTime1_b04", "", "", "", ""},
		"7.0.0.1.11.255":  {"gasBillingPeriodTime4", "", "", "", ""},
		"7.0.0.5.2.13":    {"gasRateThresholdMp3T3", "", "", "", ""},
		"7.0.0.5.1.12":    {"gasOverConsumptionThresholdMp3Limit2", "", "", "", ""},
		"7.0.0.9.18.255":  {"gasLastResetTime3", "", "", "", ""},
		"7.0.0.12.67.255": {"gasConversionParameter67", "", "", "", ""},
		"7.0.0.13.10.255": {"gasReynoldsNumber", "", "", "", ""},
		"7.0.96.5.9.255":  {"gasStatusWord9", "", "", "", ""},
		"7.0.98.3.0.255":  {"gasBillingPeriodData3", "", "", "", ""},
		"7.0.99.99.3.255": {"gasLoadProfileDay", "", "", "", ""},
		"8.0.0.1.12.255":  {"coldWaterBillingDatePeriod", "", "", "", ""},
		"9.0.0.8.6.255":   {"hotWaterFlowRateAveragingPeriod", "", "", "", ""},
		"9.0.99.1.0.255":  {"hotWaterProfile", "", "", "", ""},
		"8.0.0.0.255.255": {"coldWaterCompleteId", "", "", "", ""},
		"8.0.0.0.3.255":   {"coldWaterId4", "", "", "", ""},
	})
	// Reserved by the media tables.
	for _, code := range []string{
		"4.0.8.0.0.255", "4.0.1.7.0.255", "4.0.1.0.10.255", // HCA C 8, D 7, E 10 (rates 1-9)
		"6.0.14.0.0.255", "6.0.1.16.0.255", "6.0.1.26.0.255", // thermal C 14, D 16, 26
		"7.0.9.0.0.255", "7.0.1.4.0.255", "7.0.1.99.0.255", "7.0.1.0.64.255", // gas C 9, D 4, 99, E 64
		"7.0.43.3.0.255", "7.0.43.14.0.255", "7.0.43.0.1.255", // flow D 3, 14, E 1 (E 0 only)
		"7.0.42.1.0.255", "7.0.42.14.0.255", "7.0.42.0.1.255", // process D 1, 14, E 1
		"7.0.51.1.0.255", "7.0.51.0.2.255", "7.0.51.0.29.255", // conversion D 1, E 2, 29
		"7.0.70.0.0.255", "7.0.70.21.0.255", "7.0.70.85.0.255", // analysis D 0, 21, 85
		"8.0.6.0.0.255", "9.0.1.7.0.255", "8.0.1.0.10.255", // water C 6, D 7, E 10
		"8.0.1.0.0.100", "6.0.1.0.0.127", // F 100, 127
		"7.0.99.1.5.255", "7.0.99.43.3.255", // gas profiles of reserved values
		"4.0.0.1.0.255", "7.0.0.2.9.255", "8.0.0.2.1.255", // unallocated general objects
		"2.0.1.8.0.255", // A 2: reserved for DC electricity
	} {
		if i := describe(t, code); i.Valid() {
			t.Errorf("%s accepted as %s %q, want reserved", code, i.Kind, i.Name)
		}
	}
	// The media ranges of Table 2 and 4.2 still apply.
	kinds(t, map[string]string{"7.0.96.60.0.255": "manufacturer", "6.0.128.0.0.255": "manufacturer", "8.0.1.0.128.255": "manufacturer",
		"4.70.1.0.0.255": "utility", "7.0.94.49.0.255": "country/Germany", "9.0.93.1.0.255": "consortia/STS Association"})
}
