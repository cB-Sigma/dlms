package cosem

import "testing"

// Covers: SIG-IPE-1242, SIG-IPE-1245, SIG-IPE-2134
func TestConfiguredObjectNamesFromOBISModel(t *testing.T) {
	for _, c := range []struct {
		obis  string
		class uint16
		attr  int8
		want  string
	}{
		// Catalogue objects keep their catalogue names.
		{"1.0.32.7.0.255", ClassRegister, 2, "voltageL1"},
		{"1.0.1.6.0.255", ClassDemandRegister, 2, "maxDemandActive"},
		{"0.0.1.0.0.255", ClassClock, 2, "clock"},
		// Objects the catalogue does not list: named by IEC 62056-6-1.
		{"1.0.21.7.0.255", ClassRegister, 2, "activePowerImportL1"},
		{"1.0.21.7.0.255", ClassRegister, 3, "activePowerImportL1Scaler"},
		{"1.0.1.4.0.255", ClassDemandRegister, 2, "activePowerImportAvg1"},
		{"1.0.1.4.0.255", ClassDemandRegister, 4, "activePowerImportAvg1Scaler"},
		{"1.0.10.6.1.255", ClassExtendedRegister, 5, "apparentPowerExportMax1T1Time"},
		{"1.0.32.7.124.255", ClassRegister, 2, "voltageL1THD"},
		{"1.0.1.8.0.3", ClassRegister, 2, "activeEnergyImport_b03"},
		{"1.0.1.8.3.101", ClassRegister, 2, "activeEnergyImportT3_last1"},
		{"0.0.96.6.3.255", ClassRegister, 2, "batteryVoltage"},
		{"0.0.96.9.0.255", ClassRegister, 2, "ambientTemperature"},
		{"1.0.99.97.0.255", ClassProfileGeneric, 2, "powerFailureLog"},
		{"1.1.1.8.0.255", ClassRegister, 2, "activeEnergyImportCh1"},
		// Gas, water and heat objects: EN 13757-1:2021 clause 11.
		{"7.0.13.2.0.255", ClassRegister, 2, "gasConverterVolumeFwdBase"},
		{"7.0.13.2.0.255", ClassRegister, 3, "gasConverterVolumeFwdBaseScaler"},
		{"7.0.42.0.0.255", ClassRegister, 2, "gasPressure"},
		{"7.0.0.9.3.255", ClassData, 2, "gasDayStart"},
		{"8.0.1.0.0.255", ClassRegister, 2, "coldWaterVolume"},
		{"9.1.1.0.0.255", ClassRegister, 2, "hotWaterVolumeCh1"},
		{"6.0.1.0.0.255", ClassRegister, 2, "heatEnergy"},
		{"6.0.8.5.255.3", ClassExtendedRegister, 5, "heatPowerMax1NoRate_b03Time"},
		{"4.0.2.0.0.255", ClassRegister, 2, "hcaRatedIntegral"},
		{"7.0.99.99.1.255", ClassProfileGeneric, 2, "gasLoadProfile15min"},
		// No standard meaning: the OBIS code.
		{"0.0.94.91.99.255", ClassData, 2, "0.0.94.91.99.255"},
		{"1.0.128.8.0.255", ClassRegister, 2, "1.0.128.8.0.255"},
		{"0.0.96.55.1.255", ClassData, 2, "0.0.96.55.1.255"},
		{"1.70.1.8.0.255", ClassRegister, 2, "1.70.1.8.0.255"},
		{"0.0.40.0.9.255", 15, 2, "association9"},
		{"0.0.21.0.1.255", ClassProfileGeneric, 2, "displayReadout"},
		{"0.0.21.0.1.255", ClassData, 2, "readoutParametersE1"},
		{"0.0.16.0.1.255", 21, 2, "registerMonitorE1"},
		{"1.0.99.1.0.255", ClassProfileGeneric, 2, "blockLoadProfile"},
		{"1.0.99.1.1.255", ClassProfileGeneric, 2, "electricityLoadProfile1E1"},
		{"0.0.99.1.0.255", ClassProfileGeneric, 2, "loadProfile1"},
		{"0.0.9.0.0.255", ClassData, 2, "0.0.9.0.0.255"},
		{"1.0.95.7.0.255", ClassRegister, 2, "1.0.95.7.0.255"},
		{"1-0:1.8.0*255", ClassRegister, 2, "1-0:1.8.0*255"},
	} {
		if got := NameOf(c.obis, c.class, c.attr); got != c.want {
			t.Errorf("nameOf(%s, %d, %d) = %q, want %q", c.obis, c.class, c.attr, got, c.want)
		}
	}
}
