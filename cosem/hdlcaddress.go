package cosem

import (
	"fmt"

	"github.com/cB-Sigma/dlms/hdlc"
)

// CheckHDLCAddresses checks the addresses of a connection (IEC 62056-46 6.4.2.3,
// Tables 3 and 4): a client address of one octet that is neither
// no-station nor all-station; an upper address naming one logical device
// (the management logical device 1, or 16 up to below all-station); a
// lower address naming one physical device (16 up to below CALLING), or
// CALLING when the meter called us.
func CheckHDLCAddresses(client, upper, lower, size int) error {
	if client < 1 || client > 0x7E {
		return fmt.Errorf("HDLC client address %d is not 1 to 126 (0 is no-station, 127 all-station)", client)
	}
	all := hdlc.AllStationFor(size)
	if upper != hdlc.ManagementDevice && (upper < 0x10 || upper >= all) {
		return fmt.Errorf("HDLC upper (logical device) address %d is not 1 or 16 to %d (0 is no-station, 2 to 15 reserved, %d all-station)", upper, all-1, all)
	}
	if size == 1 {
		if lower != 0 {
			return fmt.Errorf("hdlcAddress %d needs hdlcAddressSize 2 or 4 (one octet has the upper address only)", lower)
		}
		return nil
	}
	if lower == 0 {
		return fmt.Errorf("hdlcAddress (the physical device's lower HDLC address) is required with hdlcAddressSize %d", size)
	}
	if lower < 0x10 || lower >= all {
		return fmt.Errorf("hdlcAddress %d is not 16 to %d (1 to 15 reserved, %d CALLING, %d all-station)", lower, all-1, all-1, all)
	}
	return nil
}

// ClassHDLCSetup is the IEC HDLC setup interface class
// (IEC 62056-6-2:2023 4.7.2).
const ClassHDLCSetup = 23

// HDLCSetupInactivity is its inactivity_time_out attribute, in seconds,
// 0 when not operational (4.7.2.2.8).
const HDLCSetupInactivity = 8
