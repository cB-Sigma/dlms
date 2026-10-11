package cosem

import (
	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// ClassLimiter is the limiter interface class (IEC 62056-6-2:2023 4.5.9).
const ClassLimiter = 71

// LimiterThreshold reports the limiter attributes holding thresholds
// (threshold_active, threshold_normal, threshold_emergency: 3, 4, 5),
// which are in the units of the value the limiter monitors.
func LimiterThreshold(class uint16, attr int8) bool {
	return class == ClassLimiter && attr >= 3 && attr <= 5
}

// MonitoredValue reads a limiter's monitored_value: {class_id,
// logical_name, attribute_index}.
func MonitoredValue(d axdr.DlmsData) (uint16, string, bool) {
	f, _ := d.Value.([]*axdr.DlmsData)
	if len(f) < 3 {
		return 0, "", false
	}
	class, ok := Number(*f[0])
	if !ok {
		return 0, "", false
	}
	ln, _ := f[1].Value.(string)
	obis, err := OBISFromHex(ln)
	if err != nil {
		return 0, "", false
	}
	return uint16(class), obis, true
}
