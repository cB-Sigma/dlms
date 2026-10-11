package cosem

import (
	"reflect"
	"testing"
)

// Covers: SIG-IPE-2231
func TestGeneralErrorObjectBits(t *testing.T) {
	for v, want := range map[uint16][]string{
		0:      {},
		0x8080: {"alert_unacknowledged", "alert_pending"},
		0x4040: {"warning_unacknowledged", "warning_pending"},
		0x2020: {"indication_unacknowledged", "indication_pending"},
		0x0020: {"indication_pending"},
		0x8001: {"alert_unacknowledged", "reserved_0"},
		0x1100: {"reserved_12", "reserved_8"},
	} {
		if got := GeneralErrorFlags(v); !reflect.DeepEqual(got, want) {
			t.Errorf("%04X: %v, want %v", v, got, want)
		}
	}
	for code, want := range map[string]bool{"0.0.97.97.0.255": true, "0.1.97.97.0.255": true, "0.0.97.97.1.255": false, "7.0.97.97.0.255": false} {
		if got := IsGeneralError(code, ClassData, 2); got != want {
			t.Errorf("%s: %v", code, got)
		}
	}
	if IsGeneralError("0.0.97.97.0.255", ClassRegister, 2) {
		t.Error("a register taken for the general error object")
	}
}
