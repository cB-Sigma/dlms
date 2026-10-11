package cosem

import (
	"strconv"

	"github.com/cB-Sigma/dlms/obis"
)

// ErrorBit is one named bit of the general error object of EN
// 13757-1:2021 10.3.2 (0.b.97.97.0.255, class 1, unsigned16; annex A lists
// it for every basic meter): per condition (alert, warning, indication) a
// non-acknowledged bit (15, 14, 13) and a pending bit (7, 6, 5); the other
// bits are reserved.
type ErrorBit struct {
	Bit  uint
	Name string
}

// GeneralErrorBits are the named bits of the general error object.
var GeneralErrorBits = []ErrorBit{
	{15, "alert_unacknowledged"}, {14, "warning_unacknowledged"}, {13, "indication_unacknowledged"},
	{7, "alert_pending"}, {6, "warning_pending"}, {5, "indication_pending"},
}

// GeneralErrorFlags names the set bits of a general error object value;
// reserved bits that are set are named "reserved_<bit>".
func GeneralErrorFlags(v uint16) []string {
	out := []string{}
	known := uint16(0)
	for _, b := range GeneralErrorBits {
		known |= 1 << b.Bit
		if v&(1<<b.Bit) != 0 {
			out = append(out, b.Name)
		}
	}
	for bit := 15; bit >= 0; bit-- {
		if v&(1<<bit) != 0 && known&(1<<bit) == 0 {
			out = append(out, "reserved_"+strconv.Itoa(bit))
		}
	}
	return out
}

// IsGeneralError reports the general error object's value attribute.
func IsGeneralError(code string, class uint16, attr int8) bool {
	c, err := obis.Parse(code)
	return err == nil && class == ClassData && (attr == 2 || attr == 0) &&
		c.A() == 0 && c.C() == 97 && c.D() == 97 && c.E() == 0 && c.F() == 255
}

// GeneralErrorOBIS is the general error object of annex A of EN
// 13757-1:2021 (Tables A.1 to A.4).
const GeneralErrorOBIS = "0.0.97.97.0.255"
