package cosem

import (
	"errors"
	"fmt"
	"strconv"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// ParseOBIS reads an OBIS code written as six numbers 0 to 255 separated
// by ".", "-" or ":".
func ParseOBIS(s string) ([6]byte, error) {
	var out [6]byte
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' || s[i] == '-' || s[i] == ':' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if len(parts) != 6 {
		return out, fmt.Errorf("OBIS code %q does not have six parts", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return out, fmt.Errorf("OBIS code %q has a part that is not 0–255", s)
		}
		out[i] = byte(n)
	}
	return out, nil
}

// CommError reports errors after which the association is dropped: all
// but the meter refusing a get, set or action, or a parameter.
func CommError(err error) bool {
	var de *gdlms.Error
	if errors.As(err, &de) {
		switch de.Code() {
		case gdlms.ErrorGetRejected, gdlms.ErrorSetRejected, gdlms.ErrorActionRejected, gdlms.ErrorInvalidParameter:
			return false
		}
	}
	return true
}

// OBISFromHex writes a logical name given as 12 hex digits (as gosem
// gives octet strings) as a dotted OBIS code.
func OBISFromHex(h string) (string, error) {
	if len(h) != 12 {
		return "", fmt.Errorf("logical name %q is not 6 bytes", h)
	}
	var parts [6]string
	for i := range 6 {
		n, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", err
		}
		parts[i] = strconv.Itoa(int(n))
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4] + "." + parts[5], nil
}

// Scaler is a register's scaler_unit: values are multiplied by
// 10^Exponent and carry Unit; OK is false when it is not known.
type Scaler struct {
	Exponent int8
	Unit     string
	OK       bool
}

// Capture is one column of a profile: the attribute it captures and its
// catalogue name.
type Capture struct {
	Class uint16
	OBIS  string
	Attr  int8
	Name  string
}
