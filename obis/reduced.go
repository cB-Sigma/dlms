package obis

import (
	"fmt"
	"strconv"
	"strings"
)

// Reduced is an ID code in the presentation of annex A.1, "A-B:C.D.E*F",
// as IEC 62056-21 readouts and displays use it: C and D are mandatory; A,
// B, E and F may be left out (-1 here); every group is 0 to 99, and C and
// D may be the letters C, F, L, P for 96 to 99 (A.2 Table A.1).
type Reduced struct {
	A, B, C, D, E, F int
	// Manual is set when "&" rather than "*" comes before F: the reset
	// was made by hand (A.1).
	Manual bool
}

// letters of A.2 Table A.1.
var letters = map[byte]int{'C': 96, 'F': 97, 'L': 98, 'P': 99}

// ParseReduced reads a reduced ID code: "1.8.0", "1.8.0*03", "C.1.0",
// "F.F", "1-0:1.8.0&12", "1-0:1.8.0". A trailing ".255" or "*255" (F not
// used, 5.6.1) is accepted and read as F left out.
func ParseReduced(s string) (Reduced, error) {
	r := Reduced{A: -1, B: -1, E: -1, F: -1}
	s = strings.TrimSpace(s)
	rest := s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		ab := rest[:i]
		rest = rest[i+1:]
		as, bs, hasB := strings.Cut(ab, "-")
		var err error
		if r.A, err = group(as, false); err != nil {
			return r, fmt.Errorf("reduced ID code %q: value group A: %v", s, err)
		}
		if hasB {
			if r.B, err = group(bs, false); err != nil {
				return r, fmt.Errorf("reduced ID code %q: value group B: %v", s, err)
			}
		}
	}
	if i := strings.IndexAny(rest, "*&"); i >= 0 {
		r.Manual = rest[i] == '&'
		fs := rest[i+1:]
		rest = rest[:i]
		if fs != "255" {
			f, err := group(fs, false)
			if err != nil {
				return r, fmt.Errorf("reduced ID code %q: value group F: %v", s, err)
			}
			r.F = f
		}
	}
	parts := strings.Split(rest, ".")
	if len(parts) == 4 && parts[3] == "255" {
		parts = parts[:3]
	}
	if len(parts) < 2 || len(parts) > 3 {
		return r, fmt.Errorf("reduced ID code %q needs C.D or C.D.E", s)
	}
	var err error
	if r.C, err = group(parts[0], true); err != nil {
		return r, fmt.Errorf("reduced ID code %q: value group C: %v", s, err)
	}
	if r.D, err = group(parts[1], true); err != nil {
		return r, fmt.Errorf("reduced ID code %q: value group D: %v", s, err)
	}
	if len(parts) == 3 {
		if r.E, err = group(parts[2], false); err != nil {
			return r, fmt.Errorf("reduced ID code %q: value group E: %v", s, err)
		}
	}
	return r, nil
}

// group reads one value group of a reduced code: 0 to 99 (A.1), or for C
// and D one of the letters of Table A.1.
func group(s string, letter bool) (int, error) {
	if letter && len(s) == 1 {
		if v, ok := letters[strings.ToUpper(s)[0]]; ok {
			return v, nil
		}
	}
	if s == "" || len(s) > 2 {
		return 0, fmt.Errorf("%q is not 0 to 99", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 99 {
		return 0, fmt.Errorf("%q is not 0 to 99", s)
	}
	return n, nil
}

// Code completes a reduced code (finding F-264, A.1 does not say what
// groups left out mean): A left out is 0 (abstract) when C is 96 to 99,
// the letters C, F, L, P, and 1 (electricity) otherwise, as electricity
// meter readouts print them; B left out is 0 (no channel, 5.2); E left
// out is 0 (the only or total object, 4.5); F left out is 255 (not used,
// 5.6.1).
func (r Reduced) Code() Code {
	a := r.A
	if a < 0 {
		a = 1
		if r.C >= 96 && r.C <= 99 {
			a = 0
		}
	}
	b, e, f := r.B, r.E, r.F
	if b < 0 {
		b = 0
	}
	if e < 0 {
		e = 0
	}
	if f < 0 {
		f = 255
	}
	return Code{byte(a), byte(b), byte(r.C), byte(r.D), byte(e), byte(f)}
}

// String prints the code back in reduced form, with the groups it has.
func (r Reduced) String() string {
	var sb strings.Builder
	if r.A >= 0 {
		sb.WriteString(strconv.Itoa(r.A))
		if r.B >= 0 {
			sb.WriteString("-" + strconv.Itoa(r.B))
		}
		sb.WriteByte(':')
	}
	fmt.Fprintf(&sb, "%d.%d", r.C, r.D)
	if r.E >= 0 {
		fmt.Fprintf(&sb, ".%d", r.E)
	}
	if r.F >= 0 {
		sep := "*"
		if r.Manual {
			sep = "&"
		}
		fmt.Fprintf(&sb, "%s%02d", sep, r.F)
	}
	return sb.String()
}

// ParseAny reads a six-group code or a reduced one.
func ParseAny(s string) (Code, error) {
	if c, err := Parse(s); err == nil {
		return c, nil
	}
	r, err := ParseReduced(s)
	if err != nil {
		return Code{}, err
	}
	return r.Code(), nil
}
