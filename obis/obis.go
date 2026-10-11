// Package obis is the Object Identification System of IEC 62056-6-1:2023
// (EN IEC 62056-6-1:2024 is the same text) as a model: it validates an
// OBIS code, says which range each value group is in (standard,
// manufacturer, utility, consortia, country, reserved), describes what a
// standard code identifies, and derives a point name for it. The tables are
// data (obis.yaml) with clause and table references; the wording is ours.
//
// SigmaM2M's DLMS adapter names configured objects with it, and its
// IEC 62056-21 and Wireless M-Bus adapters name readout addresses
// (reduced ID codes, annex A.1) and data records with it.
package obis

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Code is an OBIS code, value groups A to F.
type Code [6]byte

// String is the dotted form "a.b.c.d.e.f".
func (c Code) String() string {
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", c[0], c[1], c[2], c[3], c[4], c[5])
}

// A returns value group A (the medium).
func (c Code) A() byte { return c[0] }

// B returns value group B (the channel).
func (c Code) B() byte { return c[1] }

// C returns value group C (the quantity).
func (c Code) C() byte { return c[2] }

// D returns value group D (the processing).
func (c Code) D() byte { return c[3] }

// E returns value group E (further classification).
func (c Code) E() byte { return c[4] }

// F returns value group F (the billing period).
func (c Code) F() byte { return c[5] }

// Parse reads a six-group code: "1.0.1.8.0.255", or the delimited form of
// annex A.1 with all groups ("1-0:1.8.0*255", "1-0:1.8.0.255"). Reduced
// codes with groups left out are read by ParseReduced.
func Parse(s string) (Code, error) {
	var c Code
	s = strings.TrimSpace(s)
	parts := splitGroups(s)
	var delims []byte
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			delims = append(delims, s[i])
		}
	}
	switch string(delims) {
	case ".....", "-:..*", "-:..&", "-:...":
	default:
		return c, fmt.Errorf("OBIS code %q is not a.b.c.d.e.f or a-b:c.d.e*f", s)
	}
	if len(parts) != 6 {
		return c, fmt.Errorf("OBIS code %q does not have six value groups", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || p == "" || len(p) > 3 {
			return c, fmt.Errorf("OBIS code %q: value group %c is not 0 to 255", s, 'A'+i)
		}
		c[i] = byte(n)
	}
	return c, nil
}

func splitGroups(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == ':' || r == '*' || r == '&' })
}

// MustParse is Parse for constants; it panics on a bad code.
func MustParse(s string) Code {
	c, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return c
}

// Kind is the range a code falls in (clause 4, Table 2).
type Kind string

// Kinds.
const (
	Standard     Kind = "standard"     // a meaning this document defines
	Media        Kind = "media"        // A = 4-9: defined for those media elsewhere (clause 1, EN 13757-1)
	Manufacturer Kind = "manufacturer" // 4.2, Tables 2, 8, 20
	Utility      Kind = "utility"      // 5.2, B = 65-127
	Consortia    Kind = "consortia"    // 5.4.2, C = 93
	Country      Kind = "country"      // 5.4.3, C = 94, or reserved for one country in a table
	Inactive     Kind = "inactive"     // A = 0, C = 127 (Table 5)
	Reserved     Kind = "reserved"     // 4.3: not allocated
)

// Info describes a code.
type Info struct {
	Code Code
	Kind Kind
	// Medium (A), Channel (B), Quantity (C), Processing (D), Class (E) and
	// Period (F) say what each value group means, in our words; empty when
	// the group carries no meaning of its own.
	Medium, Channel, Quantity, Processing, Class, Period string
	// Owner is the country or consortium of a country or consortia code.
	Owner string
	// Name is the derived point name; empty when the code has no standard
	// meaning (manufacturer, utility, consortia, country, context codes and
	// reserved ones).
	Name string
	// Classes are the interface classes IEC 62056-6-2:2023 clause 6 gives
	// the object (class_id), in the order the standard lists them; empty
	// when it gives none.
	Classes []uint16
	// Ref is the clause and table the meaning comes from.
	Ref string
	// Problem says why a reserved code is reserved.
	Problem string
}

// Valid reports whether the code is not in a reserved range.
func (i Info) Valid() bool { return i.Kind != Reserved }

// ErrReserved is returned by Validate for codes in reserved ranges.
var ErrReserved = errors.New("reserved OBIS code")

// Validate returns an error wrapping ErrReserved for a code no range of
// IEC 62056-6-1:2023 allocates.
func Validate(c Code) error {
	if i := Describe(c); !i.Valid() {
		return fmt.Errorf("%w %s: %s", ErrReserved, c, i.Problem)
	}
	return nil
}

// Name returns the derived point name of a code, "" when it has none.
func Name(c Code) string { return Describe(c).Name }

// NameFor returns the derived point name of an object of an interface
// class: where one code names objects of different classes (IEC
// 62056-6-2:2023 6.2.19: 0.b.21.0.e is a readout profile of class 7 and a
// parameter of class 1), the row for the class decides.
func NameFor(c Code, class uint16) string { return DescribeClass(c, class).Name }

// Describe classifies and describes a code, taking the first matching row
// where rows of several classes share it.
func Describe(c Code) Info { return describe(c, 0) }

// DescribeClass is Describe for an object of a known interface class.
func DescribeClass(c Code, class uint16) Info { return describe(c, class) }

func describe(c Code, class uint16) Info {
	t := model
	in := Info{Code: c}
	a, b, cc, d, e, f := c[0], c[1], c[2], c[3], c[4], c[5]
	reserved := func(why string) Info {
		in.Kind, in.Problem, in.Name = Reserved, why, ""
		return in
	}
	ar, ok := lookup(t.a, a)
	if !ok {
		return reserved(fmt.Sprintf("value group A %d is not a medium (5.1 Table 3)", a))
	}
	in.Medium = ar.label
	br, ok := lookup(t.b, b)
	if !ok {
		return reserved(fmt.Sprintf("value group B %d is reserved (5.2 Table 4)", b))
	}
	switch br.key {
	case "channel":
		in.Channel = fmt.Sprintf("channel %d", b)
	case "none":
		in.Channel = ""
	default:
		in.Channel = br.label
	}

	// Manufacturer and utility ranges make the whole code theirs (4.2, 5.2).
	if t.mfrB[b] || t.mfrC[cc] || a == 15 && cc >= 128 && cc <= 254 || t.mfrD[d] || t.mfrE[e] || t.mfrF[f] {
		in.Kind, in.Ref = Manufacturer, "4.2, Table 2"
		if a == 15 && !t.mfrC[cc] && cc >= 128 && cc <= 254 {
			in.Ref = "8.2 Table 25 (finding F-262)"
		}
		return in
	}
	if t.utilB[b] {
		in.Kind, in.Ref = Utility, "5.2, Table 2"
		return in
	}
	if t.mgA[a] && t.mgB[b] && t.mgC[cc] && t.mgD[d] {
		in.Kind, in.Ref = Manufacturer, "Table 2, Tables 8 and 20 (C 96, D 50-99)"
		return in
	}
	if t.consC[cc] {
		in.Kind, in.Ref = Consortia, "5.4.2 Table 6"
		name, ok := t.consortia[d]
		if !ok {
			return reserved(fmt.Sprintf("consortia identifier D %d is not allocated (Table 6)", d))
		}
		in.Owner = name
		return in
	}
	if t.ctryC[cc] {
		in.Kind, in.Ref = Country, "5.4.3 Table 7"
		name, ok := t.countries[d]
		if !ok {
			return reserved(fmt.Sprintf("country identifier D %d is not allocated (Table 7)", d))
		}
		in.Owner = name
		return in
	}
	for _, r := range t.reserved {
		if r.a[a] && r.b[b] && r.c[cc] && r.d[d] && r.e[e] && r.f[f] {
			in.Kind, in.Owner, in.Ref, in.Quantity = Country, r.who, "7.5.1 Table 20", r.label
			return in
		}
	}
	var match *object
	for i, o := range t.objectsByC[cc] {
		if o.a[a] && o.b[b] && o.d[d] && o.e[e] && o.f[f] {
			if match == nil {
				match = &t.objectsByC[cc][i]
			}
			if class != 0 && slices.Contains(o.ic, class) {
				match = &t.objectsByC[cc][i]
				break
			}
		}
	}
	if o := match; o != nil {
		in.Kind, in.Ref = Standard, tableRef(o.table)
		in.Quantity = o.name
		in.Name = expand(o.name, a, d, e, f)
		in.Classes = o.ic
		if in.Classes == nil {
			for _, r := range t.classes {
				if r.a[a] && r.b[b] && r.c[cc] && r.d[d] && r.e[e] {
					in.Classes = r.ic
					break
				}
			}
		}
		if o.fBill && f != 255 {
			in.Period = period(f)
			in.Name += periodSuffix(f)
		}
		return channelName(in, b)
	}

	switch a {
	case 0:
		r, ok := lookup(t.abstractC, cc)
		if !ok {
			return reserved(fmt.Sprintf("abstract C %d is reserved (5.3.2 Table 5)", cc))
		}
		switch r.key {
		case "context":
			return reserved(fmt.Sprintf("COSEM object C %d D %d E %d is not allocated (IEC 62056-6-2:2023 6.1, 6.2)", cc, d, e))
		case "inactive":
			in.Kind, in.Ref, in.Quantity = Inactive, "5.3.2 Table 5", r.label
			return in
		}
		return reserved(fmt.Sprintf("%s object D %d E %d is not allocated (clause 6)", r.label, d, e))
	case 1:
		return electricity(in, t, b, cc, d, e, f)
	case 15:
		r, ok := lookup(t.otherMed, cc)
		if !ok {
			return reserved(fmt.Sprintf("other media C %d is reserved (8.2 Table 25)", cc))
		}
		in.Kind, in.Ref, in.Quantity = Media, "8.2 Table 25 (D, E, F to be specified, 8.3 to 8.5)", r.label
		return in
	}
	if t.prefix[a] != "" {
		return media(in, t, a, b, cc, d, e, f)
	}
	in.Kind, in.Ref = Media, "clause 1 (identifiers of this medium are defined elsewhere)"
	return in
}

// media describes A = 4 to 9 codes with a quantity in C (EN 13757-1:2021
// 11.3): C and D from the medium's tables, E by the group's rule, F a
// billing period (11.1.4.8, 11.5.3).
func media(in Info, t *tables, a, b, cc, d, e, f byte) Info {
	reserved := func(why string) Info {
		in.Kind, in.Problem, in.Name = Reserved, why, ""
		return in
	}
	ref := "EN 13757-1:2021 " + t.mediaRef[a]
	// Gas load profiles of one quantity (Table 44): D and E are the C and
	// D of the captured value.
	if a == 7 && cc == 99 {
		if q, ok := t.mediaQ[[2]byte{a, d}]; ok {
			if _, ok := q.d[e]; ok && f == 255 {
				captured := media(Info{Code: Code{a, 0, d, e, 0, 255}, Medium: in.Medium}, t, a, 0, d, e, 0, 255)
				if captured.Valid() {
					in.Kind, in.Ref = Standard, "EN 13757-1:2021 11.3.4.9 Table 44"
					in.Quantity, in.Processing, in.Classes = "load profile of "+captured.Quantity, captured.Processing, []uint16{7}
					in.Name = captured.Name + "Profile"
					return channelName(in, b)
				}
			}
		}
	}
	q, ok := t.mediaQ[[2]byte{a, cc}]
	if !ok {
		return reserved(fmt.Sprintf("%s C %d D %d E %d is not allocated (%s)", in.Medium, cc, d, e, ref))
	}
	p, ok := q.d[d]
	if !ok {
		return reserved(fmt.Sprintf("%s D %d is reserved for C %d (%s, D table %s)", in.Medium, d, cc, ref, q.dTable))
	}
	in.Kind, in.Ref = Standard, ref
	in.Quantity, in.Processing = q.label, p.label
	name := t.prefix[a] + q.q + p.suffix
	rule := q.e
	if r, ok := q.eByD[d]; ok {
		rule = r
	}
	switch {
	case rule == "gasAverages":
		x, ok := t.gasAvg[e]
		if !ok {
			return reserved(fmt.Sprintf("gas average E %d is reserved (Tables 38, 40)", e))
		}
		in.Class = x.label
		name += x.suffix
	case e == 0:
		in.Class = "total"
	case e == 255 && rule != "zero":
		// The examples of Tables 22 and 30 leave E unused (F-1201); the
		// name keeps it apart from E 0 (total).
		in.Class = "no rate"
		name += "NoRate"
	case rule != "zero" && t.mediaE[rule][e]:
		in.Class = fmt.Sprintf("rate %d", e)
		name += fmt.Sprintf("T%d", e)
	default:
		return reserved(fmt.Sprintf("%s E %d is reserved for C %d D %d (%s)", in.Medium, e, cc, d, ref))
	}
	switch {
	case f == 255:
	case t.billF[f]:
		in.Period = period(f)
		name += periodSuffix(f)
	default:
		return reserved(fmt.Sprintf("F %d names no billing period (EN 13757-1:2021 11.5.3)", f))
	}
	in.Classes = []uint16{3, 4}
	if strings.HasPrefix(p.label, "maximum") || strings.HasPrefix(p.label, "minimum") {
		in.Classes = []uint16{3, 4, 7}
	}
	in.Name = name
	return channelName(in, b)
}

// electricity describes A = 1 codes with a quantity in C (7.1 to 7.4).
func electricity(in Info, t *tables, b, cc, d, e, f byte) Info {
	reserved := func(why string) Info {
		in.Kind, in.Problem, in.Name = Reserved, why, ""
		return in
	}
	q, ok := t.quantities[cc]
	if !ok {
		if r, ok := lookup(t.electricityOther, cc); ok {
			return reserved(fmt.Sprintf("%s object D %d E %d is not allocated (7.5)", r.label, d, e))
		}
		return reserved(fmt.Sprintf("electricity C %d is reserved (7.1 Table 13)", cc))
	}
	p, ok := t.processing[d]
	if !ok {
		return reserved(fmt.Sprintf("electricity D %d is reserved (7.2 Table 14)", d))
	}
	in.Kind, in.Ref = Standard, "7.1 Table 13, 7.2 Table 14"
	in.Quantity, in.Processing, in.Classes = q.label, p.label, p.ic
	if q.hasPhase && q.phase > 0 {
		in.Quantity += fmt.Sprintf(", L%d", q.phase)
	}
	base := q.q
	if p.integral {
		if q.i != "" {
			base = q.i
		} else {
			base += "Integral"
		}
	}
	if q.hasPhase && q.phase > 0 {
		base += fmt.Sprintf("L%d", q.phase)
	}
	name := base + p.suffix

	// Value group E (7.3): the classifications are exclusive.
	switch {
	case q.special == "angle":
		ref, from := e/10, e%10
		rs, ok1 := t.angle[ref]
		fs, ok2 := t.angle[from]
		if !ok1 || !ok2 {
			return reserved(fmt.Sprintf("phase angle E %d is not in Table 17", e))
		}
		in.Class = fmt.Sprintf("angle of %s to %s", fs, rs)
		in.Ref += ", 7.3.4 Table 17"
		name += fs + "Ref" + rs
	case q.special == "losses":
		l, ok := t.losses[e]
		if !ok {
			return reserved(fmt.Sprintf("loss quantity E %d is reserved (Table 18)", e))
		}
		in.Class = l.label
		in.Ref += ", 7.3.5 Table 18"
		name += l.suffix
	case t.dipC[cc] && d == t.dipD:
		depth, dur := int(e/10), int(e%10)
		if depth >= len(t.dipDepth) || dur >= len(t.dipDur) {
			return reserved(fmt.Sprintf("voltage dip class E %d is not in Table 19", e))
		}
		in.Class = fmt.Sprintf("dip depth %s, duration %s", t.dipDepth[depth], t.dipDur[dur])
		in.Ref += ", 7.3.6 Table 19"
		name += fmt.Sprintf("Dip%02d", e)
	case t.harmonic(cc, d) && e != 0:
		matched := false
		for _, h := range t.harmE {
			if h.set[e] {
				in.Class = h.label
				if h.label == "harmonic" {
					in.Class = fmt.Sprintf("harmonic %d", e)
				}
				name += strings.ReplaceAll(h.suffix, "{e}", strconv.Itoa(int(e)))
				matched = true
			}
		}
		if !matched {
			return reserved(fmt.Sprintf("harmonic E %d is reserved (Table 16)", e))
		}
		in.Ref += ", 7.3.3 Table 16"
	case e == 0:
		in.Class = "total"
	case t.tariffE[e]:
		in.Class = fmt.Sprintf("rate %d", e)
		in.Ref += ", 7.3.2 Table 15"
		name += fmt.Sprintf("T%d", e)
	default:
		return reserved(fmt.Sprintf("tariff E %d is reserved (Table 15)", e))
	}

	// Value group F (7.4).
	switch {
	case f == 255:
	case p.thr && f <= 99:
		in.Period = fmt.Sprintf("threshold %d", f+1)
		in.Ref += ", 7.4.2"
		name += fmt.Sprintf("_th%d", f+1)
	case p.bill && t.billF[f]:
		in.Period = period(f)
		in.Ref += ", 7.4.1, A.3"
		name += periodSuffix(f)
	default:
		return reserved(fmt.Sprintf("F %d names no billing period or threshold for D %d (7.4)", f, d))
	}
	in.Name = name
	return channelName(in, b)
}

// channelName marks a measurement channel other than 0 in the name.
func channelName(in Info, b byte) Info {
	if b >= 1 && b <= 64 && in.Name != "" {
		in.Name += fmt.Sprintf("Ch%d", b)
	}
	return in
}

// harmonic reports whether E of this C and D is a harmonic (Table 16;
// IEC 62056-6-2:2023 Tables 55 and 56, F-266).
func (t *tables) harmonic(c, d byte) bool {
	for _, r := range t.harmRules {
		if r[0][c] && r[1][d] {
			return true
		}
	}
	return false
}

func tableRef(t string) string {
	if clause, ok := strings.CutPrefix(t, "6-2 "); ok {
		return "IEC 62056-6-2:2023 " + clause
	}
	switch t {
	case "8":
		return "6.1 Table 8"
	case "9":
		return "6.2 Table 9"
	case "10":
		return "6.3 Table 10"
	case "11":
		return "6.4 Table 11"
	case "12":
		return "6.5 Table 12"
	case "20":
		return "7.5.1 Table 20"
	case "21":
		return "7.5.2 Table 21"
	case "22":
		return "7.5.3 Table 22"
	case "23":
		return "7.5.4 Table 23"
	case "24":
		return "7.5.5 Table 24"
	}
	return "Table " + t
}

// expand fills a name template: {e}, {e+N}, {e-N}, {d}, {d-N}, {f},
// {f-N}, {E} (empty for E 0, "E<e>" otherwise), {ut} (a utility table
// number, IEC 62056-6-2:2023 6.2.40: 128 x (D mod 16) + E) and {m} (the
// medium prefix of A, EN 13757-1:2021 media 4 to 9).
func expand(tmpl string, a, d, e, f byte) string {
	var sb strings.Builder
	group := func(c byte) int {
		switch c {
		case 'd':
			return int(d)
		case 'f':
			return int(f)
		}
		return int(e)
	}
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			sb.WriteString(tmpl)
			return sb.String()
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			sb.WriteString(tmpl)
			return sb.String()
		}
		sb.WriteString(tmpl[:i])
		expr := tmpl[i+1 : i+j]
		switch {
		case expr == "E":
			if e != 0 {
				sb.WriteString("E" + strconv.Itoa(int(e)))
			}
		case expr == "m":
			sb.WriteString(model.prefix[a])
		case expr == "ut":
			sb.WriteString(strconv.Itoa(int(d%16)*128 + int(e)))
		case expr == "e", expr == "d", expr == "f":
			sb.WriteString(strconv.Itoa(group(expr[0])))
		case len(expr) > 2 && (expr[1] == '+' || expr[1] == '-'):
			n, _ := strconv.Atoi(expr[2:])
			if expr[1] == '-' {
				n = -n
			}
			sb.WriteString(strconv.Itoa(group(expr[0]) + n))
		}
		tmpl = tmpl[i+j+1:]
	}
}

// period describes a billing period F (A.3, Table A.2).
func period(f byte) string {
	switch {
	case f <= 99:
		return fmt.Sprintf("billing period with counter value %d", f)
	case f >= 101 && f <= 125:
		return fmt.Sprintf("last %d billing period(s)", f-100)
	case f == 126:
		return "unspecified number of last billing periods"
	}
	return ""
}

// periodSuffix names a billing period F: "_b03" for VZ = 3 (the suffix the
// IEC 62056-21 adapter uses), "_last1" for 101, "_lastN" for 126.
func periodSuffix(f byte) string {
	switch {
	case f <= 99:
		return fmt.Sprintf("_b%02d", f)
	case f >= 101 && f <= 125:
		return fmt.Sprintf("_last%d", f-100)
	case f == 126:
		return "_lastN"
	}
	return ""
}
