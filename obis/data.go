package obis

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The tables of IEC 62056-6-1:2023 live in obis.yaml, transcribed as facts
// with clause and table references; the names and labels there are ours.
//
//go:embed obis.yaml
var tableYAML []byte

// set is a set of values of one value group.
type set [256]bool

// parseSet reads "3", "0-9", "1,4-9,15" or "*".
func parseSet(s string) (set, error) {
	var out set
	s = strings.TrimSpace(s)
	if s == "*" {
		for i := range out {
			out[i] = true
		}
		return out, nil
	}
	if s == "" {
		return out, fmt.Errorf("empty value set")
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 || a > 255 {
			return out, fmt.Errorf("bad value %q in %q", lo, s)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 255 {
				return out, fmt.Errorf("bad range %q in %q", part, s)
			}
		}
		for v := a; v <= b; v++ {
			out[v] = true
		}
	}
	return out, nil
}

func mustSet(s string) set {
	v, err := parseSet(s)
	if err != nil {
		panic("obis: obis.yaml: " + err.Error())
	}
	return v
}

type keyed struct {
	V     string `yaml:"v"`
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
}

type rawTables struct {
	Source string  `yaml:"source"`
	A      []keyed `yaml:"a"`
	B      []keyed `yaml:"b"`
	Mfr    struct {
		B, C, D, E, F string
	} `yaml:"manufacturer"`
	MfrGeneral struct{ A, B, C, D string } `yaml:"manufacturerGeneral"`
	Utility    struct{ A, B string }       `yaml:"utility"`
	Consortia  struct{ A, B, C string }    `yaml:"consortia"`
	Country    struct{ A, B, C string }    `yaml:"country"`
	ConsortiaD []struct {
		D    int    `yaml:"d"`
		Name string `yaml:"name"`
	} `yaml:"consortiaD"`
	CountryD []struct {
		D    int    `yaml:"d"`
		Name string `yaml:"name"`
	} `yaml:"countryD"`
	AbstractC    []keyed `yaml:"abstractC"`
	ElectricityC []struct {
		C       []int  `yaml:"c"`
		Q       string `yaml:"q"`
		I       string `yaml:"i"`
		Label   string `yaml:"label"`
		Special string `yaml:"special"`
	} `yaml:"electricityC"`
	ElectricityOtherC []keyed `yaml:"electricityOtherC"`
	ElectricityD      []struct {
		D         int    `yaml:"d"`
		S         string `yaml:"s"`
		Integral  bool   `yaml:"integral"`
		Bill      bool   `yaml:"bill"`
		Threshold bool   `yaml:"threshold"`
		IC        string `yaml:"ic"`
		Label     string `yaml:"label"`
	} `yaml:"electricityD"`
	TariffE   string `yaml:"tariffE"`
	Harmonics struct {
		Rules []struct{ C, D string } `yaml:"rules"`
		E     []struct {
			V     string `yaml:"v"`
			S     string `yaml:"s"`
			Label string `yaml:"label"`
		} `yaml:"e"`
	} `yaml:"harmonics"`
	AngleIndex []struct {
		I int    `yaml:"i"`
		S string `yaml:"s"`
	} `yaml:"angleIndex"`
	LossesE []struct {
		E     int    `yaml:"e"`
		S     string `yaml:"s"`
		Label string `yaml:"label"`
	} `yaml:"lossesE"`
	Dips struct {
		C        string   `yaml:"c"`
		D        int      `yaml:"d"`
		Depth    []string `yaml:"depth"`
		Duration []string `yaml:"duration"`
	} `yaml:"dips"`
	OtherMediaC []keyed `yaml:"otherMediaC"`
	Objects     []struct {
		T    string `yaml:"t"`
		A    string `yaml:"a"`
		B    string `yaml:"b"`
		C    string `yaml:"c"`
		D    string `yaml:"d"`
		E    string `yaml:"e"`
		F    string `yaml:"f"`
		IC   string `yaml:"ic"`
		Name string `yaml:"name"`
	} `yaml:"objects"`
	Classes []struct {
		A, B, C, D, E string
		IC            string `yaml:"ic"`
	} `yaml:"classes"`
	Media []struct {
		A      string `yaml:"a"`
		Prefix string `yaml:"prefix"`
		Ref    string `yaml:"ref"`
		Groups []struct {
			D    string            `yaml:"d"`
			E    string            `yaml:"e"`
			EByD map[string]string `yaml:"eByD"`
			C    []struct {
				C     int    `yaml:"c"`
				Q     string `yaml:"q"`
				Label string `yaml:"label"`
			} `yaml:"c"`
		} `yaml:"groups"`
	} `yaml:"media"`
	MediaD map[string][]struct {
		D     int    `yaml:"d"`
		S     string `yaml:"s"`
		Label string `yaml:"label"`
	} `yaml:"mediaD"`
	MediaE struct {
		Rates9      string `yaml:"rates9"`
		Rates63     string `yaml:"rates63"`
		GasAverages []struct {
			E     int    `yaml:"e"`
			S     string `yaml:"s"`
			Label string `yaml:"label"`
		} `yaml:"gasAverages"`
	} `yaml:"mediaE"`
	ReservedFor []struct {
		A, B, C, D, E, F string
		Who              string `yaml:"who"`
		Label            string `yaml:"label"`
	} `yaml:"reservedFor"`
}

// rangeEntry maps a value set to a key and label.
type rangeEntry struct {
	set   set
	key   string
	label string
}

func ranges(in []keyed) []rangeEntry {
	out := make([]rangeEntry, 0, len(in))
	for _, k := range in {
		out = append(out, rangeEntry{mustSet(k.V), k.Key, k.Label})
	}
	return out
}

func lookup(rs []rangeEntry, v byte) (rangeEntry, bool) {
	for _, r := range rs {
		if r.set[v] {
			return r, true
		}
	}
	return rangeEntry{}, false
}

// quantity is one electricity C code (Table 13).
type quantity struct {
	c        byte
	phase    int // 0: sum of phases (or the only code), 1 to 3: L1 to L3
	q, i     string
	label    string
	special  string
	hasPhase bool
}

// processing is one electricity D code (Table 14).
type processing struct {
	suffix              string
	integral, bill, thr bool
	label               string
	ic                  []uint16
}

// object is one row of the standard object tables.
type object struct {
	table            string
	a, b, c, d, e, f set
	fBill            bool
	name             string
	ic               []uint16 // interface classes (IEC 62056-6-2:2023 clause 6)
}

// classRow gives the interface classes of codes IEC 62056-6-1 defines.
type classRow struct {
	a, b, c, d, e set
	ic            []uint16
}

type reservation struct {
	a, b, c, d, e, f set
	who, label       string
}

// suffixed is a name suffix with its label (a D or E code).
type suffixed struct{ suffix, label string }

// mediaQuantity is one C code of media 4 to 9 (EN 13757-1:2021 11.3):
// its name, the D table and the E rule that apply to it.
type mediaQuantity struct {
	q, label, ref string
	d             map[byte]suffixed
	dTable        string
	e             string // rates9, rates63, zero, gasAverages
	eByD          map[byte]string
}

// tables is the parsed model.
type tables struct {
	source                                string
	a, b                                  []rangeEntry
	mfrB, mfrC, mfrD, mfrE, mfrF          set
	mgA, mgB, mgC, mgD                    set
	utilA, utilB                          set
	consA, consB, consC                   set
	ctryA, ctryB, ctryC                   set
	consortia, countries                  map[byte]string
	abstractC, electricityOther, otherMed []rangeEntry
	quantities                            map[byte]quantity
	processing                            map[byte]processing
	tariffE                               set
	harmRules                             [][2]set
	harmE                                 []struct {
		set           set
		suffix, label string
	}
	angle      map[byte]string
	losses     map[byte]struct{ suffix, label string }
	dipC       set
	dipD       byte
	dipDepth   []string
	dipDur     []string
	objects    []object
	objectsByC [256][]object
	classes    []classRow
	prefix     [256]string               // medium prefix by A (4 to 9)
	mediaRef   [256]string               // clause by A
	mediaQ     map[[2]byte]mediaQuantity // by A and C
	mediaE     map[string]set
	gasAvg     map[byte]suffixed
	reserved   []reservation
	billF      set
}

var model = load()

func load() *tables {
	var r rawTables
	if err := yaml.Unmarshal(tableYAML, &r); err != nil {
		panic("obis: obis.yaml: " + err.Error())
	}
	t := &tables{source: r.Source, a: ranges(r.A), b: ranges(r.B)}
	t.mfrB, t.mfrC, t.mfrD, t.mfrE, t.mfrF = mustSet(r.Mfr.B), mustSet(r.Mfr.C), mustSet(r.Mfr.D), mustSet(r.Mfr.E), mustSet(r.Mfr.F)
	t.mgA, t.mgB, t.mgC, t.mgD = mustSet(r.MfrGeneral.A), mustSet(r.MfrGeneral.B), mustSet(r.MfrGeneral.C), mustSet(r.MfrGeneral.D)
	t.utilA, t.utilB = mustSet(r.Utility.A), mustSet(r.Utility.B)
	t.consA, t.consB, t.consC = mustSet(r.Consortia.A), mustSet(r.Consortia.B), mustSet(r.Consortia.C)
	t.ctryA, t.ctryB, t.ctryC = mustSet(r.Country.A), mustSet(r.Country.B), mustSet(r.Country.C)
	t.consortia, t.countries = map[byte]string{}, map[byte]string{}
	for _, c := range r.ConsortiaD {
		t.consortia[byte(c.D)] = c.Name
	}
	for _, c := range r.CountryD {
		if _, dup := t.countries[byte(c.D)]; dup {
			panic(fmt.Sprintf("obis: obis.yaml: country D %d twice", c.D))
		}
		t.countries[byte(c.D)] = c.Name
	}
	t.abstractC, t.electricityOther, t.otherMed = ranges(r.AbstractC), ranges(r.ElectricityOtherC), ranges(r.OtherMediaC)
	t.quantities = map[byte]quantity{}
	for _, q := range r.ElectricityC {
		for i, c := range q.C {
			if _, dup := t.quantities[byte(c)]; dup {
				panic(fmt.Sprintf("obis: obis.yaml: electricity C %d twice", c))
			}
			t.quantities[byte(c)] = quantity{c: byte(c), phase: i, q: q.Q, i: q.I, label: q.Label, special: q.Special, hasPhase: len(q.C) == 4}
		}
	}
	t.processing = map[byte]processing{}
	for _, d := range r.ElectricityD {
		t.processing[byte(d.D)] = processing{d.S, d.Integral, d.Bill, d.Threshold, d.Label, mustClasses(d.IC)}
	}
	t.tariffE = mustSet(r.TariffE)
	for _, h := range r.Harmonics.Rules {
		t.harmRules = append(t.harmRules, [2]set{mustSet(h.C), mustSet(h.D)})
	}
	for _, h := range r.Harmonics.E {
		t.harmE = append(t.harmE, struct {
			set           set
			suffix, label string
		}{mustSet(h.V), h.S, h.Label})
	}
	t.angle = map[byte]string{}
	for _, a := range r.AngleIndex {
		t.angle[byte(a.I)] = a.S
	}
	t.losses = map[byte]struct{ suffix, label string }{}
	for _, l := range r.LossesE {
		t.losses[byte(l.E)] = struct{ suffix, label string }{l.S, l.Label}
	}
	// The L2 block (51 to 70) and the L3 block (71 to 90) repeat the L1
	// block 31 to 50 (Table 18; finding F-263).
	for e := byte(31); e <= 50; e++ {
		l1 := t.losses[e]
		for i, phase := range []string{"L2", "L3"} {
			t.losses[e+20*byte(i+1)] = struct{ suffix, label string }{strings.TrimSuffix(l1.suffix, "L1") + phase, phase + strings.TrimPrefix(l1.label, "L1")}
		}
	}
	t.dipC, t.dipD, t.dipDepth, t.dipDur = mustSet(r.Dips.C), byte(r.Dips.D), r.Dips.Depth, r.Dips.Duration
	t.billF = mustSet("0-99,101-126,255")
	// A name an abstract table gives is not reused for an electricity
	// object: the electricity twin is prefixed (0.0.99.1.0.255 is
	// loadProfile1, 1.0.99.1.0.255 electricityLoadProfile1).
	abstract := map[string]bool{}
	for _, o := range r.Objects {
		if o.A == "0" {
			abstract[baseName(o.Name)] = true
		}
	}
	for _, o := range r.Objects {
		name := o.Name
		if o.A == "1" && abstract[baseName(name)] {
			name = "electricity" + strings.ToUpper(name[:1]) + name[1:]
		}
		ob := object{table: o.T, a: mustSet(o.A), b: mustSet(o.B), c: mustSet(o.C), d: mustSet(o.D), e: mustSet(o.E), name: name, ic: mustClasses(o.IC)}
		switch o.F {
		case "":
			ob.f = mustSet("255")
		case "bill":
			ob.f, ob.fBill = t.billF, true
		default:
			ob.f = mustSet(o.F)
		}
		t.objects = append(t.objects, ob)
		for c := range ob.c {
			if ob.c[c] {
				t.objectsByC[c] = append(t.objectsByC[c], ob)
			}
		}
	}
	t.mediaQ, t.mediaE, t.gasAvg = map[[2]byte]mediaQuantity{}, map[string]set{}, map[byte]suffixed{}
	t.mediaE["rates9"], t.mediaE["rates63"] = mustSet(r.MediaE.Rates9), mustSet(r.MediaE.Rates63)
	for _, g := range r.MediaE.GasAverages {
		t.gasAvg[byte(g.E)] = suffixed{g.S, g.Label}
	}
	dTables := map[string]map[byte]suffixed{}
	for name, rows := range r.MediaD {
		m := map[byte]suffixed{}
		for _, x := range rows {
			if _, dup := m[byte(x.D)]; dup {
				panic(fmt.Sprintf("obis: obis.yaml: media D table %s has D %d twice", name, x.D))
			}
			m[byte(x.D)] = suffixed{x.S, x.Label}
		}
		dTables[name] = m
	}
	for _, m := range r.Media {
		as := mustSet(m.A)
		for a := range as {
			if !as[a] {
				continue
			}
			t.prefix[a], t.mediaRef[a] = m.Prefix, m.Ref
			for _, g := range m.Groups {
				d, ok := dTables[g.D]
				if !ok {
					panic("obis: obis.yaml: unknown media D table " + g.D)
				}
				eByD := map[byte]string{}
				for k, v := range g.EByD {
					n, err := strconv.Atoi(k)
					if err != nil {
						panic("obis: obis.yaml: bad eByD key " + k)
					}
					eByD[byte(n)] = v
				}
				for _, c := range g.C {
					k := [2]byte{byte(a), byte(c.C)}
					if _, dup := t.mediaQ[k]; dup {
						panic(fmt.Sprintf("obis: obis.yaml: medium %d C %d twice", a, c.C))
					}
					t.mediaQ[k] = mediaQuantity{q: c.Q, label: c.Label, ref: m.Ref, d: d, dTable: g.D, e: g.E, eByD: eByD}
				}
			}
		}
	}
	for _, x := range r.Classes {
		t.classes = append(t.classes, classRow{mustSet(x.A), mustSet(x.B), mustSet(x.C), mustSet(x.D), mustSet(x.E), mustClasses(x.IC)})
	}
	for _, x := range r.ReservedFor {
		t.reserved = append(t.reserved, reservation{mustSet(x.A), mustSet(x.B), mustSet(x.C), mustSet(x.D), mustSet(x.E), mustSet(x.F), x.Who, x.Label})
	}
	return t
}

// Counts is the size of the model, for tests and the report.
type Counts struct {
	Media        int // allocated A values (Table 3)
	Countries    int // Table 7 rows
	Consortia    int // Table 6 rows
	ElectricityC int // quantity C values (Table 13)
	ElectricityD int // D values (Table 14)
	Harmonics    int // E values of Table 16 other than 0
	AngleCodes   int // E values of Table 17
	LossCodes    int // E values of Table 18
	DipClasses   int // E values of Table 19
	ObjectRows   int // rows of Tables 8 to 12 and 20 to 24, 6-2 clause 6 and EN 13757-1 clause 11.3
	MediaC       int // quantity C codes of media 4 to 9 (EN 13757-1:2021), per A
	MediaD       int // D codes of the EN 13757-1:2021 D tables
}

// Stats counts the model.
func Stats() Counts {
	t := model
	var c Counts
	for v := 0; v < 256; v++ {
		if _, ok := lookup(t.a, byte(v)); ok {
			c.Media++
		}
		for _, h := range t.harmE {
			if h.set[v] {
				c.Harmonics++
			}
		}
	}
	c.Countries, c.Consortia = len(t.countries), len(t.consortia)
	c.ElectricityC, c.ElectricityD = len(t.quantities), len(t.processing)
	c.AngleCodes = len(t.angle) * len(t.angle)
	c.LossCodes = len(t.losses)
	c.DipClasses = len(t.dipDepth) * len(t.dipDur)
	c.ObjectRows = len(t.objects)
	c.MediaC = len(t.mediaQ)
	seen := map[string]bool{}
	for _, q := range t.mediaQ {
		if !seen[q.dTable] {
			seen[q.dTable] = true
			c.MediaD += len(q.d)
		}
	}
	return c
}

// baseName is a name template without its placeholders.
func baseName(tmpl string) string {
	var sb strings.Builder
	depth := 0
	for _, r := range tmpl {
		switch {
		case r == '{':
			depth++
		case r == '}':
			depth--
		case depth == 0:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// mustClasses reads "1,3,4" (empty: none given).
func mustClasses(s string) []uint16 {
	if s == "" {
		return nil
	}
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 65535 {
			panic("obis: obis.yaml: bad interface class list " + s)
		}
		out = append(out, uint16(n))
	}
	return out
}
