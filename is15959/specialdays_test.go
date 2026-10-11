package is15959

import (
	"strings"
	"testing"
)

// The special days table (class 11, 0.0.11.0.0.255) in the Part 2 and
// Part 3 profiles: its entries readable by the reader and settable by the
// utility settings association, as the activity calendar is; insert and
// delete executable by the utility settings association only; nobody else
// (public, push, firmware, display) has rights on it; the reference says
// it is our reading. Part 1 profiles do not list it.
//
// Covers: SIG-IPE-980
func TestSpecialDaysTable(t *testing.T) {
	for _, id := range []string{"part2-1ph", "part2-3ph", "part3-ctpt", "part3-boundary"} {
		sp, _ := Get(id)
		o := sp.Object(SpecialDaysTable, 2)
		if o == nil || o.Class != ClassSpecialDays || o.Name != "specialDaysTable" || o.Group != GroupProgrammable || o.Type != "array" {
			t.Fatalf("%s: special days entries %+v", id, o)
		}
		if !strings.Contains(o.Ref, "our reading") {
			t.Errorf("%s: reference %q does not say it is our reading", id, o.Ref)
		}
		cal, ok := sp.Access(ClassActivityCalendar, "0.0.13.0.0.255", 10, false)
		if !ok || o.Access != cal {
			t.Errorf("%s: special days rights %v, activity calendar %v", id, o.Access, cal)
		}
		for r, want := range map[Role]Right{PC: 0, MR: Read, US: Read | Write, Push: 0, FW: 0, IHD: 0} {
			if got := o.Access.Of(r); got != want {
				t.Errorf("%s: %v has %v on the entries, want %v", id, r, got, want)
			}
		}
		for m, name := range map[int8]string{1: "special-day-insert", 2: "special-day-delete"} {
			a, ok := sp.Access(ClassSpecialDays, SpecialDaysTable, m, true)
			if !ok || a.Of(US) != Exec || a.Of(MR) != 0 || sp.Method(name) == nil || sp.Method(name).Method != m {
				t.Errorf("%s: method %d rights %v", id, m, a)
			}
		}
		if w := sp.Method("special-days"); w == nil || w.Attr != 2 || w.Method != 0 || w.Access.Of(US) != Read|Write {
			t.Errorf("%s: table write %+v", id, w)
		}
	}
	for _, id := range []string{"part1-category-A", "part1-category-B", "part1-category-C"} {
		sp, _ := Get(id)
		if sp.Object(SpecialDaysTable, 2) != nil {
			t.Errorf("%s lists the special days table", id)
		}
	}
}
