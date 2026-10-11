package is15959_test

import (
	"testing"

	"github.com/cB-Sigma/dlms/is15959"
)

// IS 16444 (Part 1):2015 11.5 and 11.7, (Part 2):2017 10.2: the head-end
// names every event code the IS 15959 logs carry, pairs occurrences with
// restorations and classes tampers (our classification, F-1921).
//
// Covers: SIG-IPE-3550
func TestIS16444EventInfo(t *testing.T) {
	infos := is15959.EventInfos()
	if len(infos) == 0 {
		t.Fatal("no event codes")
	}
	keyName := map[string]string{}
	for _, e := range infos {
		if e.Key == "" || e.Category == "" || e.Kind == "" || e.Condition == "" {
			t.Errorf("code %d = %+v: want key, category, kind and condition", e.Code, e)
		}
		if n, ok := keyName[e.Key]; ok && n != e.Name {
			t.Errorf("key %s names %q and %q", e.Key, n, e.Name)
		}
		keyName[e.Key] = e.Name
		if e.Pair != 0 {
			p, ok := is15959.Info(e.Pair)
			if !ok || p.Pair != e.Code || p.Condition != e.Condition || p.Kind == e.Kind || p.Tamper != e.Tamper {
				t.Errorf("code %d and its pair %d = %+v, %+v: want a matched occurrence and restoration", e.Code, e.Pair, e, p)
			}
		}
	}
	// Every code of every profile's logs is described.
	for _, id := range is15959.IDs() {
		sp, _ := is15959.Get(id)
		for _, l := range sp.Events {
			for _, c := range l.Codes {
				if _, ok := is15959.Info(c.Code); !ok {
					t.Errorf("%s %s code %d has no EventInfo", sp.ID, l.Name, c.Code)
				}
			}
		}
		for _, b := range sp.ESW {
			if is15959.ESWKey(b) == "" {
				t.Errorf("%s ESW bit %d has no key", sp.ID, b.Bit)
			}
		}
	}
	for code, want := range map[int]struct {
		key, kind string
		tamper    bool
	}{
		201: {"magneticInfluence", is15959.KindOccurrence, true}, 202: {"magneticInfluenceCleared", is15959.KindRestoration, true},
		203: {"neutralDisturbance", is15959.KindOccurrence, true}, 251: {"coverOpened", is15959.KindSingle, true},
		51: {"currentReversedL1", is15959.KindOccurrence, true}, 65: {"currentBypass", is15959.KindOccurrence, true},
		7: {"overVoltage", is15959.KindOccurrence, false}, 101: {"powerFailure", is15959.KindOccurrence, false},
		102: {"powerFailureCleared", is15959.KindRestoration, false},
		301: {"loadDisconnected", is15959.KindSingle, false}, 302: {"loadConnected", is15959.KindSingle, false},
		212: {"prePaidMode", is15959.KindSingle, false}, 178: {"importExportMetering", is15959.KindSingle, false},
	} {
		e, _ := is15959.Info(code)
		if e.Key != want.key || e.Kind != want.kind || e.Tamper != want.tamper {
			t.Errorf("code %d = %+v, want key %s, kind %s, tamper %v", code, e, want.key, want.kind, want.tamper)
		}
	}
	if _, ok := is15959.Info(999); ok {
		t.Error("code 999 is described")
	}
}
