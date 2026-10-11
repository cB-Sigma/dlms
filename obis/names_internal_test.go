package obis

import "testing"

// Covers: SIG-IPE-1245, SIG-IPE-2132
func TestEveryObjectRowNamesUniquely(t *testing.T) {
	// Every code of every object row (all the values its groups allow,
	// channels 0 and 1, F 255 and the first billing codes) and every
	// electricity quantity with every processing code: no two codes derive
	// the same name, across media and across interface classes. A code may
	// name its objects of different classes differently (NameFor).
	owner := map[string]Code{}
	var n int
	check := func(c Code, class uint16) {
		name := DescribeClass(c, class).Name
		if name == "" {
			return
		}
		n++
		if prev, dup := owner[name]; dup && prev != c {
			t.Fatalf("%s and %s both derive %q", prev, c, name)
		}
		owner[name] = c
	}
	values := func(s set) []byte {
		var out []byte
		for v := range s {
			if s[v] {
				out = append(out, byte(v))
			}
		}
		return out
	}
	for _, o := range model.objects {
		for _, a := range values(o.a) {
			for _, b := range []byte{0, 1} {
				if !o.b[b] {
					continue
				}
				for _, c := range values(o.c) {
					for _, d := range values(o.d) {
						for _, e := range values(o.e) {
							for _, f := range []byte{255, 0, 101, 126} {
								if !o.f[f] {
									continue
								}
								code := Code{a, b, c, d, e, f}
								check(code, 0)
								for _, class := range o.ic {
									check(code, class)
								}
							}
						}
					}
				}
			}
		}
	}
	for c := range model.quantities {
		for d := range model.processing {
			for e := 0; e <= 127; e++ {
				for _, f := range []byte{255, 0, 101} {
					check(Code{1, 0, c, d, byte(e), f}, 0)
				}
			}
		}
	}
	// Media 4 to 9 (EN 13757-1:2021): every quantity with every D code
	// and representative E and F values, and the gas load profiles.
	for k, q := range model.mediaQ {
		for d := range q.d {
			for _, e := range []byte{0, 1, 9, 11, 28, 63, 255} {
				for _, f := range []byte{255, 0, 101, 126} {
					check(Code{k[0], 0, k[1], d, e, f}, 0)
					check(Code{k[0], 1, k[1], d, e, f}, 0)
				}
			}
			if k[0] == 7 {
				check(Code{7, 0, 99, k[1], d, 255}, 0)
			}
		}
	}
	if n < 100000 {
		t.Fatalf("only %d names checked", n)
	}
	t.Logf("%d names, %d distinct", n, len(owner))
}
