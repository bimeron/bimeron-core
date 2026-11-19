package routing

import (
	"os"
	"regexp/syntax"
	"runtime"
	"testing"
)

// retainedHeap returns the heap that the value built by f keeps reachable.
func retainedHeap(t *testing.T, f func() any) float64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := f()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(v)
	return float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)) / (1 << 20)
}

// TestMeasureGeoRegexWorstCase reports the heap retained by the heaviest
// datasets the regex limits accept: one fills the endpoint budget with
// anchored Unicode classes, the other the instruction budget with counted
// repetition. Set BIMERON_GEOSITE_MEASURE_WORST=1 to run it.
func TestMeasureGeoRegexWorstCase(t *testing.T) {
	if os.Getenv("BIMERON_GEOSITE_MEASURE_WORST") != "1" {
		t.Skip("BIMERON_GEOSITE_MEASURE_WORST is not set")
	}
	for _, value := range []string{`^\pL{22}$`, "[a-z]{1000}"} {
		tree, err := syntax.Parse(value, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		insts, runes := regexWeight(tree)
		n := min(maxGeoRegexInsts/insts, maxGeoRegexRunes/runes, maxGeoRegex, maxGeoRegexBytes/len(value))
		entries := make([][]byte, n)
		for i := range entries {
			entries[i] = geoDomain(1, value)
		}
		site := geoGroup("worst", entries...)
		mib := retainedHeap(t, func() any {
			d, err := DecodeGeoData(nil, site)
			if err != nil {
				t.Fatal(err)
			}
			return d
		})
		t.Logf("%d x %q: %d instructions, %d endpoints, %.1f MiB retained", n, value, n*insts, n*runes, mib)
	}
}

// TestMeasureGeoSiteRegexBudget reports how much of the regex budget a
// GeoSite dataset uses and how much heap its decoded form retains. Set
// BIMERON_GEOSITE_MEASURE to a geosite.dat file; see "Regex budgets" in
// docs/GEODATA.MD. The test fails if the dataset uses more than half of a
// total limit or a quarter of a per-expression limit; re-evaluate the limits
// before shipping such a dataset.
func TestMeasureGeoSiteRegexBudget(t *testing.T) {
	path := os.Getenv("BIMERON_GEOSITE_MEASURE")
	if path == "" {
		t.Skip("BIMERON_GEOSITE_MEASURE is not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var budget regexBudget
	var d *GeoData
	retained := retainedHeap(t, func() any {
		var err error
		if d, err = decodeGeoData(nil, data, &budget); err != nil {
			t.Fatal(err)
		}
		return d
	})
	t.Logf("%s: %d groups, %d expressions, %d regex bytes", path, len(d.sites), budget.count, budget.bytes)
	t.Logf("instructions: %d total (limit %d), %d largest (limit %d)", budget.insts, maxGeoRegexInsts, budget.maxInsts, maxGeoRegexInst)
	t.Logf("rune-range endpoints: %d total (limit %d), %d largest (limit %d)", budget.runes, maxGeoRegexRunes, budget.maxRunes, maxGeoRegexRune)
	t.Logf("retained heap after decoding: %.1f MiB", retained)
	for _, c := range []struct {
		name         string
		used, limit  int
		headroomPart int
	}{
		{"total instructions", budget.insts, maxGeoRegexInsts, 2},
		{"total endpoints", budget.runes, maxGeoRegexRunes, 2},
		{"regex count", budget.count, maxGeoRegex, 2},
		{"regex bytes", budget.bytes, maxGeoRegexBytes, 2},
		{"largest expression instructions", budget.maxInsts, maxGeoRegexInst, 4},
		{"largest expression endpoints", budget.maxRunes, maxGeoRegexRune, 4},
	} {
		if c.used*c.headroomPart > c.limit {
			t.Errorf("%s: %d exceeds 1/%d of the limit %d; re-evaluate the limits", c.name, c.used, c.headroomPart, c.limit)
		}
	}
}
