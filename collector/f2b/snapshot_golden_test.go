package f2b

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapshotGolden is the JSON counterpart of TestCollectGolden
// (collector_golden_test.go): both gather from the exact same
// newGoldenCollector() fixture, but this one pins the Snapshot shape
// docs/metrics-json-schema-v1.md documents - field names, types, ordering
// and presence rules - as a readable JSON diff, rather than Prometheus text
// exposition. Any accidental change to a field name, type, ordering rule or
// presence rule anywhere in Snapshot's JSON tags shows up here.
//
// Run with `go test ./collector/f2b/... -run TestSnapshotGolden -update` to
// regenerate testdata/snapshot.golden.json after a deliberate, reviewed
// schema change - exactly the same flag TestCollectGolden uses, and the
// same flag variable (there is only one `-update` for this package).
func TestSnapshotGolden(t *testing.T) {
	snap := gatherGoldenSnapshot(t)
	got := marshalSnapshotIndent(t, snap)

	goldenPath := filepath.Join("testdata", "snapshot.golden.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("create testdata dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file (run with -update to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("snapshot JSON does not match %s (run with -update to regenerate)\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
	}

	// Determinism check: a second, independently constructed collector
	// against an identical fixture must gather byte-identical JSON. Every
	// field in Snapshot is either sourced from the fixed fixture data or
	// computed from the injected clock seam (c.nowFn), never from
	// time.Now() or unsorted map iteration reaching output directly - so
	// this must hold. If it ever fails, that is a genuine production bug
	// (some field escaped the clock seam, or an unsorted map iteration
	// order reached output undeduplicated) to be reported, not papered
	// over by excluding the offending field from this comparison.
	got2 := marshalSnapshotIndent(t, gatherGoldenSnapshot(t))
	if string(got) != string(got2) {
		t.Errorf("snapshot JSON is not deterministic across two freshly constructed, identically-fixtured collectors:\n--- first ---\n%s\n--- second ---\n%s", got, got2)
	}
}

// gatherGoldenSnapshot builds a fresh fake socket server, fixture database
// and Collector (newGoldenCollector), then gathers a Snapshot with
// SnapshotOptions mirroring Collect()'s own call exactly (full sections, the
// collector's configured ceiling, alert-state mutation on) - so this is a
// faithful JSON rendering of the very same gather TestCollectGolden pins as
// Prometheus text, not some other, looser gather.
func gatherGoldenSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)

	snap, err := c.Snapshot(SnapshotOptions{
		Include:                    allSections,
		MaxIPs:                     c.maxIPMetrics,
		MutateAlertState:           true,
		HonorExitOnSocketConnError: true,
	})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	return snap
}

// marshalSnapshotIndent renders snap the way an operator diffing the golden
// fixture would want to read it: indented, with a trailing newline.
func marshalSnapshotIndent(t *testing.T, snap *Snapshot) []byte {
	t.Helper()
	got, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	return append(got, '\n')
}
