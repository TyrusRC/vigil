package scanner

import (
	"path/filepath"
	"testing"

	"github.com/TyrusRC/vigil/internal/core"
)

func TestFPFeedback_MarkUnmarkPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".vigil-fp.json")

	f := core.NewFinding("SQL Injection", core.SeverityHigh)
	f.URL = "https://example.com/item"
	f.Parameter = "id"

	db := LoadFPFeedback(path)
	db.MarkFP(f, "manual: reflected but not exploitable")
	if !db.IsFP(f) {
		t.Fatal("IsFP = false after MarkFP")
	}
	if err := db.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from disk: the mark must survive so future scans suppress it.
	reloaded := LoadFPFeedback(path)
	if !reloaded.IsFP(f) {
		t.Fatal("FP mark did not persist across reload")
	}

	// A different finding must NOT match.
	other := core.NewFinding("XSS", core.SeverityMedium)
	other.URL = "https://example.com/item"
	other.Parameter = "q"
	if reloaded.IsFP(other) {
		t.Fatal("unrelated finding matched FP database")
	}

	// Unmark removes it.
	reloaded.UnmarkFP(f)
	if reloaded.IsFP(f) {
		t.Fatal("IsFP = true after UnmarkFP")
	}
	if err := reloaded.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if LoadFPFeedback(path).IsFP(f) {
		t.Fatal("unmark did not persist across reload")
	}
}
