package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
)

func TestFPMarkHandler(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".vigil-fp.json")

	f := core.NewFinding("SQL Injection", core.SeverityHigh)
	f.ID = "find-1"
	f.URL = "https://example.com/item"
	f.Parameter = "id"

	var mu sync.Mutex
	h := fpMarkHandler(dbPath, &mu, func(id string) *core.Finding {
		if id == f.ID {
			return f
		}
		return nil
	})

	post := func(bodyJSON string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/fp", strings.NewReader(bodyJSON)))
		return rec
	}

	// Mark as FP → persisted and matchable by the scanner.
	if rec := post(`{"id":"find-1","fp":true,"reason":"ui"}`); rec.Code != http.StatusOK {
		t.Fatalf("mark code = %d, body=%s", rec.Code, rec.Body)
	}
	if !scanner.LoadFPFeedback(dbPath).IsFP(f) {
		t.Fatal("finding not recorded in FP database after mark")
	}

	// Unmark → removed.
	if rec := post(`{"id":"find-1","fp":false}`); rec.Code != http.StatusOK {
		t.Fatalf("unmark code = %d", rec.Code)
	}
	if scanner.LoadFPFeedback(dbPath).IsFP(f) {
		t.Fatal("finding still in FP database after unmark")
	}

	// Unknown finding → 404.
	if rec := post(`{"id":"nope","fp":true}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id code = %d, want 404", rec.Code)
	}

	// Wrong method → 405.
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/fp", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code = %d, want 405", rec.Code)
	}
}

func TestDeleteScanOutput_Auto_RemovesDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "vigil-report-x")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sub, "vigil-report.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(sub, "tools.jsonl"), []byte("{}\n"), 0o644)

	if n := deleteScanOutput(sub, true); n != 1 {
		t.Fatalf("auto delete returned %d, want 1", n)
	}
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatal("auto delete should remove the whole dir")
	}
}

func TestDeleteScanOutput_UserDir_KeepsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vigil-report.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "tools.jsonl"), []byte("{}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "nikto.log"), []byte("x"), 0o644)
	keep := filepath.Join(dir, "my-notes.txt")
	os.WriteFile(keep, []byte("important"), 0o644)

	n := deleteScanOutput(dir, false)
	if n != 3 {
		t.Fatalf("removed %d vigil files, want 3", n)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("must NOT delete the caller's own files")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("must NOT remove the user's --output-dir itself")
	}
}
