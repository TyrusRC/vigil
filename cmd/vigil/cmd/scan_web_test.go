package cmd

import (
	"net/http"
	"net/http/httptest"
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
