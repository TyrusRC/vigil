package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
)

// vigilOutputGlobs are the filename patterns vigil writes into a scan dir.
// Used to delete scan output without touching a caller's other files.
// NOTE: every pattern must match only files vigil itself writes — a broad
// wildcard like "*.log" would delete a caller's unrelated files in their
// --output-dir. Tool logs are unified into tools.jsonl, so no "*.log" entry.
var vigilOutputGlobs = []string{
	"vigil-report.*", "vigil-partial.json", "tools.jsonl",
	"nikto.json", "dalfox.json", "wpscan.json", "arjun.json",
}

// deleteScanOutput removes this scan's saved artifacts from dir and returns how
// many entries were removed. When auto is true the dir was created by vigil
// (no --output-dir), so the whole directory is removed; otherwise only
// vigil-produced files are deleted so a caller's --output-dir is never nuked.
func deleteScanOutput(dir string, auto bool) int {
	if dir == "" {
		return 0
	}
	if auto {
		if err := os.RemoveAll(dir); err == nil {
			return 1
		}
		return 0
	}
	n := 0
	for _, g := range vigilOutputGlobs {
		matches, _ := filepath.Glob(filepath.Join(dir, g))
		for _, m := range matches {
			if os.Remove(m) == nil {
				n++
			}
		}
	}
	return n
}

// fpMarkHandler serves POST /api/fp: the web UI calls it when an operator
// marks a finding a false positive (fp=true) or restores it (fp=false). The
// decision is written to the FP database at fpPath so a future
// `vigil scan --fp-database <path>` downgrades the same (type,url,param).
//
// find resolves a finding ID to the live finding; mu serializes the
// load-modify-save so concurrent requests don't clobber each other.
func fpMarkHandler(fpPath string, mu *sync.Mutex, find func(id string) *core.Finding) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ID     string `json:"id"`
			FP     bool   `json:"fp"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}

		target := find(body.ID)
		if target == nil {
			http.Error(w, `{"error":"finding not found"}`, http.StatusNotFound)
			return
		}

		mu.Lock()
		db := scanner.LoadFPFeedback(fpPath)
		if body.FP {
			db.MarkFP(target, body.Reason)
		} else {
			db.UnmarkFP(target)
		}
		err := db.Save()
		count := db.Count()
		mu.Unlock()
		if err != nil {
			http.Error(w, `{"error":"could not save FP database"}`, http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"path":%q,"count":%d}`, fpPath, count)
	}
}
