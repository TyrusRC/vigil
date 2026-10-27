package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TyrusRC/vigil/internal/scanner"
)

// runnerFunc adapts an inspection callback into a Runner that returns a canned
// result, letting a test observe the ScanRequest the server built.
func runnerFunc(inspect func(ScanRequest), result *scanner.ScanResult) Runner {
	return inspectRunner{inspect: inspect, result: result}
}

type inspectRunner struct {
	inspect func(ScanRequest)
	result  *scanner.ScanResult
}

func (r inspectRunner) Run(_ context.Context, req ScanRequest) (*scanner.ScanResult, error) {
	if r.inspect != nil {
		r.inspect(req)
	}
	res := r.result
	if res == nil {
		res = &scanner.ScanResult{Targets: []string{req.Target}}
	}
	return res, nil
}

// consoleServer is a test server with on-disk side-stores under a temp dir, so
// targets/settings/FP persistence exercises the real paths without touching the
// repo. Private targets are allowed so local URLs validate.
func consoleServer(t *testing.T, runner Runner) *Server {
	t.Helper()
	return NewServerWithStore(runner, NewStore(), ServerConfig{
		AllowPrivateTargets: true,
		DataDir:             t.TempDir(),
	})
}

func TestVersion(t *testing.T) {
	srv := NewServerWithStore(fakeRunner{}, NewStore(), ServerConfig{Version: "1.2.3"})
	rec := doJSON(t, srv, http.MethodGet, "/api/version", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("version code = %d, want 200", rec.Code)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["version"] != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", out["version"])
	}
}

func TestTools_EmptyWhenNoProvider(t *testing.T) {
	srv := consoleServer(t, fakeRunner{})
	rec := doJSON(t, srv, http.MethodGet, "/api/tools", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tools code = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "[]\n" && got != "[]" {
		t.Errorf("tools body = %q, want empty array", got)
	}
}

func TestTargets_CRUDAndScan(t *testing.T) {
	srv := consoleServer(t, fakeRunner{result: sampleResult()})

	// Empty to start.
	if rec := doJSON(t, srv, http.MethodGet, "/api/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d, want 200", rec.Code)
	}

	// Create.
	rec := doJSON(t, srv, http.MethodPost, "/api/targets", `{"url":"http://example.com","label":"demo"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var tgt Target
	if err := json.Unmarshal(rec.Body.Bytes(), &tgt); err != nil {
		t.Fatalf("decode target: %v", err)
	}
	if tgt.ID == "" || tgt.URL != "http://example.com" {
		t.Fatalf("target = %+v", tgt)
	}

	// Missing URL → 400.
	if rec := doJSON(t, srv, http.MethodPost, "/api/targets", `{"label":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty url code = %d, want 400", rec.Code)
	}

	// Scan the target → 202 and records last_scan_id.
	rec = doJSON(t, srv, http.MethodPost, "/api/targets/"+tgt.ID+"/scan", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan code = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	job := decodeJob(t, rec)
	if job.Target != "http://example.com" {
		t.Errorf("scan target = %q", job.Target)
	}
	srv.WaitIdle()
	if got, _ := srv.targets.Get(tgt.ID); got == nil || got.LastScanID != job.ID {
		t.Errorf("last_scan_id not recorded: %+v", got)
	}

	// Scan a missing target → 404.
	if rec := doJSON(t, srv, http.MethodPost, "/api/targets/nope/scan", ""); rec.Code != http.StatusNotFound {
		t.Errorf("scan missing code = %d, want 404", rec.Code)
	}

	// Delete.
	if rec := doJSON(t, srv, http.MethodDelete, "/api/targets/"+tgt.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("delete code = %d, want 200", rec.Code)
	}
	if rec := doJSON(t, srv, http.MethodDelete, "/api/targets/"+tgt.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("re-delete code = %d, want 404", rec.Code)
	}
}

func TestSettings_GetPutRoundTrip(t *testing.T) {
	srv := consoleServer(t, fakeRunner{})

	// Default is empty config.
	if rec := doJSON(t, srv, http.MethodGet, "/api/settings", ""); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d, want 200", rec.Code)
	}

	// Put valid config.
	rec := doJSON(t, srv, http.MethodPut, "/api/settings", `{"profile":"quick","detectors":{"xss":true}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Read it back.
	rec = doJSON(t, srv, http.MethodGet, "/api/settings", "")
	var cfg ScanConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if cfg.Profile != "quick" || !cfg.Detectors["xss"] {
		t.Errorf("settings = %+v", cfg)
	}

	// Invalid detector name → 400.
	if rec := doJSON(t, srv, http.MethodPut, "/api/settings", `{"detectors":{"notareal":true}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad settings code = %d, want 400", rec.Code)
	}
}

func TestSettings_AppliedToTargetScan(t *testing.T) {
	srv := consoleServer(t, fakeRunner{result: sampleResult()})

	// Store a default profile.
	if rec := doJSON(t, srv, http.MethodPut, "/api/settings", `{"profile":"thorough"}`); rec.Code != http.StatusOK {
		t.Fatalf("put settings: %d", rec.Code)
	}
	// Create a target and scan it with no body → settings default applies.
	rec := doJSON(t, srv, http.MethodPost, "/api/targets", `{"url":"http://example.com"}`)
	var tgt Target
	_ = json.Unmarshal(rec.Body.Bytes(), &tgt)

	var gotProfile string
	srv.runner = runnerFunc(func(req ScanRequest) {
		if req.Config != nil {
			gotProfile = req.Config.Profile
		}
	}, sampleResult())
	rec = doJSON(t, srv, http.MethodPost, "/api/targets/"+tgt.ID+"/scan", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan code = %d", rec.Code)
	}
	srv.WaitIdle()
	if gotProfile != "thorough" {
		t.Errorf("scan used profile %q, want thorough (from settings)", gotProfile)
	}
}

func TestMarkFP_RoundTrip(t *testing.T) {
	srv := consoleServer(t, fakeRunner{result: sampleResult()})

	// Run a scan to completion so the finding exists.
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"http://example.com"}`)
	job := decodeJob(t, rec)
	srv.WaitIdle()

	// Grab the finding id.
	rec = doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/findings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("findings code = %d", rec.Code)
	}
	var findings []*struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &findings); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(findings) == 0 || findings[0].ID == "" {
		t.Fatalf("no findings with ids: %s", rec.Body.String())
	}
	fid := findings[0].ID

	// Mark it a false positive.
	rec = doJSON(t, srv, http.MethodPost, "/api/scans/"+job.ID+"/findings/"+fid+"/fp", `{"fp":true,"reason":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark fp code = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Unknown finding → 404.
	if rec := doJSON(t, srv, http.MethodPost, "/api/scans/"+job.ID+"/findings/nope/fp", `{"fp":true}`); rec.Code != http.StatusNotFound {
		t.Errorf("mark fp missing code = %d, want 404", rec.Code)
	}
}

func TestCompliance_Assess(t *testing.T) {
	srv := consoleServer(t, fakeRunner{result: sampleResult()})
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"http://example.com"}`)
	job := decodeJob(t, rec)
	srv.WaitIdle()

	rec = doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/compliance?framework=pci-dss", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("compliance code = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Unknown framework → 400.
	if rec := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/compliance?framework=bogus", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad framework code = %d, want 400", rec.Code)
	}
}

func TestStores_PersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	tpath := dir + "/targets.json"
	spath := dir + "/settings.json"

	ts, err := NewTargetStore(tpath)
	if err != nil {
		t.Fatal(err)
	}
	created := ts.Create("http://example.com", "demo")
	ss, err := NewSettingsStore(spath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Put(ScanConfig{Profile: "quick"}); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk — a fresh process.
	ts2, err := NewTargetStore(tpath)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := ts2.Get(created.ID); !ok || got.Label != "demo" {
		t.Errorf("target not persisted: %+v ok=%v", got, ok)
	}
	ss2, err := NewSettingsStore(spath)
	if err != nil {
		t.Fatal(err)
	}
	if ss2.Get().Profile != "quick" {
		t.Errorf("settings not persisted: %+v", ss2.Get())
	}
}

func TestConsoleEndpoints_RequireAuth(t *testing.T) {
	srv := NewServerWithStore(fakeRunner{}, NewStore(), ServerConfig{APIKey: "secret", DataDir: t.TempDir()})
	for _, path := range []string{"/api/targets", "/api/settings", "/api/tools"} {
		if rec := doJSON(t, srv, http.MethodGet, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without key = %d, want 401", path, rec.Code)
		}
	}
	// Query-param key is accepted (EventSource / browser path).
	if rec := doJSON(t, srv, http.MethodGet, "/api/tools?key=secret", ""); rec.Code != http.StatusOK {
		t.Errorf("tools with ?key= = %d, want 200", rec.Code)
	}
}
