package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/tools"
)

func logInfo(msg string, args ...any)  { fmt.Fprintf(os.Stderr, "[INFO] "+msg+"\n", args...) }
func logWarn(msg string, args ...any)  { fmt.Fprintf(os.Stderr, "[WARN] "+msg+"\n", args...) }
func logError(msg string, args ...any) { fmt.Fprintf(os.Stderr, "[ERROR] "+msg+"\n", args...) }

// Runner executes a scan for a request and returns its result. Implementations
// back the real scanner; tests supply a fake.
type Runner interface {
	Run(ctx context.Context, req ScanRequest) (*scanner.ScanResult, error)
}

// scanTimeout bounds a single API-triggered scan.
const scanTimeout = 30 * time.Minute

// maxConcurrentScans limits how many API-triggered scans can run in parallel.
const maxConcurrentScans = 3

// ServerConfig holds options for building a Server.
type ServerConfig struct {
	// APIKey, when non-empty, requires a Bearer token on authenticated endpoints.
	APIKey string
	// AllowPrivateTargets disables the SSRF protection that blocks scans against
	// private/link-local IP addresses. Intended for internal-network scanners.
	AllowPrivateTargets bool
	// DataDir, when set, is where targets/settings/FP state is persisted. Empty
	// keeps those stores in-memory.
	DataDir string
	// ToolsProvider returns the external tools for GET /api/tools. Supplied by
	// the cmd layer (which owns the tool constructors) to avoid an import cycle.
	ToolsProvider func() []tools.Tool
	// Version is reported by GET /api/version. Empty reports "dev".
	Version string
}

// Server is the HTTP JSON API for scans.
type Server struct {
	store    *Store
	runner   Runner
	mux      *http.ServeMux
	wg       sync.WaitGroup
	scanSem  chan struct{}
	config   ServerConfig
	events   *ScanEventBus
	targets  *TargetStore
	settings *SettingsStore
	fpPath   string
}

// NewServer builds a Server backed by runner. The returned Server's Handler
// also serves any provided static frontend.
func NewServer(runner Runner) *Server {
	return NewServerWithStore(runner, NewStore(), ServerConfig{})
}

// NewServerWithStore builds a Server backed by runner and a caller-provided
// store — pass a persistent store so jobs survive a restart.
func NewServerWithStore(runner Runner, store *Store, cfg ServerConfig) *Server {
	s := &Server{
		store:   store,
		runner:  runner,
		mux:     http.NewServeMux(),
		scanSem: make(chan struct{}, maxConcurrentScans),
		config:  cfg,
		events:  NewScanEventBus(),
	}

	// Persisted side-stores live under DataDir (empty ⇒ in-memory). A load
	// error is non-fatal: fall back to in-memory so the server still starts.
	var targetPath, settingsPath string
	if cfg.DataDir != "" {
		targetPath = filepath.Join(cfg.DataDir, "vigil-targets.json")
		settingsPath = filepath.Join(cfg.DataDir, "vigil-settings.json")
		s.fpPath = filepath.Join(cfg.DataDir, ".vigil-fp.json")
	} else {
		s.fpPath = ".vigil-fp.json"
	}
	ts, err := NewTargetStore(targetPath)
	if err != nil {
		logWarn("targets store: %v; using in-memory", err)
		ts, _ = NewTargetStore("")
	}
	ss, err := NewSettingsStore(settingsPath)
	if err != nil {
		logWarn("settings store: %v; using in-memory", err)
		ss, _ = NewSettingsStore("")
	}
	s.targets = ts
	s.settings = ss

	s.routes()
	return s
}

// Handler returns the HTTP handler for the API (without the static frontend).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Events returns the scan event bus for publishing real-time events.
func (s *Server) Events() *ScanEventBus {
	return s.events
}

// WaitIdle blocks until all in-flight scans finish. Intended for tests and
// graceful shutdown.
func (s *Server) WaitIdle() {
	s.wg.Wait()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/scans", s.requireAuth(s.handleCreateScan))
	s.mux.HandleFunc("GET /api/scans", s.requireAuth(s.handleListScans))
	s.mux.HandleFunc("GET /api/scans/{id}", s.requireAuth(s.handleGetScan))
	s.mux.HandleFunc("DELETE /api/scans/{id}", s.requireAuth(s.handleCancelScan))
	s.mux.HandleFunc("GET /api/scans/{id}/progress", s.requireAuth(s.handleGetProgress))
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.requireAuth(s.handleGetReport))
	s.mux.HandleFunc("GET /api/scans/{id}/findings", s.requireAuth(s.handleGetFindings))
	s.mux.HandleFunc("GET /api/scans/{id}/events", s.handleSSE)
	s.mux.HandleFunc("GET /api/profiles", s.requireAuth(s.handleProfiles))
	s.mux.HandleFunc("GET /api/config/defaults", s.requireAuth(s.handleConfigDefaults))
	s.mux.HandleFunc("GET /api/version", s.handleVersion)
	s.mux.HandleFunc("GET /api/tools", s.requireAuth(s.handleTools))

	// Finding-level operations.
	s.mux.HandleFunc("POST /api/scans/{id}/findings/{fid}/fp", s.requireAuth(s.handleMarkFP))
	s.mux.HandleFunc("GET /api/scans/{id}/compliance", s.requireAuth(s.handleCompliance))

	// Settings (default scan config for new scans).
	s.mux.HandleFunc("GET /api/settings", s.requireAuth(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/settings", s.requireAuth(s.handlePutSettings))

	// Targets (persistent, re-scannable).
	s.mux.HandleFunc("GET /api/targets", s.requireAuth(s.handleListTargets))
	s.mux.HandleFunc("POST /api/targets", s.requireAuth(s.handleCreateTarget))
	s.mux.HandleFunc("DELETE /api/targets/{id}", s.requireAuth(s.handleDeleteTarget))
	s.mux.HandleFunc("POST /api/targets/{id}/scan", s.requireAuth(s.handleScanTarget))
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	v := s.config.Version
	if v == "" {
		v = "dev"
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": "vigil", "version": v})
}

func (s *Server) handleTools(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.ToolList())
}

// findFinding locates a finding by id within a completed scan.
func (s *Server) findFinding(scanID, findingID string) (*core.Finding, bool) {
	job, ok := s.store.Get(scanID)
	if !ok || job.Result() == nil {
		return nil, false
	}
	for _, f := range job.Result().Findings {
		if f.ID == findingID {
			return f, true
		}
	}
	return nil, false
}

func (s *Server) handleMarkFP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FP     bool   `json:"fp"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	count, err := s.MarkFP(r.PathValue("id"), r.PathValue("fid"), body.FP, body.Reason)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	assessment, err := s.Compliance(r.PathValue("id"), r.URL.Query().Get("framework"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = assessment.WriteJSON(w)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.settings.Get())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var cfg ScanConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.settings.Put(cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleListTargets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.targets.List())
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL   string `json:"url"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.URL = strings.TrimSpace(body.URL)
	if body.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if err := s.validateTarget(body.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.targets.Create(body.URL, body.Label))
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if !s.targets.Delete(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleScanTarget(w http.ResponseWriter, r *http.Request) {
	// Optional config body; an empty body means "use settings defaults", but a
	// malformed (non-empty, unparseable) body is a client error, not a silent
	// fallback to defaults.
	var req ScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	job, err := s.ScanTarget(r.Context(), r.PathValue("id"), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// profileNames are the scan profiles GetProfile recognizes (others → normal).
var profileNames = []string{"quick", "normal", "thorough", "passive"}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Profiles())
}

func (s *Server) handleConfigDefaults(w http.ResponseWriter, _ *http.Request) {
	detectors, profiles := s.ConfigDefaults()
	writeJSON(w, http.StatusOK, map[string]any{
		"detectors": detectors,
		"profiles":  profiles,
	})
}

func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.Findings(r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

// requireAuth wraps a handler with bearer-token checking when an API key is
// configured. Health is left open so load balancers can probe without a key.
// authorized reports whether the request carries the configured API key. The
// key may arrive as an "Authorization: Bearer <key>" header or, for clients
// that cannot set headers (EventSource, a browser following the opened URL), as
// a "key" query parameter. When no key is configured, every request is allowed.
func (s *Server) authorized(r *http.Request) bool {
	if s.config.APIKey == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.URL.Query().Get("key")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.config.APIKey)) == 1
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	job, err := s.StartScan(r.Context(), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// writeServiceError maps a service-layer sentinel error to an HTTP response.
// ErrInvalidRequest → 400 (its message is client-safe), ErrNotFound → 404,
// ErrNotCompleted → 409, ErrNotRunning → 409, anything else → 500.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), ErrInvalidRequest.Error()+": "))
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrNotCompleted):
		writeError(w, http.StatusConflict, "scan has not completed")
	case errors.Is(err, ErrNotRunning):
		writeError(w, http.StatusConflict, "scan is not running")
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// validateTarget checks the scan target for scheme and SSRF safety.
func (s *Server) validateTarget(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return &validationError{"invalid target URL (must include scheme and host)"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &validationError{"unsupported scheme: only http and https are allowed"}
	}
	if s.config.AllowPrivateTargets {
		return nil
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return &validationError{"cannot resolve target host"}
	}
	for _, ipStr := range ips {
		if isBlockedIP(ipStr) {
			return &validationError{"target resolves to a private/loopback address"}
		}
	}
	return nil
}

// isBlockedIP reports whether ipStr is a loopback, private, link-local, or
// unspecified address. IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1) are
// normalised to their IPv4 form first so they cannot bypass the check.
func isBlockedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unparseable → block
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// SafeDialContext returns a net.Dialer.DialContext wrapper that resolves the
// target address and blocks connections to private/loopback IPs. Use it as the
// DialContext in an http.Transport to defend against DNS-rebinding SSRF: even
// if a hostname resolved to a public IP at validation time, the transport-level
// check catches a rebind to a private IP at connect time.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: %w", err)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: resolve %s: %w", host, err)
	}
	for _, ipStr := range ips {
		if isBlockedIP(ipStr) {
			return nil, fmt.Errorf("ssrf dial: %s resolved to blocked address %s", host, ipStr)
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, s.ListScans(offset, limit))
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	job, err := s.GetScan(r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	if err := s.CancelScan(r.PathValue("id")); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleGetProgress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if job.Status != StatusRunning {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   job.Status,
			"progress": job.Progress,
		})
		return
	}
	p := s.store.GetProgress(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   job.Status,
		"progress": p,
	})
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	// Render to a buffer first so a mid-render error can still return a proper
	// status instead of a half-written body with headers already sent.
	var buf bytes.Buffer
	contentType, err := s.Report(r.PathValue("id"), r.URL.Query().Get("format"), &buf)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = buf.WriteTo(w)
}

// start launches the scan asynchronously, transitioning job state as it runs.
// The scan derives from the request context for request-scoped values but is
// detached from its cancellation so it survives the HTTP response returning.
// A bounded semaphore limits concurrent scans.
func (s *Server) start(reqCtx context.Context, id string, req ScanRequest) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Acquire a scan slot — fail the job if none are available within a
		// short window so callers get immediate feedback instead of an
		// unbounded queue.
		select {
		case s.scanSem <- struct{}{}:
			defer func() { <-s.scanSem }()
		case <-time.After(5 * time.Second):
			logWarn("scan %s rejected: too many concurrent scans", id)
			s.store.setFailed(id, "too many concurrent scans; try again later")
			return
		}

		s.store.setRunning(id)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), scanTimeout)
		defer cancel()
		s.store.setCancel(id, cancel)

		logInfo("scan %s started for %s (profile=%s)", id, req.Target, req.Profile)

		// Stream findings live to SSE subscribers as they are discovered.
		var found int32
		req.OnFinding = func(f *core.Finding) {
			n := atomic.AddInt32(&found, 1)
			s.events.Publish(ScanEvent{Type: EventFinding, ScanID: id, Finding: f})
			s.store.setProgress(id, ScanProgress{Phase: "scanning", FindingsCount: int(n)})
		}

		result, err := s.runner.Run(ctx, req)
		if ctx.Err() != nil {
			logInfo("scan %s cancelled", id)
			s.events.Publish(ScanEvent{Type: EventError, ScanID: id, Error: "cancelled"})
			return
		}
		if err != nil {
			logError("scan %s failed: %v", id, err)
			s.store.setFailed(id, err.Error())
			s.events.Publish(ScanEvent{Type: EventError, ScanID: id, Error: err.Error()})
			return
		}
		summary := result.Summary()
		s.store.setProgress(id, ScanProgress{
			Phase:         "completed",
			FindingsCount: summary.TotalFindings,
		})
		logInfo("scan %s completed: %d findings", id, summary.TotalFindings)
		s.store.setCompleted(id, result)
		s.events.Publish(ScanEvent{Type: EventComplete, ScanID: id})
	}()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return // response already partially written; best effort
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// parsePagination extracts offset and limit query parameters. Defaults: offset=0, limit=100.
func parsePagination(r *http.Request) (offset, limit int) {
	offset = queryInt(r, "offset", 0)
	limit = queryInt(r, "limit", 100)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	return
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
