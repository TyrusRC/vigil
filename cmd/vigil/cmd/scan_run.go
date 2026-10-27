// scan_run.go — runScan: the cobra RunE handler for `vigil scan`.
// Adjudication logic is in scan_adjudicate.go; TUI output in scan_tui.go.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"net/http"

	"github.com/TyrusRC/vigil/internal/capture"
	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/reporting"
	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/scope"
	"github.com/TyrusRC/vigil/internal/session"
	uitui "github.com/TyrusRC/vigil/internal/tui"
	"github.com/TyrusRC/vigil/internal/webui"
	"github.com/spf13/cobra"
)

func runScan(cmd *cobra.Command, args []string) error {
	if err := applyConfigFile(cmd); err != nil {
		return err
	}

	// UI mode: web UI by default, headless for automation (praetor/CI).
	uitui.AutoDetect()
	if headlessMode {
		uitui.SetHeadless(true)
	}

	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	s := scanner.New()
	defer s.Close()

	// Scan directory: the single place tool logs, native tool output files,
	// and the auto-saved report all land. Use --output-dir when given, else a
	// timestamped dir so a run's artifacts — including every tool's raw log —
	// are never lost. Decided up front so tools write logs here as they run,
	// and so the web UI's delete-output endpoint knows where they are.
	scanDir := outputDir
	if scanDir == "" {
		scanDir = fmt.Sprintf("vigil-report-%s", time.Now().Format("2006-01-02T150405"))
	}

	// Start web UI server unless --headless or --no-ui
	var eventBus *webui.EventBus
	scanStatus := "running"
	var findingsMu sync.Mutex
	var liveFindings []*core.Finding
	if !headlessMode && !noUI {
		eventBus = webui.NewEventBus()
		uiHandler, uiErr := webui.Handler()
		if uiErr == nil {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/events", eventBus.SSEHandler())
			mux.HandleFunc("/api/target", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				target := ""
				if len(targets) > 0 {
					target = targets[0]
				}
				fmt.Fprintf(w, `{"target":%q,"status":%q}`, target, scanStatus)
			})
			mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				findingsMu.Lock()
				deduped := core.Findings(liveFindings).Deduplicate()
				findingsMu.Unlock()
				data, _ := json.Marshal(deduped)
				if data == nil {
					data = []byte("[]")
				}
				w.Write(data)
			})
			// Triage feedback — the web UI posts here when an operator marks a
			// finding a false positive (or restores it). The mark is written to
			// the FP database so a future `vigil scan --fp-database <path>`
			// downgrades the same (type,url,param) to low confidence. Writes to
			// --fp-database when set, else the conventional .vigil-fp.json.
			fpPath := fpDatabasePath
			if fpPath == "" {
				fpPath = ".vigil-fp.json"
			}
			var fpMu sync.Mutex
			mux.HandleFunc("/api/fp", fpMarkHandler(fpPath, &fpMu, func(id string) *core.Finding {
				findingsMu.Lock()
				defer findingsMu.Unlock()
				for _, f := range liveFindings {
					if f.ID == id {
						return f
					}
				}
				return nil
			}))
			// Capture proxy — records full req/res for the Traffic view. Opt-in
			// (--capture): routing every external tool through it disables
			// keep-alives and buffers bodies, which slows the scan, so the
			// default scan does not force traffic through it. The Store is
			// always created so /api/history returns [] cleanly when off.
			captureProxy := capture.New("")
			if captureTraffic {
				captureAddr, captureErr := captureProxy.Start(0)
				if captureErr == nil {
					os.Setenv("HTTP_PROXY", "http://"+captureAddr)
					os.Setenv("HTTPS_PROXY", "http://"+captureAddr)
				}
			}
			mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				data, _ := json.Marshal(captureProxy.Store.All())
				w.Write(data)
			})
			mux.HandleFunc("/api/history/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				idStr := strings.TrimPrefix(r.URL.Path, "/api/history/")
				var id int64
				fmt.Sscanf(idStr, "%d", &id)
				entry := captureProxy.Store.Get(id)
				if entry == nil {
					http.Error(w, `{"error":"not found"}`, 404)
					return
				}
				data, _ := json.Marshal(entry)
				w.Write(data)
			})

			// DELETE /api/findings/{id} — remove a single finding from the
			// dashboard view (e.g. an operator triaging out a finding they do
			// not want in the result). Affects this session's in-memory set;
			// to suppress it on future scans, mark it a false positive instead.
			mux.HandleFunc("/api/findings/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodDelete {
					http.Error(w, `{"error":"DELETE required"}`, http.StatusMethodNotAllowed)
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/api/findings/")
				findingsMu.Lock()
				kept := liveFindings[:0:0]
				removed := false
				for _, f := range liveFindings {
					if f.ID == id {
						removed = true
						continue
					}
					kept = append(kept, f)
				}
				liveFindings = kept
				remaining := len(liveFindings)
				findingsMu.Unlock()
				if !removed {
					http.Error(w, `{"error":"finding not found"}`, http.StatusNotFound)
					return
				}
				fmt.Fprintf(w, `{"ok":true,"remaining":%d}`, remaining)
			})

			// DELETE /api/output — clear all findings and delete this scan's
			// saved output artifacts (reports, tool logs) from scanDir. Removes
			// only vigil-produced files, never the caller's --output-dir itself.
			mux.HandleFunc("/api/output", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodDelete {
					http.Error(w, `{"error":"DELETE required"}`, http.StatusMethodNotAllowed)
					return
				}
				findingsMu.Lock()
				liveFindings = nil
				findingsMu.Unlock()
				removed := deleteScanOutput(scanDir, outputDir == "")
				fmt.Fprintf(w, `{"ok":true,"files_removed":%d}`, removed)
			})

			// SPA catch-all LAST
			mux.Handle("/", uiHandler)
			ln, uiURL, listenErr := webui.LaunchServer(mux, uiPort)
			if listenErr == nil {
				go func() {
					if serveErr := http.Serve(ln, mux); serveErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Web UI server error: %v\n", serveErr)
					}
				}()
				fmt.Fprintf(os.Stderr, "  Web UI: %s\n\n", uiURL)
				webui.OpenBrowser(uiURL)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Web UI failed: %v (scan continues without UI)\n", listenErr)
			}
		}
	}

	for _, target := range targets {
		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Host == "" {
			return fmt.Errorf("invalid target URL: %s (must include scheme, e.g. https://example.com)", target)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", parsedURL.Scheme)
		}
	}

	// Smart auto-configuration: probe the target and auto-enable features.
	// Runs BEFORE validation so profile-derived level/risk are set first.
	autoConfig(cmd, targets)

	if level < 1 || level > 5 {
		return fmt.Errorf("level must be between 1 and 5, got %d", level)
	}
	if risk < 1 || risk > 3 {
		return fmt.Errorf("risk must be between 1 and 3, got %d", risk)
	}

	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed header %q: must be in 'Key: Value' format", h)
		}
		headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	// CLI flag wins over env; missing flag falls back to VIGIL_LOGIN_PASS.
	if loginPass == "" {
		if env := os.Getenv("VIGIL_LOGIN_PASS"); env != "" {
			loginPass = env
		}
	}

	sessionCookies := cookies
	if loginURL != "" {
		loginCtx, loginCancel := context.WithTimeout(context.Background(), 60*time.Second)
		got, lerr := performLogin(loginCtx)
		loginCancel()
		if lerr != nil {
			return fmt.Errorf("login failed: %w", lerr)
		}
		sessionCookies = mergeCookies(cookies, got)
		if verbose {
			fmt.Fprintln(os.Stderr, "[*] Authenticated: scanning with captured session")
		}
	}

	// When a proxy is set but --insecure was not explicitly passed, auto-enable
	// TLS skip. The proxy (typically Burp) terminates TLS with its own CA, so
	// direct requests fail with x509 verification errors unless skipped.
	if proxy != "" && !insecure {
		insecure = true
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] --proxy set: auto-enabling --insecure (TLS verification skipped)\n")
		}
	}

	config := &scanner.Config{
		Timeout:        timeout,
		Concurrency:    concurrency,
		Verbose:        verbose,
		Headers:        headerMap,
		Cookies:        sessionCookies,
		UserAgent:      userAgent,
		Data:           data,
		Method:         method,
		ProxyURL:       proxy,
		Insecure:       insecure,
		OutputDir:      scanDir,
		CheckpointPath: checkpointPath,
		ResumePath:     resumePath,
	}
	s.SetConfig(config)

	internalConfig := scanner.DefaultInternalConfig()
	if profile != "" {
		p := scanner.GetProfile(profile)
		internalConfig = p.Config
	}
	if err := applyCLIFlags(internalConfig); err != nil {
		return err
	}
	// Scope is ON by default: restrict traffic to the target host(s) so a scan
	// never wanders off-target, and skip session-destroying paths. Operators
	// broaden with --scope-host / --include-path, or disable with --no-scope.
	// Cross-host detectors (cloud, subdomain-takeover, external APIs) and OOB
	// callbacks use a separate unscoped client, so this does not block them.
	if !noScope {
		hosts := scopeHosts
		if len(hosts) == 0 {
			seen := map[string]bool{}
			for _, t := range targets {
				if u, e := url.Parse(t); e == nil && u.Hostname() != "" && !seen[u.Hostname()] {
					seen[u.Hostname()] = true
					hosts = append(hosts, u.Hostname())
				}
			}
		}
		sc, serr := scope.New(hosts, includePaths, excludePaths, !noDefaultExcludes)
		if serr != nil {
			return fmt.Errorf("invalid scope: %w", serr)
		}
		internalConfig.Scope = sc
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Scope: hosts=%v include=%v exclude=%v default-excludes=%v (--no-scope to disable)\n",
				hosts, includePaths, excludePaths, !noDefaultExcludes)
		}
	} else if verbose {
		fmt.Fprintln(os.Stderr, "[*] Scope disabled (--no-scope): all hosts allowed")
	}
	if ratePerSec > 0 {
		internalConfig.RateLimitPerSec = ratePerSec
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Rate limit: %.2f req/s\n", ratePerSec)
		}
	}
	// When a login was performed, keep that session alive for the scan: poll a
	// canary (an authenticated-only URL, default the first target) and re-run the
	// login on logout. --login-success is the authenticated marker.
	if loginURL != "" {
		canary := sessionCheckURL
		if canary == "" && len(targets) > 0 {
			canary = targets[0]
		}
		internalConfig.Session = session.New(sessionCookies, performLogin, canary, loginSuccess)
		internalConfig.SessionCheckInterval = sessionCheckInterval
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Session keepalive: canary=%s marker=%q every %s\n",
				canary, loginSuccess, sessionCheckInterval)
		}
	}
	if verbose && internalConfig.EnableJSDep {
		if internalConfig.NVDAPIKey != "" {
			fmt.Fprintln(os.Stderr, "[*] NVD: authenticated tier (~50 req/30s)")
		} else {
			fmt.Fprintln(os.Stderr, "[*] NVD: anonymous tier (~5 req/30s; pass --nvd-api-key or set NVD_API_KEY for higher limit)")
		}
	}
	internalConfig.Verbose = verbose
	if eventBus != nil {
		internalConfig.OnFinding = func(f *core.Finding) {
			findingsMu.Lock()
			liveFindings = append(liveFindings, f)
			findingsMu.Unlock()
			eventBus.PublishFinding(f)
		}
	}

	if dryRun {
		printDryRun(targets, internalConfig)
		return nil
	}

	if err := s.SetInternalConfig(internalConfig); err != nil && verbose {
		fmt.Fprintf(os.Stderr, "Warning: Failed to configure internal scanner: %v\n", err)
	}

	for _, target := range targets {
		if err := s.AddTarget(target); err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	if !internalOnly {
		registerTools(s)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping scan...")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigChan)
	}()

	formats, err := resolveFormats(formatList, jsonOutput, htmlOutput)
	if err != nil {
		return err
	}
	if verr := validateOutput(formats, outputDir); verr != nil {
		return verr
	}

	// Print the human banner only when emitting the default text report to stdout.
	if outputDir == "" && len(formats) == 1 && formats[0] == "text" {
		if len(targets) == 1 {
			printScanHeader(targets[0])
		} else {
			printScanHeader(fmt.Sprintf("%d targets", len(targets)))
		}
	}

	result, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	scanStatus = "complete"
	findingsMu.Lock()
	liveFindings = result.Findings
	findingsMu.Unlock()

	if verifyFindings {
		runVerification(ctx, result.Findings, headerMap, sessionCookies)
	}

	// Haruspex adjudication: a FAIL-OPEN triage pass that annotates each finding with a
	// "real finding" probability (and flags likely noise for review) AFTER verification.
	// It only annotates — it never drops or reorders a finding, so it cannot cause a
	// missed finding. No engine configured / unreachable -> findings untouched.
	// Use a fresh context — the scan context may already be expired.
	adjCtx, adjCancel := context.WithTimeout(context.Background(), 90*time.Second)
	adjudicateFindings(adjCtx, result.Findings)
	adjCancel()

	// FP feedback: downgrade findings that match past false positives.
	if fpDatabasePath != "" {
		fpDB := scanner.LoadFPFeedback(fpDatabasePath)
		suppressed := fpDB.ApplyToFindings(result.Findings)
		if verbose && suppressed > 0 {
			fmt.Fprintf(os.Stderr, "[*] FP feedback: suppressed %d known false positives from %s\n",
				suppressed, fpDatabasePath)
		}
	}

	// Confidence threshold: filter out low-confidence findings for enterprise.
	if minConfidence != "" {
		before := len(result.Findings)
		result.Findings = filterByConfidence(result.Findings, minConfidence)
		if verbose && before != len(result.Findings) {
			fmt.Fprintf(os.Stderr, "[*] Confidence filter (>=%s): %d → %d findings\n",
				minConfidence, before, len(result.Findings))
		}
	}

	printTUIFindings(result.Findings)
	printTUISummary(result)

	// Coverage summary: show what was tested and what was skipped so the
	// result is never silently incomplete.
	printCoverageSummary(result, internalConfig)

	// Write detailed coverage data if requested.
	if coveragePath != "" {
		if ct := s.CoverageData(); ct != nil {
			if err := ct.WriteJSON(coveragePath); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Coverage write failed: %v\n", err)
			} else if verbose {
				sum := ct.Summary()
				fmt.Fprintf(os.Stderr, "[*] Coverage data: %d params × %d detectors → %s\n",
					sum.UniqueParams, len(sum.DetectorsUsed), coveragePath)
			}
		}
	}

	report := reporting.NewReport(result)

	// Auto-save: when no --output-dir was specified, write JSON + HTML reports
	// into the same scanDir the tool logs already went to, so results are never
	// lost. The text report still goes to stdout as before.
	if outputDir == "" && len(result.Findings) > 0 {
		if err := os.MkdirAll(scanDir, 0o755); err == nil {
			autoFormats := []string{"json", "html"}
			for _, af := range autoFormats {
				path := filepath.Join(scanDir, "vigil-report."+validFormats[af])
				if f, ferr := os.Create(path); ferr == nil {
					writeOne(report, af, f)
					f.Close()
				}
			}
			printTUIAutoSave(scanDir + "/")
		}
	}

	if err := writeReports(report, formats, outputDir); err != nil {
		return err
	}

	if complianceSpec != "" {
		if err := runCompliance(result.Findings, complianceSpec, outputDir); err != nil {
			return err
		}
	}

	if err := runExport(ctx, result.Findings); err != nil {
		return err
	}

	gateFindings := result.Findings
	if baselinePath != "" {
		baseline, berr := reporting.LoadBaselineFindings(baselinePath)
		if berr != nil {
			return berr
		}
		delta := reporting.DiffFindings(baseline, result.Findings)
		printDelta(delta)
		if failOnNew {
			gateFindings = delta.New
		}
	}

	fail, count, gerr := evaluateGate(gateFindings, failOn)
	if gerr != nil {
		return gerr
	}
	if fail {
		threshold, _ := core.ParseSeverity(failOn)
		return &gateError{Threshold: threshold, Count: count}
	}

	// When web UI is active, keep the server alive so the user can
	// browse results. Wait for Ctrl+C.
	if eventBus != nil {
		eventBus.PublishComplete(map[string]interface{}{
			"findings": len(result.Findings),
			"duration": result.Duration.String(),
		})
		fmt.Fprintf(os.Stderr, "\n  Scan complete. Web UI at http://localhost:%d — press Ctrl+C to exit.\n", uiPort)
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n  Shutting down.")
	}
	return nil
}
