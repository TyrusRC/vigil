package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TyrusRC/vigil/internal/api"
	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/tools"
	"github.com/TyrusRC/vigil/internal/webui"
)

var (
	webPort      int
	webListen    string
	webStateFile string
	webAPIKey    string
	webNoOpen    bool
	webNoAuth    bool
)

// scanRunner is the production api.Runner: it drives the real scanner.
type scanRunner struct{}

func (scanRunner) Run(ctx context.Context, req api.ScanRequest) (*scanner.ScanResult, error) {
	s := scanner.New()
	defer s.Close()

	// Build the full transport + detector configuration from the request.
	// A bare {target, profile} body still works: the profile falls through to
	// the config DTO, which otherwise defaults everything.
	cfg := req.Config
	if cfg == nil {
		cfg = &api.ScanConfig{}
	}
	if cfg.Profile == "" {
		cfg.Profile = req.Profile
	}
	transport, internalConfig, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("configure scanner: %w", err)
	}
	if req.OnFinding != nil {
		internalConfig.OnFinding = req.OnFinding
	}

	s.SetConfig(transport)
	if err := s.SetInternalConfig(internalConfig); err != nil {
		return nil, fmt.Errorf("configure scanner: %w", err)
	}
	if err := s.AddTarget(req.Target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	registerTools(s)
	return s.Scan(ctx)
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Open the vigil web dashboard (and JSON API)",
	Long: `Start an HTTP server exposing the vigil dashboard (a single-page app)
and its JSON API for launching scans and browsing results, then open the
dashboard in your default browser.

Examples:
  vigil web
  vigil web --port 9000
  vigil web --no-open
  vigil web --listen 0.0.0.0 --api-key my-secret`,
	Args: cobra.NoArgs,
	RunE: runWeb,
}

func init() {
	rootCmd.AddCommand(webCmd)
	webCmd.Flags().IntVarP(&webPort, "port", "p", 8080, "Port to listen on")
	webCmd.Flags().StringVar(&webListen, "listen", "localhost", "Address to bind to; \"localhost\" binds loopback on both IPv4 and IPv6 (use 0.0.0.0 to expose on all interfaces)")
	webCmd.Flags().StringVar(&webStateFile, "state-file", "", "Persist scan jobs to this JSON file so they survive a restart (default: in-memory only)")
	webCmd.Flags().StringVar(&webAPIKey, "api-key", "", "Bearer token required for API access (also read from VIGIL_API_KEY)")
	webCmd.Flags().BoolVar(&webNoOpen, "no-open", false, "Do not open the dashboard in a browser (for headless/server use)")
	webCmd.Flags().BoolVar(&webNoAuth, "no-auth", false, "Disable API authentication entirely (dangerous; only for a trusted isolated host)")
}

// resolveAPIKey decides the Bearer token for the API. An explicit --api-key or
// VIGIL_API_KEY wins; otherwise one is generated so the API is authenticated by
// default. --no-auth returns "" (open API) for trusted isolated hosts.
func resolveAPIKey() (key string, generated bool) {
	if webNoAuth {
		return "", false
	}
	if webAPIKey != "" {
		return webAPIKey, false
	}
	if env := os.Getenv("VIGIL_API_KEY"); env != "" {
		return env, false
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		// Extremely unlikely; fall back to time-seeded hex rather than no auth.
		return fmt.Sprintf("%x", time.Now().UnixNano()), true
	}
	return hex.EncodeToString(buf), true
}

func runWeb(cmd *cobra.Command, _ []string) error {
	apiKey, generatedKey := resolveAPIKey()

	mux, apiServer, err := buildWebMux(scanRunner{}, api.ServerConfig{
		APIKey:        apiKey,
		Version:       version,
		ToolsProvider: webTools,
	})
	if err != nil {
		return err
	}

	listeners, err := webListeners(webListen, webPort)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Report and open the actual bound port (handles --port 0) at a host the
	// browser can reach — "localhost" lets the client pick a working family.
	_, boundPort, _ := net.SplitHostPort(listeners[0].Addr().String())
	uiURL := "http://" + net.JoinHostPort(uiHost(webListen), boundPort)

	// The browser can't send an Authorization header, so hand it the key as a
	// query param; the SPA reads ?key= and sends it as a Bearer token after.
	browseURL := uiURL
	if apiKey != "" {
		browseURL = uiURL + "/?key=" + url.QueryEscape(apiKey)
	}

	if !webNoOpen {
		if oerr := webui.OpenBrowser(browseURL); oerr != nil {
			fmt.Fprintf(os.Stderr, "[!] could not open browser: %v (open %s manually)\n", oerr, browseURL)
		}
	}

	fmt.Fprintf(os.Stderr, "[*] vigil dashboard on %s\n", uiURL)
	switch {
	case apiKey == "":
		fmt.Fprintln(os.Stderr, "[!] API authentication DISABLED (--no-auth); endpoints are open to anyone who can reach this port")
	case generatedKey:
		fmt.Fprintf(os.Stderr, "[*] API key (generated): %s\n", apiKey)
		fmt.Fprintf(os.Stderr, "[*] Open the dashboard with: %s\n", browseURL)
	default:
		fmt.Fprintln(os.Stderr, "[*] API authentication enabled (Bearer token required)")
	}

	errCh := make(chan error, 1)
	for _, l := range listeners {
		go func(l net.Listener) {
			if serr := srv.Serve(l); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				errCh <- serr
			}
		}(l)
	}

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[*] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdownCtx) // closes every listener passed to Serve
		apiServer.WaitIdle()
		return err
	case serr := <-errCh:
		return fmt.Errorf("server error: %w", serr)
	}
}

// isLoopbackListen reports whether listen names the loopback (the default). On
// WSL2 mirrored networking IPv4 127.0.0.1 can be unreachable while IPv6 ::1
// works (and vice-versa elsewhere), so a loopback request binds both families.
func isLoopbackListen(listen string) bool {
	switch listen {
	case "", "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// webListeners binds the dashboard. For a loopback listen it binds both
// 127.0.0.1 and ::1 (skipping a family the host lacks) so the browser reaches
// it whichever loopback works; any other listen binds that single address.
func webListeners(listen string, port int) ([]net.Listener, error) {
	bindPort := strconv.Itoa(port)
	if !isLoopbackListen(listen) {
		l, err := net.Listen("tcp", net.JoinHostPort(listen, bindPort))
		if err != nil {
			return nil, err
		}
		return []net.Listener{l}, nil
	}
	var ls []net.Listener
	for _, host := range []string{"127.0.0.1", "::1"} {
		l, err := net.Listen("tcp", net.JoinHostPort(host, bindPort))
		if err != nil {
			continue
		}
		ls = append(ls, l)
		// Pin later families to the first bound port (matters for --port 0).
		if _, p, perr := net.SplitHostPort(l.Addr().String()); perr == nil {
			bindPort = p
		}
	}
	if len(ls) == 0 {
		return nil, fmt.Errorf("could not bind loopback on port %d", port)
	}
	return ls, nil
}

// uiHost picks the host to show and open in a browser. Loopback and wildcard
// binds are browsed via "localhost"; an explicit address is browsed as-is.
func uiHost(listen string) string {
	if isLoopbackListen(listen) {
		return "localhost"
	}
	switch listen {
	case "0.0.0.0", "::", "[::]":
		return "localhost"
	}
	return listen
}

// webTools returns the external tools for GET /api/tools. It reuses the exact
// registration the scanner uses, so the UI reports the same tool set a scan
// would run.
// NOTE: registerTools skips nuclei when its binary is absent, so an unavailable
// nuclei is omitted from the list rather than shown as unavailable.
func webTools() []tools.Tool {
	s := scanner.New()
	defer s.Close()
	registerTools(s)
	return s.Tools()
}

// buildAPIServer constructs the shared api.Server (the service that backs both
// the REST API and the MCP server). When stateFile is set, scan jobs persist
// there and the targets/settings/FP side-stores live alongside it (so a running
// `vigil web` and a `vigil mcp` pointed at the same file share state); otherwise
// everything is in-memory.
func buildAPIServer(runner api.Runner, stateFile string, cfg api.ServerConfig) (*api.Server, error) {
	if stateFile != "" {
		cfg.DataDir = filepath.Dir(stateFile)
		store, err := api.NewPersistentStore(stateFile)
		if err != nil {
			return nil, fmt.Errorf("job store: %w", err)
		}
		return api.NewServerWithStore(runner, store, cfg), nil
	}
	return api.NewServerWithStore(runner, api.NewStore(), cfg), nil
}

// buildWebMux wires the JSON API under /api/, the MCP streamable-HTTP endpoint
// at /mcp, and the embedded SPA at /.
func buildWebMux(runner api.Runner, cfg api.ServerConfig) (http.Handler, *api.Server, error) {
	ui, err := webui.Handler()
	if err != nil {
		return nil, nil, fmt.Errorf("web ui: %w", err)
	}
	apiServer, err := buildAPIServer(runner, webStateFile, cfg)
	if err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", apiServer.Handler())
	mux.Handle("/mcp", mcpHTTPHandler(apiServer, cfg.APIKey))
	mux.Handle("/", ui)
	return mux, apiServer, nil
}
