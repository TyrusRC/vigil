package cmd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/vigil/internal/api"
	"github.com/TyrusRC/vigil/internal/scanner"
)

type stubRunner struct{}

func (stubRunner) Run(_ context.Context, req api.ScanRequest) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{Targets: []string{req.Target}}, nil
}

func TestBuildServeMux_RoutesAPIAndUI(t *testing.T) {
	mux, _, err := buildWebMux(stubRunner{}, api.ServerConfig{})
	if err != nil {
		t.Fatalf("buildWebMux: %v", err)
	}

	// API is mounted under /api/.
	recAPI := httptest.NewRecorder()
	mux.ServeHTTP(recAPI, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
	if recAPI.Code != http.StatusOK || !strings.Contains(recAPI.Body.String(), "ok") {
		t.Errorf("/api/health = %d %q", recAPI.Code, recAPI.Body.String())
	}

	// The SPA is served at the root.
	recUI := httptest.NewRecorder()
	mux.ServeHTTP(recUI, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if recUI.Code != http.StatusOK || recUI.Body.Len() == 0 {
		t.Errorf("/ = %d (len %d)", recUI.Code, recUI.Body.Len())
	}
}

// TestWebListeners_LoopbackBindsBothFamilies verifies the default loopback bind
// listens on both 127.0.0.1 and ::1 (so a browser reaches it whichever loopback
// works on the host), and that both share the same port when --port is 0.
func TestWebListeners_LoopbackBindsBothFamilies(t *testing.T) {
	ls, err := webListeners("localhost", 0)
	if err != nil {
		t.Fatalf("webListeners: %v", err)
	}
	defer func() {
		for _, l := range ls {
			l.Close()
		}
	}()

	if len(ls) == 0 {
		t.Fatal("no listeners bound")
	}
	seen := map[string]bool{}
	port := ""
	for _, l := range ls {
		host, p, _ := net.SplitHostPort(l.Addr().String())
		seen[host] = true
		if port == "" {
			port = p
		} else if p != port {
			t.Errorf("family bound to port %s, want shared port %s", p, port)
		}
	}
	// IPv6 may be unavailable in CI, but IPv4 loopback must always be present.
	if !seen["127.0.0.1"] {
		t.Errorf("did not bind 127.0.0.1; bound: %v", seen)
	}
}

// TestUIHost maps bind addresses to the host a browser should use.
func TestUIHost(t *testing.T) {
	for _, tc := range []struct{ listen, want string }{
		{"localhost", "localhost"},
		{"127.0.0.1", "localhost"},
		{"::1", "localhost"},
		{"0.0.0.0", "localhost"},
		{"::", "localhost"},
		{"192.168.1.10", "192.168.1.10"},
	} {
		if got := uiHost(tc.listen); got != tc.want {
			t.Errorf("uiHost(%q) = %q, want %q", tc.listen, got, tc.want)
		}
	}
}
