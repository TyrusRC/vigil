package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/vigil/internal/api"
)

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

func mcpReq(key string) *http.Request {
	url := "/mcp"
	if strings.HasPrefix(key, "?") {
		url += key
	}
	r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(initBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if strings.HasPrefix(key, "bearer:") {
		r.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(key, "bearer:"))
	}
	return r
}

func TestMCPHTTPHandler_Auth(t *testing.T) {
	svc := api.NewServerWithStore(scanRunner{}, api.NewStore(), api.ServerConfig{AllowPrivateTargets: true})
	h := mcpHTTPHandler(svc, "secret")

	// No key → 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mcpReq(""))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no key = %d, want 401", rec.Code)
	}

	// Wrong key → 401.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mcpReq("bearer:wrong"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong key = %d, want 401", rec.Code)
	}

	// Correct key via header → handed to the MCP handler (initialize succeeds).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mcpReq("bearer:secret"))
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("valid header key rejected (%d)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"result"`) {
		t.Errorf("initialize body = %q, want a JSON-RPC result", rec.Body.String())
	}

	// Correct key via query param → also accepted.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mcpReq("?key=secret"))
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("valid query key rejected (%d)", rec.Code)
	}
}

func TestMCPHTTPHandler_NoAuthWhenKeyEmpty(t *testing.T) {
	svc := api.NewServerWithStore(scanRunner{}, api.NewStore(), api.ServerConfig{AllowPrivateTargets: true})
	h := mcpHTTPHandler(svc, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mcpReq(""))
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("open handler rejected request (%d)", rec.Code)
	}
}
