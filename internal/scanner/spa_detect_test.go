package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	vighttp "github.com/TyrusRC/vigil/internal/http"
)

func TestDetectSPACatchAll_TrueForSPA(t *testing.T) {
	spaHTML := "<html><head><title>My SPA</title></head><body><div id='root'></div><script src='/app.js'></script></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, spaHTML)
	}))
	defer srv.Close()

	client := vighttp.NewClient()
	got := detectSPACatchAll(context.Background(), client, srv.URL)
	if !got {
		t.Error("expected SPA catch-all detection to return true for a server that serves the same body for all paths")
	}
}

func TestDetectSPACatchAll_FalseForNormalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "<html><body>Home page with unique content</body></html>")
		} else {
			w.WriteHeader(404)
			fmt.Fprint(w, "Not Found")
		}
	}))
	defer srv.Close()

	client := vighttp.NewClient()
	got := detectSPACatchAll(context.Background(), client, srv.URL)
	if got {
		t.Error("expected SPA catch-all detection to return false for a server with different responses per path")
	}
}

func TestDetectSPACatchAll_FalseForShortBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	client := vighttp.NewClient()
	got := detectSPACatchAll(context.Background(), client, srv.URL)
	if !got {
		// short body < 100 chars should return false
	}
	// The function returns false for bodies < 100 chars
	if got {
		t.Error("expected false for very short body")
	}
}

func TestBodyHash(t *testing.T) {
	h1 := bodyHash("hello world")
	h2 := bodyHash("hello world")
	h3 := bodyHash("different content")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
	if len(h1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 hex chars, got %d", len(h1))
	}
}
