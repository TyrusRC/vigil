package typeconfuse

import (
	"net/url"
	"testing"
)

func TestIntParams(t *testing.T) {
	u, _ := url.Parse("https://example.com/api/products?page=1&limit=10&name=test")
	got := intParams(u)
	want := map[string]bool{"page": true, "limit": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected param %q", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("missing param %q", p)
	}
}

func TestIntParamsEmpty(t *testing.T) {
	u, _ := url.Parse("https://example.com/api/products?name=test&category=food")
	got := intParams(u)
	if len(got) != 0 {
		t.Errorf("expected no integer params, got %v", got)
	}
}

func TestReplaceParam(t *testing.T) {
	u, _ := url.Parse("https://example.com/api?page=1&limit=10")
	got := replaceParam(u, "page", "true")
	parsed, _ := url.Parse(got)
	if parsed.Query().Get("page") != "true" {
		t.Errorf("expected page=true, got page=%s", parsed.Query().Get("page"))
	}
	if parsed.Query().Get("limit") != "10" {
		t.Errorf("limit should be preserved, got %s", parsed.Query().Get("limit"))
	}
}
