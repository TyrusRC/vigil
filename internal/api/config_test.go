package api

import "testing"

func TestScanConfig_Build_DetectorToggles(t *testing.T) {
	off := false
	cfg := ScanConfig{
		Detectors: map[string]bool{
			"sqli":           false, // default-on → turn off
			"http2race":      true,  // default-off → turn on
			"CacheDeception": true,  // name match is case-insensitive
		},
		TimeBasedSQLi: &off,
	}

	_, internal, err := cfg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if internal.EnableSQLi {
		t.Error("EnableSQLi should be off")
	}
	if !internal.EnableHTTP2Race {
		t.Error("EnableHTTP2Race should be on")
	}
	if !internal.EnableCacheDeception {
		t.Error("EnableCacheDeception should be on (case-insensitive)")
	}
	if internal.EnableTimeBasedSQLi {
		t.Error("EnableTimeBasedSQLi should be off via typed field")
	}
}

func TestScanConfig_Build_UnknownDetectorRejected(t *testing.T) {
	cfg := ScanConfig{Detectors: map[string]bool{"notadetector": true}}
	if _, _, err := cfg.Build(); err == nil {
		t.Fatal("expected error for unknown detector, got nil")
	}
}

func TestScanConfig_Build_TransportAndScope(t *testing.T) {
	cfg := ScanConfig{
		Rate:        12,
		Cookie:      "session=abc",
		UserAgent:   "vigil-test",
		ScopeHosts:  []string{"example.com"},
		ExcludePath: []string{"^/logout"},
	}
	transport, internal, err := cfg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if transport.Cookies != "session=abc" || transport.UserAgent != "vigil-test" {
		t.Errorf("transport not applied: %+v", transport)
	}
	if internal.RateLimitPerSec != 12 {
		t.Errorf("rate = %v, want 12", internal.RateLimitPerSec)
	}
	if internal.Scope == nil {
		t.Fatal("scope should be built from scope_hosts/exclude_path")
	}
}

func TestScanConfig_Build_Auth(t *testing.T) {
	cfg := ScanConfig{
		AuthACookie:  "a=1",
		AuthBHeaders: map[string]string{"Authorization": "Bearer b"},
	}
	_, internal, err := cfg.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if internal.AuthA.Cookies != "a=1" {
		t.Errorf("AuthA.Cookies = %q", internal.AuthA.Cookies)
	}
	if internal.AuthB.Headers["Authorization"] != "Bearer b" {
		t.Errorf("AuthB.Headers = %v", internal.AuthB.Headers)
	}
}

func TestDetectorNames_CoversCommonDetectors(t *testing.T) {
	names := DetectorNames()
	if len(names) < 100 {
		t.Fatalf("expected 100+ detector names, got %d", len(names))
	}
	want := map[string]bool{"sqli": false, "xss": false, "ssrf": false}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("missing expected detector names: %v", want)
	}
}
