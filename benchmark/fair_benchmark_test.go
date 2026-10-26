package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/templates"
	"github.com/TyrusRC/vigil/internal/templates/parser"
)

// TestFairComparison runs a fair comparison between vigil and nuclei
func TestFairComparison(t *testing.T) {
	nucleiPath := os.Getenv("HOME") + "/go/bin/nuclei"
	if _, err := os.Stat(nucleiPath); os.IsNotExist(err) {
		var err error
		nucleiPath, err = exec.LookPath("nuclei")
		if err != nil {
			t.Skip("Nuclei not found")
		}
	}

	// Create test server that returns predictable response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.19.0")
		w.Header().Set("X-Powered-By", "PHP/8.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Test Application v1.0</title></head>
<body>
<h1>Welcome</h1>
<div id="version">1.0.0</div>
</body>
</html>`))
	}))
	defer server.Close()

	// Create template that will definitely match
	tmplContent := `id: fair-benchmark-test
info:
  name: Fair Benchmark Test
  author: benchmark
  severity: info
  description: Template for fair benchmarking
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "nginx"
      - type: status
        status:
          - 200
    matchers-condition: and
`
	tmpDir := t.TempDir()
	tmplPath := filepath.Join(tmpDir, "fair-test.yaml")
	os.WriteFile(tmplPath, []byte(tmplContent), 0644)

	// Parse template for vigil
	p := parser.New()
	tmpl, err := p.ParseFile(tmplPath)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	iterations := 20

	// ========================================
	// vigil Benchmark
	// ========================================
	t.Log("\n╔══════════════════════════════════════════╗")
	t.Log("║        vigil Template Scanner             ║")
	t.Log("╚══════════════════════════════════════════╝")

	s, _ := scanner.NewTemplateScanner(&scanner.TemplateScanConfig{
		Concurrency: 1, // Single thread for fair comparison
	})

	// Warmup
	target, _ := core.NewTarget(server.URL)
	s.Scan(context.Background(), target, []*templates.Template{tmpl})

	vigilTimes := make([]time.Duration, iterations)
	var vigilMatches int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		target, _ := core.NewTarget(server.URL)
		result, _ := s.Scan(context.Background(), target, []*templates.Template{tmpl})
		vigilTimes[i] = time.Since(start)
		if len(result.Findings) > 0 {
			vigilMatches++
		}
	}

	avgVigil := averageDuration(vigilTimes)
	t.Logf("  Iterations: %d", iterations)
	t.Logf("  Matches: %d/%d", vigilMatches, iterations)
	t.Logf("  Average: %v", avgVigil)
	t.Logf("  Min: %v", minDuration(vigilTimes))
	t.Logf("  Max: %v", maxDuration(vigilTimes))

	// ========================================
	// Nuclei Benchmark
	// ========================================
	t.Log("\n╔══════════════════════════════════════════╗")
	t.Log("║              Nuclei                      ║")
	t.Log("╚══════════════════════════════════════════╝")

	// Warmup nuclei
	warmupCmd := exec.Command(nucleiPath, "-t", tmplPath, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-c", "1")
	warmupCmd.Run()

	nucleiTimes := make([]time.Duration, iterations)
	var nucleiMatches int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		cmd := exec.Command(nucleiPath, "-t", tmplPath, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-c", "1", "-no-color")
		output, _ := cmd.CombinedOutput()
		nucleiTimes[i] = time.Since(start)
		if strings.TrimSpace(string(output)) != "" {
			nucleiMatches++
		}
	}

	avgNuclei := averageDuration(nucleiTimes)
	t.Logf("  Iterations: %d", iterations)
	t.Logf("  Matches: %d/%d", nucleiMatches, iterations)
	t.Logf("  Average: %v", avgNuclei)
	t.Logf("  Min: %v", minDuration(nucleiTimes))
	t.Logf("  Max: %v", maxDuration(nucleiTimes))

	// ========================================
	// Summary
	// ========================================
	t.Log("\n╔══════════════════════════════════════════╗")
	t.Log("║           Performance Summary            ║")
	t.Log("╚══════════════════════════════════════════╝")

	t.Logf("  vigil avg:   %v", avgVigil)
	t.Logf("  Nuclei avg: %v", avgNuclei)

	if avgVigil < avgNuclei {
		speedup := float64(avgNuclei) / float64(avgVigil)
		t.Logf("\n  ✓ vigil is %.1fx faster than Nuclei", speedup)
	} else {
		speedup := float64(avgVigil) / float64(avgNuclei)
		t.Logf("\n  ✗ Nuclei is %.1fx faster than vigil", speedup)
	}

	// Memory comparison (rough)
	t.Log("\n  Note: vigil runs as a library (in-process),")
	t.Log("        Nuclei runs as external process (higher overhead)")
}

// TestMultiTemplateFairComparison compares with 50 real templates
func TestMultiTemplateFairComparison(t *testing.T) {
	templatesDir := "/tmp/nuclei-templates/http/technologies"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		t.Skip("Nuclei templates not found")
	}

	nucleiPath := os.Getenv("HOME") + "/go/bin/nuclei"
	if _, err := os.Stat(nucleiPath); os.IsNotExist(err) {
		t.Skip("Nuclei not found")
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.0.3")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>Test</body></html>`))
	}))
	defer server.Close()

	// Load templates
	p := parser.New()
	allTmpls, err := p.ParseDirectory(templatesDir)
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Use first 50 templates
	numTemplates := 50
	if len(allTmpls) < numTemplates {
		numTemplates = len(allTmpls)
	}
	tmpls := allTmpls[:numTemplates]

	t.Logf("Testing with %d templates\n", numTemplates)

	// Create temp dir for nuclei
	tmpDir := t.TempDir()
	for i, tmpl := range tmpls {
		if tmpl.Path != "" {
			content, _ := os.ReadFile(tmpl.Path)
			destPath := filepath.Join(tmpDir, fmt.Sprintf("t%d.yaml", i))
			os.WriteFile(destPath, content, 0644)
		}
	}

	iterations := 5

	// vigil
	t.Log("\n=== vigil ===")
	s, _ := scanner.NewTemplateScanner(&scanner.TemplateScanConfig{Concurrency: 10})

	// Warmup
	target, _ := core.NewTarget(server.URL)
	s.Scan(context.Background(), target, tmpls)

	var vigilTotalTime time.Duration
	var vigilFindings int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		target, _ := core.NewTarget(server.URL)
		result, _ := s.Scan(context.Background(), target, tmpls)
		vigilTotalTime += time.Since(start)
		vigilFindings = len(result.Findings)
	}

	avgVigil := vigilTotalTime / time.Duration(iterations)
	t.Logf("  Average: %v (%d findings)", avgVigil, vigilFindings)

	// Nuclei
	t.Log("\n=== Nuclei ===")

	// Warmup
	warmup := exec.Command(nucleiPath, "-t", tmpDir, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-c", "10")
	warmup.Run()

	var nucleiTotalTime time.Duration
	var nucleiFindings int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		cmd := exec.Command(nucleiPath, "-t", tmpDir, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-c", "10", "-no-color")
		output, _ := cmd.CombinedOutput()
		nucleiTotalTime += time.Since(start)
		nucleiFindings = len(strings.Split(strings.TrimSpace(string(output)), "\n"))
		if strings.TrimSpace(string(output)) == "" {
			nucleiFindings = 0
		}
	}

	avgNuclei := nucleiTotalTime / time.Duration(iterations)
	t.Logf("  Average: %v (%d findings)", avgNuclei, nucleiFindings)

	// Summary
	t.Log("\n=== Summary ===")
	if avgVigil < avgNuclei {
		speedup := float64(avgNuclei) / float64(avgVigil)
		t.Logf("  vigil is %.1fx faster with %d templates", speedup, numTemplates)
	} else {
		speedup := float64(avgVigil) / float64(avgNuclei)
		t.Logf("  Nuclei is %.1fx faster with %d templates", speedup, numTemplates)
	}
}
