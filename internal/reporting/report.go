package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/scoring"
)

const (
	reportVersion = "1.0.0"
	toolName      = "vigil"
)

// Report represents a scan report.
type Report struct {
	Version     string              `json:"version"`
	Tool        string              `json:"tool"`
	GeneratedAt time.Time           `json:"generated_at"`
	ScanResult  *scanner.ScanResult `json:"scan_result"`
	Summary     scanner.ScanSummary `json:"summary"`
}

// NewReport creates a new report from scan results. It enriches findings with
// default CVSS scores before computing the summary.
func NewReport(result *scanner.ScanResult) *Report {
	scoring.Enrich(result.Findings)
	return &Report{
		Version:     reportVersion,
		Tool:        toolName,
		GeneratedAt: time.Now(),
		ScanResult:  result,
		Summary:     result.Summary(),
	}
}

// WriteJSON writes the report as JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// WriteText writes the report as human-readable text.
func (r *Report) WriteText(w io.Writer) error {
	result := r.ScanResult

	fmt.Fprintln(w, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w, "                    vigil SCAN REPORT                            ")
	fmt.Fprintln(w, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)

	// Scan info
	fmt.Fprintf(w, "Report Version: %s\n", r.Version)
	fmt.Fprintf(w, "Generated At:   %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Scan Duration:  %s\n", result.Duration.Round(time.Second))
	fmt.Fprintln(w)

	// Targets
	fmt.Fprintln(w, "TARGETS:")
	for _, target := range result.Targets {
		fmt.Fprintf(w, "  - %s\n", target)
	}
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintln(w, "SUMMARY:")
	fmt.Fprintf(w, "  Total Findings: %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(w, "  Critical: %d\n", r.Summary.Critical)
	fmt.Fprintf(w, "  High:     %d\n", r.Summary.High)
	fmt.Fprintf(w, "  Medium:   %d\n", r.Summary.Medium)
	fmt.Fprintf(w, "  Low:      %d\n", r.Summary.Low)
	fmt.Fprintf(w, "  Info:     %d\n", r.Summary.Info)
	fmt.Fprintf(w, "  Tools Run: %d | Skipped: %d\n", result.ToolsRun, result.ToolsSkipped)
	fmt.Fprintln(w)

	// Findings grouped by severity
	if len(result.Findings) > 0 {
		fmt.Fprintln(w, "FINDINGS:")
		fmt.Fprintln(w, "---------")
		severityOrder := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}
		idx := 0
		for _, sev := range severityOrder {
			for _, finding := range result.Findings {
				if finding.Severity != sev {
					continue
				}
				idx++
				fmt.Fprintf(w, "\n[%d] %s (%s)\n", idx, finding.Type, finding.Severity)
				fmt.Fprintf(w, "    URL: %s\n", finding.URL)
				if finding.Parameter != "" {
					fmt.Fprintf(w, "    Parameter: %s\n", finding.Parameter)
				}
				if finding.Description != "" {
					fmt.Fprintf(w, "    Description: %s\n", finding.Description)
				}
				if finding.Evidence != "" {
					ev := finding.Evidence
					if len(ev) > 500 {
						ev = ev[:500] + "..."
					}
					fmt.Fprintf(w, "    Evidence: %s\n", ev)
				}
				if finding.Request != "" {
					req := finding.Request
					if len(req) > 800 {
						req = req[:800] + "\n    ... (truncated)"
					}
					fmt.Fprintf(w, "    Request:\n")
					for _, line := range strings.Split(req, "\n") {
						fmt.Fprintf(w, "      %s\n", line)
					}
				}
				if finding.Response != "" {
					resp := finding.Response
					if len(resp) > 800 {
						resp = resp[:800] + "\n    ... (truncated)"
					}
					fmt.Fprintf(w, "    Response:\n")
					for _, line := range strings.Split(resp, "\n") {
						fmt.Fprintf(w, "      %s\n", line)
					}
				}
				if finding.Tool != "" {
					fmt.Fprintf(w, "    Tool: %s\n", finding.Tool)
				}
				if len(finding.CWE) > 0 {
					fmt.Fprintf(w, "    CWE: %v\n", finding.CWE)
				}
				if len(finding.WSTG) > 0 {
					fmt.Fprintf(w, "    WSTG: %v\n", finding.WSTG)
				}
				if finding.Verified {
					fmt.Fprintf(w, "    Verified: yes\n")
				}
			}
		}
	} else {
		fmt.Fprintln(w, "No vulnerabilities found.")
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ERRORS:")
		for _, err := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", err)
		}
	}

	fmt.Fprintln(w)
	return nil
}
