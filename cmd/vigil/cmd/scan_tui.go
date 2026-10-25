package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
	uitui "github.com/TyrusRC/vigil/internal/tui"
)

// printTUIFindings renders findings as inline TUI cards grouped by severity.
func printTUIFindings(findings core.Findings) {
	if !uitui.IsEnabled() || len(findings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr)
	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	idx := 0
	for _, sev := range severityOrder {
		for _, f := range findings {
			if strings.ToLower(string(f.Severity)) != sev {
				continue
			}
			idx++
			uitui.FindingInline(idx, string(f.Severity), f.Type, f.URL, f.Parameter, f.Evidence)
		}
	}
}

// printTUISummary renders the severity summary with colored badges.
func printTUISummary(result *scanner.ScanResult) {
	if !uitui.IsEnabled() {
		return
	}
	crit, high, med, low, inf := 0, 0, 0, 0, 0
	for _, f := range result.Findings {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		default:
			inf++
		}
	}
	dur := result.Duration.Round(time.Second).String()
	uitui.Summary(crit, high, med, low, inf, dur)
}

// printTUIAutoSave shows the auto-save notification.
func printTUIAutoSave(dir string) {
	if uitui.IsEnabled() {
		uitui.SavedReport(dir)
	} else {
		fmt.Fprintf(os.Stderr, "[+] Auto-saved report to %s\n", dir)
	}
}
