package cmd

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/decision"
	"github.com/TyrusRC/vigil/internal/scanner"
)

func printDryRun(targets []string, cfg *scanner.InternalScanConfig) {
	w := os.Stderr
	fmt.Fprintln(w, "=== DRY RUN — no traffic will be sent ===")
	fmt.Fprintf(w, "Targets (%d):\n", len(targets))
	for _, t := range targets {
		fmt.Fprintf(w, "  %s\n", t)
	}
	fmt.Fprintf(w, "Profile: %s\n", profile)
	fmt.Fprintf(w, "Level: %d  Risk: %d\n", level, risk)
	fmt.Fprintf(w, "Rate limit: %.0f req/s\n", cfg.RateLimitPerSec)
	if cfg.Scope != nil {
		fmt.Fprintln(w, "Scope: ON (target host(s))")
	} else {
		fmt.Fprintln(w, "Scope: OFF")
	}
	fmt.Fprintln(w, "\nEnabled detectors:")
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if strings.HasPrefix(f.Name, "Enable") && f.Type.Kind() == reflect.Bool && v.Field(i).Bool() {
			fmt.Fprintf(w, "  %s\n", strings.TrimPrefix(f.Name, "Enable"))
		}
	}
	tplPaths := templateDirs
	if len(tplPaths) == 0 {
		tplPaths = discoverTemplatePaths()
	}
	if len(tplPaths) > 0 {
		fmt.Fprintf(w, "\nTemplates: %v\n", tplPaths)
	}
	if loginURL != "" {
		fmt.Fprintf(w, "\nLogin: %s (user: %s)\n", loginURL, loginUser)
	}
	fmt.Fprintln(w, "\n=== No traffic sent ===")
}

// adjudicateFindings runs a fail-open Haruspex triage pass over already-produced
// findings. It annotates each finding with "real finding" probability and tags
// likely noise for review. It never removes, reorders, or re-severities findings.
func adjudicateFindings(ctx context.Context, findings core.Findings) {
	cfg := decision.FromEnv()
	if len(findings) == 0 {
		return
	}
	engine := "heuristic"
	if cfg.Enabled && (cfg.APIKey != "" || decision.IsLocal(cfg.BaseURL)) {
		engine = "haruspex"
	}
	fmt.Fprintf(os.Stderr, "[*] Finding adjudication (%s): scoring %d findings...\n", engine, len(findings))
	items := make([]decision.Item, len(findings))
	for i, f := range findings {
		ev := f.Evidence
		if len(ev) > 600 {
			ev = ev[:600]
		}
		var tags []string
		tags = append(tags, string(f.Severity))
		tags = append(tags, string(f.Confidence))
		if f.Verified {
			tags = append(tags, "verified-by-replay")
		} else {
			tags = append(tags, "unverified")
		}
		if f.Tool != "" {
			tags = append(tags, "tool:"+f.Tool)
		}
		if f.Metadata != nil {
			if rounds, ok := f.Metadata["verification_rounds"]; ok {
				tags = append(tags, fmt.Sprintf("vrounds:%v", rounds))
			}
			if confirmed, ok := f.Metadata["verification_confirmed"]; ok {
				tags = append(tags, fmt.Sprintf("vconfirmed:%v", confirmed))
			}
		}
		qualifier := ""
		if !f.Verified {
			qualifier = decision.ImpactQualifier(f.Type)
		}
		items[i] = decision.Item{
			Key: f.ID,
			Text: fmt.Sprintf("%s on %s param %q [%s]: %s%s",
				f.Type, f.URL, f.Parameter, strings.Join(tags, ","), ev, qualifier),
		}
	}
	probs, err := decision.Adjudicate(ctx, cfg, items)
	if err != nil || probs == nil || len(probs) != len(findings) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Haruspex adjudication failed (findings unchanged): %v\n", err)
		}
		return
	}
	reviewed := 0
	for i, f := range findings {
		p := probs[i]
		if p == nil {
			continue
		}
		if f.Metadata == nil {
			f.Metadata = map[string]interface{}{}
		}
		f.Metadata["haruspex_real_prob"] = *p
		if *p < 0.5 && !f.Verified {
			f.Metadata["haruspex_triage"] = "review"
		}
		reviewed++
	}
	if reviewed > 0 {
		fmt.Fprintf(os.Stderr, "[+] Haruspex adjudication: scored %d/%d findings\n", reviewed, len(findings))
	}
}
