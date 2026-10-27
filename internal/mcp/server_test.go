package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TyrusRC/vigil/internal/api"
	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/scanner"
)

// fakeRunner returns a canned result without touching the network.
type fakeRunner struct{}

func (fakeRunner) Run(_ context.Context, req api.ScanRequest) (*scanner.ScanResult, error) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = req.Target + "/?id=1"
	f.CWE = []string{"CWE-89"}
	return &scanner.ScanResult{Targets: []string{req.Target}, Findings: core.Findings{f}}, nil
}

// connect builds an MCP server over an in-memory transport and returns a
// connected client session.
func connect(t *testing.T) *mcpsdk.ClientSession {
	t.Helper()
	svc := api.NewServerWithStore(fakeRunner{}, api.NewStore(), api.ServerConfig{
		AllowPrivateTargets: true,
		DataDir:             t.TempDir(),
	})
	srv := New(svc, "test")

	clientT, serverT := mcpsdk.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcpsdk.ClientSession, name string, args any, out any) *mcpsdk.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if out != nil && res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("decode %s output: %v", name, err)
		}
	}
	return res
}

func TestListTools(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	want := map[string]bool{
		"scan_start": false, "scan_status": false, "scan_list": false,
		"scan_findings": false, "scan_report": false, "scan_cancel": false,
		"list_profiles": false, "config_defaults": false, "list_tools": false,
		"compliance_assess": false, "fp_mark": false, "target_list": false, "target_scan": false,
	}
	for _, tool := range res.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q not registered", name)
		}
	}
}

func TestScanRoundTrip(t *testing.T) {
	cs := connect(t)

	var started scanRef
	call(t, cs, "scan_start", map[string]any{"target": "http://example.com", "profile": "quick"}, &started)
	if started.ScanID == "" {
		t.Fatal("scan_start returned no scan_id")
	}

	// Poll scan_status until completed (the fake runner finishes near-instantly).
	var status jobDTO
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		call(t, cs, "scan_status", map[string]any{"scan_id": started.ScanID}, &status)
		if status.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Status != "completed" {
		t.Fatalf("scan did not complete: status=%q", status.Status)
	}
	if status.Summary == nil || status.Summary.Critical != 1 {
		t.Errorf("summary = %+v, want 1 critical", status.Summary)
	}

	// Findings carry the finding id.
	var findings struct {
		Count    int          `json:"count"`
		Findings []findingDTO `json:"findings"`
	}
	call(t, cs, "scan_findings", map[string]any{"scan_id": started.ScanID}, &findings)
	if findings.Count != 1 || findings.Findings[0].Severity != "critical" {
		t.Fatalf("findings = %+v", findings)
	}
	fid := findings.Findings[0].ID

	// Mark it a false positive.
	var fp struct {
		Count int `json:"count"`
	}
	call(t, cs, "fp_mark", map[string]any{"scan_id": started.ScanID, "finding_id": fid, "fp": true, "reason": "test"}, &fp)
	if fp.Count != 1 {
		t.Errorf("fp count = %d, want 1", fp.Count)
	}

	// Compliance assessment renders.
	compRes := call(t, cs, "compliance_assess", map[string]any{"scan_id": started.ScanID, "framework": "pci-dss"}, nil)
	if compRes.IsError {
		t.Errorf("compliance_assess returned an error result")
	}
}

func TestScanStart_InvalidTargetIsError(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "scan_start",
		Arguments: map[string]any{"target": ""},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Error("empty target should produce a tool error result")
	}
}

func TestMetaTools(t *testing.T) {
	cs := connect(t)

	var profiles struct {
		Profiles []api.ProfileInfo `json:"profiles"`
	}
	call(t, cs, "list_profiles", map[string]any{}, &profiles)
	if len(profiles.Profiles) == 0 {
		t.Error("list_profiles returned none")
	}

	var defaults struct {
		Detectors []string `json:"detectors"`
		Profiles  []string `json:"profiles"`
	}
	call(t, cs, "config_defaults", map[string]any{}, &defaults)
	if len(defaults.Detectors) == 0 {
		t.Error("config_defaults returned no detectors")
	}
}
