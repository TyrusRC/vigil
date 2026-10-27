// Package mcp exposes vigil's control surface as a Model Context Protocol
// server so MCP-speaking agents can drive scans. Every tool is a thin wrapper
// over *api.Server (the same service the REST API and web UI use), so there is
// no duplicated scan logic across transports.
package mcp

import (
	"bytes"
	"context"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TyrusRC/vigil/internal/api"
	"github.com/TyrusRC/vigil/internal/core"
)

// defaultListLimit bounds scan_list when the caller omits a limit.
const defaultListLimit = 50

// New builds an MCP server whose tools delegate to svc. version is reported in
// the server's implementation info.
func New(svc *api.Server, version string) *mcpsdk.Server {
	if version == "" {
		version = "dev"
	}
	s := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:        "vigil",
		Title:       "vigil web vulnerability scanner",
		Description: "Launch and manage vigil scans, read findings and reports, and run compliance assessments.",
		Version:     version,
	}, nil)
	registerTools(s, svc)
	return s
}

// --- tool input/output types (kept small so the inferred schemas stay stable
// and an agent gets exactly the fields it needs) ---

type empty struct{}

type scanRef struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
	Target string `json:"target"`
}

type summaryDTO struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type jobDTO struct {
	ScanID   string      `json:"scan_id"`
	Target   string      `json:"target"`
	Profile  string      `json:"profile,omitempty"`
	Status   string      `json:"status"`
	Error    string      `json:"error,omitempty"`
	Summary  *summaryDTO `json:"summary,omitempty"`
	Progress string      `json:"progress,omitempty"`
}

type findingDTO struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	URL      string   `json:"url,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
}

func jobToDTO(j *api.ScanJob) jobDTO {
	dto := jobDTO{
		ScanID:  j.ID,
		Target:  j.Target,
		Profile: j.Profile,
		Status:  string(j.Status),
		Error:   j.Error,
	}
	if j.Summary != nil {
		dto.Summary = &summaryDTO{
			Total:    j.Summary.TotalFindings,
			Critical: j.Summary.Critical,
			High:     j.Summary.High,
			Medium:   j.Summary.Medium,
			Low:      j.Summary.Low,
			Info:     j.Summary.Info,
		}
	}
	if j.Progress != nil {
		dto.Progress = j.Progress.Phase
	}
	return dto
}

func findingsToDTO(fs core.Findings) []findingDTO {
	out := make([]findingDTO, 0, len(fs))
	for _, f := range fs {
		out = append(out, findingDTO{
			ID:       f.ID,
			Title:    f.Title,
			Severity: string(f.Severity),
			URL:      f.URL,
			CWE:      f.CWE,
		})
	}
	return out
}

// registerTools wires every tool. Handlers return (nil, out, nil) and let the
// SDK marshal the typed output; a returned error becomes a tool error result.
func registerTools(s *mcpsdk.Server, svc *api.Server) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_start",
		Description: "Start a new scan. Returns immediately with a scan_id; poll scan_status/scan_findings for progress. 'profile' is one of quick|normal|thorough|passive; 'config' optionally overrides transport, scope, auth and per-detector toggles.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in struct {
		Target  string          `json:"target" jsonschema:"target URL to scan (http or https)"`
		Profile string          `json:"profile,omitempty" jsonschema:"scan profile: quick, normal, thorough or passive"`
		Config  *api.ScanConfig `json:"config,omitempty" jsonschema:"optional full scan configuration"`
	}) (*mcpsdk.CallToolResult, scanRef, error) {
		job, err := svc.StartScan(ctx, api.ScanRequest{Target: in.Target, Profile: in.Profile, Config: in.Config})
		if err != nil {
			return nil, scanRef{}, err
		}
		return nil, scanRef{ScanID: job.ID, Status: string(job.Status), Target: job.Target}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_status",
		Description: "Get a scan's status, profile, error (if any) and severity summary once completed.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID string `json:"scan_id" jsonschema:"the scan id returned by scan_start"`
	}) (*mcpsdk.CallToolResult, jobDTO, error) {
		job, err := svc.GetScan(in.ScanID)
		if err != nil {
			return nil, jobDTO{}, err
		}
		return nil, jobToDTO(job), nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_list",
		Description: "List scans in creation order (newest last), with status and severity summary.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		Offset int `json:"offset,omitempty"`
		Limit  int `json:"limit,omitempty"`
	}) (*mcpsdk.CallToolResult, struct {
		Scans []jobDTO `json:"scans"`
	}, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = defaultListLimit
		}
		jobs := svc.ListScans(in.Offset, limit)
		out := struct {
			Scans []jobDTO `json:"scans"`
		}{Scans: make([]jobDTO, 0, len(jobs))}
		for _, j := range jobs {
			out.Scans = append(out.Scans, jobToDTO(j))
		}
		return nil, out, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_findings",
		Description: "List a completed scan's findings (id, title, severity, url, cwe). Use scan_report for full detail.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID string `json:"scan_id"`
	}) (*mcpsdk.CallToolResult, struct {
		Count    int          `json:"count"`
		Findings []findingDTO `json:"findings"`
	}, error) {
		findings, err := svc.Findings(in.ScanID)
		if err != nil {
			return nil, struct {
				Count    int          `json:"count"`
				Findings []findingDTO `json:"findings"`
			}{}, err
		}
		dtos := findingsToDTO(findings)
		return nil, struct {
			Count    int          `json:"count"`
			Findings []findingDTO `json:"findings"`
		}{Count: len(dtos), Findings: dtos}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_report",
		Description: "Render a completed scan's report. 'format' is one of json|sarif|html|markdown|csv|... (default json). Returns the rendered content as text.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID string `json:"scan_id"`
		Format string `json:"format,omitempty"`
	}) (*mcpsdk.CallToolResult, struct {
		ContentType string `json:"content_type"`
		Content     string `json:"content"`
	}, error) {
		var buf bytes.Buffer
		ct, err := svc.Report(in.ScanID, in.Format, &buf)
		if err != nil {
			return nil, struct {
				ContentType string `json:"content_type"`
				Content     string `json:"content"`
			}{}, err
		}
		return nil, struct {
			ContentType string `json:"content_type"`
			Content     string `json:"content"`
		}{ContentType: ct, Content: buf.String()}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_cancel",
		Description: "Cancel a running scan.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID string `json:"scan_id"`
	}) (*mcpsdk.CallToolResult, struct {
		Status string `json:"status"`
	}, error) {
		if err := svc.CancelScan(in.ScanID); err != nil {
			return nil, struct {
				Status string `json:"status"`
			}{}, err
		}
		return nil, struct {
			Status string `json:"status"`
		}{Status: "cancelled"}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "list_profiles",
		Description: "List the available scan profiles and their descriptions.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ empty) (*mcpsdk.CallToolResult, struct {
		Profiles []api.ProfileInfo `json:"profiles"`
	}, error) {
		return nil, struct {
			Profiles []api.ProfileInfo `json:"profiles"`
		}{Profiles: svc.Profiles()}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "config_defaults",
		Description: "List the controllable detector names and profile names for building a scan config.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ empty) (*mcpsdk.CallToolResult, struct {
		Detectors []string `json:"detectors"`
		Profiles  []string `json:"profiles"`
	}, error) {
		detectors, profiles := svc.ConfigDefaults()
		return nil, struct {
			Detectors []string `json:"detectors"`
			Profiles  []string `json:"profiles"`
		}{Detectors: detectors, Profiles: profiles}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "list_tools",
		Description: "List the external scanner tools and whether each is available on this host.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ empty) (*mcpsdk.CallToolResult, struct {
		Tools []api.ToolInfo `json:"tools"`
	}, error) {
		return nil, struct {
			Tools []api.ToolInfo `json:"tools"`
		}{Tools: svc.ToolList()}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "compliance_assess",
		Description: "Assess a completed scan against a compliance framework ('pci-dss', 'hipaa' or 'iso-27001'). Returns the assessment as JSON text.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID    string `json:"scan_id"`
		Framework string `json:"framework" jsonschema:"pci-dss, hipaa or iso-27001"`
	}) (*mcpsdk.CallToolResult, struct {
		Content string `json:"content"`
	}, error) {
		assessment, err := svc.Compliance(in.ScanID, in.Framework)
		if err != nil {
			return nil, struct {
				Content string `json:"content"`
			}{}, err
		}
		var buf bytes.Buffer
		if err := assessment.WriteJSON(&buf); err != nil {
			return nil, struct {
				Content string `json:"content"`
			}{}, err
		}
		return nil, struct {
			Content string `json:"content"`
		}{Content: buf.String()}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "fp_mark",
		Description: "Mark (fp=true) or clear (fp=false) a finding as a false positive. Returns the new false-positive count.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in struct {
		ScanID    string `json:"scan_id"`
		FindingID string `json:"finding_id"`
		FP        bool   `json:"fp"`
		Reason    string `json:"reason,omitempty"`
	}) (*mcpsdk.CallToolResult, struct {
		Count int `json:"count"`
	}, error) {
		count, err := svc.MarkFP(in.ScanID, in.FindingID, in.FP, in.Reason)
		if err != nil {
			return nil, struct {
				Count int `json:"count"`
			}{}, err
		}
		return nil, struct {
			Count int `json:"count"`
		}{Count: count}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "target_list",
		Description: "List the saved, re-scannable targets.",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ empty) (*mcpsdk.CallToolResult, struct {
		Targets []*api.Target `json:"targets"`
	}, error) {
		return nil, struct {
			Targets []*api.Target `json:"targets"`
		}{Targets: svc.Targets()}, nil
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "target_scan",
		Description: "Start a scan for a saved target by its id, recording it as the target's last scan.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in struct {
		TargetID string          `json:"target_id"`
		Profile  string          `json:"profile,omitempty"`
		Config   *api.ScanConfig `json:"config,omitempty"`
	}) (*mcpsdk.CallToolResult, scanRef, error) {
		job, err := svc.ScanTarget(ctx, in.TargetID, api.ScanRequest{Profile: in.Profile, Config: in.Config})
		if err != nil {
			return nil, scanRef{}, err
		}
		return nil, scanRef{ScanID: job.ID, Status: string(job.Status), Target: job.Target}, nil
	})
}
