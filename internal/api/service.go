package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TyrusRC/vigil/internal/compliance"
	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/reporting"
	"github.com/TyrusRC/vigil/internal/scanner"
)

// This file groups the exported operations that make up vigil's control
// surface. Both the HTTP handlers (internal/api) and the MCP server
// (internal/mcp) call these methods, so scan orchestration, config validation
// and the reusable pipelines (reporting, compliance, FP feedback) live in one
// place with no duplicated logic between transports.

// Sentinel errors let callers map a failure to a transport-appropriate status
// (HTTP code, MCP error) without string matching.
var (
	// ErrInvalidRequest is a client error (bad target, bad config). Its message
	// is safe to return to the caller.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrNotFound means the scan, finding or target does not exist.
	ErrNotFound = errors.New("not found")
	// ErrNotCompleted means the scan has not finished, so its result is absent.
	ErrNotCompleted = errors.New("scan has not completed")
	// ErrNotRunning means a cancel was requested for a scan that is not running.
	ErrNotRunning = errors.New("scan is not running")
)

// invalidf wraps a client-facing message as an ErrInvalidRequest.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}

// ProfileInfo is a scan profile's name and description.
type ProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ToolInfo is an external tool's availability as reported to clients.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Available bool   `json:"available"`
}

// StartScan validates and launches a scan asynchronously, returning the queued
// job. When req.Config is nil the persisted settings default is applied. Client
// errors are wrapped as ErrInvalidRequest.
func (s *Server) StartScan(ctx context.Context, req ScanRequest) (*ScanJob, error) {
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		return nil, invalidf("target is required")
	}
	if err := s.validateTarget(req.Target); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRequest, err.Error())
	}
	if req.Config == nil {
		def := s.settings.Get()
		req.Config = &def
	}
	if _, _, err := req.Config.Build(); err != nil {
		return nil, invalidf("invalid config: %s", err.Error())
	}
	job := s.store.Create(req)
	logInfo("scan %s queued for %s", job.ID, req.Target)
	s.start(ctx, job.ID, req)
	return job, nil
}

// GetScan returns a scan job by id.
func (s *Server) GetScan(id string) (*ScanJob, error) {
	job, ok := s.store.Get(id)
	if !ok {
		return nil, ErrNotFound
	}
	return job, nil
}

// ListScans returns a page of scan jobs in creation order.
func (s *Server) ListScans(offset, limit int) []*ScanJob {
	return s.store.ListPaged(offset, limit)
}

// CancelScan stops a running scan.
func (s *Server) CancelScan(id string) error {
	if _, ok := s.store.Get(id); !ok {
		return ErrNotFound
	}
	if !s.store.Cancel(id) {
		return ErrNotRunning
	}
	logInfo("scan %s cancelled by operator", id)
	return nil
}

// Findings returns the findings of a completed scan.
func (s *Server) Findings(id string) (core.Findings, error) {
	job, ok := s.store.Get(id)
	if !ok {
		return nil, ErrNotFound
	}
	if job.Result() == nil {
		return core.Findings{}, nil
	}
	return job.Result().Findings, nil
}

// Report renders a completed scan's report in the given format (default "json")
// to w, returning the content type written.
func (s *Server) Report(id, format string, w io.Writer) (contentType string, err error) {
	job, ok := s.store.Get(id)
	if !ok {
		return "", ErrNotFound
	}
	if job.Status != StatusCompleted || job.result == nil {
		return "", ErrNotCompleted
	}
	if format == "" {
		format = "json"
	}
	ct, ok := reportContentType(format)
	if !ok {
		return "", invalidf("unknown report format: %s", format)
	}
	report := reporting.NewReport(job.result)
	if err := writeReport(w, report, format); err != nil {
		return "", err
	}
	return ct, nil
}

// Profiles returns the available scan profiles.
func (s *Server) Profiles() []ProfileInfo {
	out := make([]ProfileInfo, 0, len(profileNames))
	for _, n := range profileNames {
		p := scanner.GetProfile(n)
		out = append(out, ProfileInfo{Name: p.Name, Description: p.Description})
	}
	return out
}

// ConfigDefaults returns the controllable detector names and profile names.
func (s *Server) ConfigDefaults() (detectors, profiles []string) {
	return DetectorNames(), profileNames
}

// ToolList returns the external tools and their availability.
func (s *Server) ToolList() []ToolInfo {
	out := []ToolInfo{}
	if s.config.ToolsProvider == nil {
		return out
	}
	for _, t := range s.config.ToolsProvider() {
		info := ToolInfo{Name: t.Name(), Available: t.IsAvailable()}
		if info.Available {
			info.Version = t.Version()
		}
		out = append(out, info)
	}
	return out
}

// Compliance assesses a completed scan against a framework ("pci-dss", "hipaa",
// "iso-27001").
func (s *Server) Compliance(id, framework string) (compliance.Assessment, error) {
	job, ok := s.store.Get(id)
	if !ok {
		return compliance.Assessment{}, ErrNotFound
	}
	if job.Result() == nil {
		return compliance.Assessment{}, ErrNotCompleted
	}
	fw, err := compliance.ParseFramework(framework)
	if err != nil {
		return compliance.Assessment{}, fmt.Errorf("%w: %s", ErrInvalidRequest, err.Error())
	}
	return compliance.Assess(job.Result().Findings, fw), nil
}

// MarkFP records (fp=true) or clears (fp=false) a finding as a false positive in
// the persistent FP database, returning the new entry count.
func (s *Server) MarkFP(scanID, findingID string, fp bool, reason string) (int, error) {
	finding, ok := s.findFinding(scanID, findingID)
	if !ok {
		return 0, ErrNotFound
	}
	db := scanner.LoadFPFeedback(s.fpPath)
	if fp {
		db.MarkFP(finding, reason)
	} else {
		db.UnmarkFP(finding)
	}
	if err := db.Save(); err != nil {
		return 0, fmt.Errorf("save FP database: %w", err)
	}
	return db.Count(), nil
}

// Targets returns the persistent targets.
func (s *Server) Targets() []*Target {
	return s.targets.List()
}

// ScanTarget launches a scan for a persistent target, recording it as the
// target's last scan. A nil req.Config uses the settings default.
func (s *Server) ScanTarget(ctx context.Context, targetID string, req ScanRequest) (*ScanJob, error) {
	target, ok := s.targets.Get(targetID)
	if !ok {
		return nil, ErrNotFound
	}
	req.Target = target.URL
	job, err := s.StartScan(ctx, req)
	if err != nil {
		return nil, err
	}
	s.targets.SetLastScan(target.ID, job.ID)
	return job, nil
}
