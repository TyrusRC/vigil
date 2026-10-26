package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/TyrusRC/vigil/internal/tools"
)

// toolLogName is the single JSONL file that records every external-tool run.
const toolLogName = "tools.jsonl"

// toolRunRecord is one line in tools.jsonl: a structured record of a single
// external-tool invocation. Raw output is kept alongside parsed metadata so
// the file is both greppable and machine-parseable (one JSON object per line).
type toolRunRecord struct {
	Timestamp  time.Time        `json:"ts"`
	Tool       string           `json:"tool"`
	Target     string           `json:"target,omitempty"`
	DurationMS int64            `json:"duration_ms"`
	Success    bool             `json:"success"`
	Findings   int              `json:"findings"`
	Summary    []toolRunFinding `json:"finding_summary,omitempty"`
	Errors     []string         `json:"errors,omitempty"`
	Raw        string           `json:"raw,omitempty"`
}

type toolRunFinding struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	URL       string `json:"url,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// writeToolLog appends one JSONL record for a tool run to <dir>/tools.jsonl, so
// every integrated tool's run is saved in one structured file — not just the
// few that happen to write a native output file. A no-op when dir is empty or
// there is nothing to record.
//
// The record is written in a single O_APPEND write, which is atomic on POSIX,
// so concurrent tool goroutines never interleave within a line.
func writeToolLog(dir, target, tool string, result *tools.ToolResult) {
	if dir == "" || result == nil {
		return
	}
	// Nothing worth recording: no output, no findings, no errors.
	if result.RawOutput == "" && len(result.Findings) == 0 && len(result.Errors) == 0 {
		return
	}

	rec := toolRunRecord{
		Timestamp:  time.Now(),
		Tool:       tool,
		Target:     target,
		DurationMS: result.ExecutionTime.Milliseconds(),
		Success:    result.Success,
		Findings:   len(result.Findings),
		Errors:     result.Errors,
		Raw:        result.RawOutput,
	}
	for _, f := range result.Findings {
		if f == nil {
			continue
		}
		rec.Summary = append(rec.Summary, toolRunFinding{
			Type:      f.Type,
			Severity:  string(f.Severity),
			URL:       f.URL,
			Parameter: f.Parameter,
		})
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, toolLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}
