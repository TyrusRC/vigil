package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Finding represents a discovered security vulnerability.
type Finding struct {
	// Identification
	ID   string `json:"id"`
	Tool string `json:"tool,omitempty"`

	// Classification
	Type       string     `json:"type"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`

	// Details
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter,omitempty"`

	// Evidence
	Evidence string `json:"evidence,omitempty"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`

	// OWASP Mapping
	WSTG       []string `json:"wstg,omitempty"`
	Top10      []string `json:"top10,omitempty"`
	APITop10   []string `json:"api_top10,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`

	// Remediation
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// Status
	Verified  bool      `json:"verified,omitempty"`
	Timestamp time.Time `json:"timestamp"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewFinding creates a new Finding with the given type and severity.
// Title defaults to vulnType so both the "type" and "title" JSON fields
// carry a human-readable label when the caller does not set Title explicitly.
func NewFinding(vulnType string, severity Severity) *Finding {
	return &Finding{
		ID:         uuid.New().String(),
		Type:       vulnType,
		Title:      vulnType,
		Severity:   severity,
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
}

// Validate checks if the finding has all required fields.
func (f *Finding) Validate() error {
	if f.ID == "" {
		return errors.New("finding ID is required")
	}
	if f.Type == "" {
		return errors.New("finding type is required")
	}
	if !f.Severity.IsValid() {
		return errors.New("invalid severity")
	}
	if f.Confidence != "" && !f.Confidence.IsValid() {
		return errors.New("invalid confidence")
	}
	if f.URL == "" {
		return errors.New("finding URL is required")
	}
	return nil
}

// DeduplicationKey returns a unique key for deduplication purposes.
func (f *Finding) DeduplicationKey() string {
	data := fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(f.Type), f.Type, len(f.URL), f.URL, len(f.Parameter), f.Parameter)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// WithOWASPMapping adds OWASP framework mappings to the finding.
func (f *Finding) WithOWASPMapping(wstg, top10, cwe []string) *Finding {
	f.WSTG = wstg
	f.Top10 = top10
	f.CWE = cwe
	return f
}

// At sets the URL and parameter the finding was discovered at and returns the
// finding for fluent chaining.
func (f *Finding) At(url, parameter string) *Finding {
	f.URL = url
	f.Parameter = parameter
	return f
}

// ByTool records the detector or tool that produced the finding and returns
// the finding for fluent chaining.
func (f *Finding) ByTool(tool string) *Finding {
	f.Tool = tool
	return f
}

// SetEvidence sets the evidence details for the finding.
func (f *Finding) SetEvidence(evidence, request, response string) *Finding {
	f.Evidence = evidence
	f.Request = request
	f.Response = response
	return f
}

// WithProof attaches a reproducible curl command and the server response.
// The user can copy-paste the curl command to reproduce the finding.
func (f *Finding) WithProof(method, targetURL, payload string, statusCode int, responseBody string) *Finding {
	if method == "" {
		method = "GET"
	}

	// Build a reproducible curl command
	param := f.Parameter
	if param == "" {
		param = "PARAM"
	}
	payloadDisplay := payload
	if payloadDisplay == "" {
		payloadDisplay = f.Evidence
		if idx := strings.Index(payloadDisplay, "\n"); idx > 0 {
			payloadDisplay = payloadDisplay[:idx]
		}
	}
	if strings.HasPrefix(payloadDisplay, "Payload: ") {
		payloadDisplay = payloadDisplay[9:]
	}

	if method == "GET" {
		// GET: payload in query string
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		f.Request = fmt.Sprintf("curl '%s%s%s=%s'", targetURL, sep, param, payloadDisplay)
	} else {
		// POST: payload in body
		f.Request = fmt.Sprintf("curl -X %s '%s' -d '%s=%s'", method, targetURL, param, payloadDisplay)
	}

	// Truncated response showing the server behavior
	maxBody := 300
	body := responseBody
	if len(body) > maxBody {
		body = body[:maxBody] + "..."
	}
	// Single-line the response for compact display
	body = strings.ReplaceAll(body, "\n", " ")
	body = strings.ReplaceAll(body, "\r", "")
	f.Response = fmt.Sprintf("HTTP %d → %s", statusCode, strings.TrimSpace(body))
	return f
}

// Age returns the duration since the finding was discovered.
func (f *Finding) Age() time.Duration {
	return time.Since(f.Timestamp)
}

// Findings is a slice of Finding with helper methods.
type Findings []*Finding

// SortBySeverity sorts findings by severity (critical first).
func (f Findings) SortBySeverity() {
	sort.Slice(f, func(i, j int) bool {
		return f[i].Severity.Score() > f[j].Severity.Score()
	})
}

// Deduplicate removes duplicate findings based on deduplication key.
func (f Findings) Deduplicate() Findings {
	best := make(map[string]*Finding)
	order := make([]string, 0, len(f))

	for _, finding := range f {
		key := finding.DeduplicationKey()
		if existing, ok := best[key]; !ok {
			best[key] = finding
			order = append(order, key)
		} else if confidenceScore(finding.Confidence) > confidenceScore(existing.Confidence) {
			best[key] = finding
		}
	}

	result := make(Findings, 0, len(order))
	for _, key := range order {
		result = append(result, best[key])
	}
	return result
}

// confidenceScore returns a numeric score for confidence comparison.
func confidenceScore(c Confidence) int {
	switch c {
	case ConfidenceConfirmed:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// FilterBySeverity returns findings with the specified severity.
func (f Findings) FilterBySeverity(severity Severity) Findings {
	result := make(Findings, 0)
	for _, finding := range f {
		if finding.Severity == severity {
			result = append(result, finding)
		}
	}
	return result
}

// FilterByMinSeverity returns findings with severity >= minSeverity.
func (f Findings) FilterByMinSeverity(minSeverity Severity) Findings {
	minScore := minSeverity.Score()
	result := make(Findings, 0)
	for _, finding := range f {
		if finding.Severity.Score() >= minScore {
			result = append(result, finding)
		}
	}
	return result
}

// Count returns the total number of findings.
func (f Findings) Count() int {
	return len(f)
}

// CountBySeverity returns a map of severity to count.
func (f Findings) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, finding := range f {
		counts[finding.Severity]++
	}
	return counts
}
