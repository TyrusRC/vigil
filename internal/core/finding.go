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

// WithProof attaches the raw HTTP request and response like Burp's proxy history.
// Shows the full wire format: request line + headers + body, response status + headers + body.
func (f *Finding) WithProof(method, targetURL, payload string, statusCode int, responseBody string) *Finding {
	if method == "" {
		method = "GET"
	}

	// Build raw HTTP request (Burp-style)
	param := f.Parameter
	if param == "" {
		param = "input"
	}
	payloadVal := payload
	if payloadVal == "" {
		payloadVal = f.Evidence
		if idx := strings.Index(payloadVal, "\n"); idx > 0 {
			payloadVal = payloadVal[:idx]
		}
	}
	if strings.HasPrefix(payloadVal, "Payload: ") {
		payloadVal = payloadVal[9:]
	}

	var reqBuilder strings.Builder
	if method == "GET" {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		fullURL := fmt.Sprintf("%s%s%s=%s", targetURL, sep, param, payloadVal)
		reqBuilder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", method, fullURL))
	} else {
		reqBuilder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", method, targetURL))
	}
	// Parse host from URL
	if idx := strings.Index(targetURL, "://"); idx > 0 {
		hostPart := targetURL[idx+3:]
		if slashIdx := strings.Index(hostPart, "/"); slashIdx > 0 {
			hostPart = hostPart[:slashIdx]
		}
		reqBuilder.WriteString(fmt.Sprintf("Host: %s\n", hostPart))
	}
	reqBuilder.WriteString("User-Agent: vigil/1.0\n")
	reqBuilder.WriteString("Accept: */*\n")
	if method == "POST" || method == "PUT" || method == "PATCH" {
		body := fmt.Sprintf("%s=%s", param, payloadVal)
		reqBuilder.WriteString("Content-Type: application/x-www-form-urlencoded\n")
		reqBuilder.WriteString(fmt.Sprintf("Content-Length: %d\n", len(body)))
		reqBuilder.WriteString("\n")
		reqBuilder.WriteString(body)
	}
	f.Request = reqBuilder.String()

	// Build raw HTTP response (Burp-style) — skip if no real response
	if statusCode > 0 && responseBody != "" {
		maxBody := 2000
		body := responseBody
		if len(body) > maxBody {
			body = body[:maxBody] + "\n\n[...truncated...]"
		}
		f.Response = fmt.Sprintf("HTTP/1.1 %d\nContent-Length: %d\n\n%s", statusCode, len(responseBody), body)
	}
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

// MergeSameRoot collapses findings that share the same (Title, Parameter) into
// one finding per root cause, collecting the affected URLs. URL-level findings
// (e.g. "Web Cache Deception" on 43 different paths) become one entry with the
// highest severity/confidence and an AffectedURLs list in Metadata. Param-level
// injection findings that differ only by URL keep the URL that had the strongest
// evidence. Call after Deduplicate.
func (f Findings) MergeSameRoot() Findings {
	type group struct {
		best *Finding
		urls []string
	}
	groups := make(map[string]*group)
	order := make([]string, 0, len(f))

	for _, finding := range f {
		key := fmt.Sprintf("%d:%s|%d:%s", len(finding.Title), finding.Title, len(finding.Parameter), finding.Parameter)
		if g, ok := groups[key]; !ok {
			groups[key] = &group{best: finding, urls: []string{finding.URL}}
			order = append(order, key)
		} else {
			g.urls = append(g.urls, finding.URL)
			if severityScore(finding.Severity) > severityScore(g.best.Severity) ||
				(severityScore(finding.Severity) == severityScore(g.best.Severity) &&
					confidenceScore(finding.Confidence) > confidenceScore(g.best.Confidence)) {
				oldURL := g.best.URL
				g.best = finding
				// Keep the best URL, the rest go to affected list
				_ = oldURL
			}
		}
	}

	result := make(Findings, 0, len(order))
	for _, key := range order {
		g := groups[key]
		if len(g.urls) > 1 {
			// Deduplicate URLs
			seen := make(map[string]bool)
			unique := make([]string, 0, len(g.urls))
			for _, u := range g.urls {
				if !seen[u] {
					seen[u] = true
					unique = append(unique, u)
				}
			}
			if g.best.Metadata == nil {
				g.best.Metadata = make(map[string]interface{})
			}
			g.best.Metadata["affected_urls"] = unique
			g.best.Metadata["affected_count"] = len(unique)
		}
		result = append(result, g.best)
	}
	return result
}

// severityScore returns a numeric score for severity comparison.
func severityScore(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
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
