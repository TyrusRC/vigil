package api

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/TyrusRC/vigil/internal/scanner"
	"github.com/TyrusRC/vigil/internal/scope"
)

// ScanConfig is the JSON-serializable projection of the scanner's two config
// structs (scanner.Config for transport and scanner.InternalScanConfig for
// detector behavior). It is what the REST API and MCP server accept so a
// client can drive every meaningful knob: typed fields for the common scalars,
// auth, scope and crawl, plus a generic Detectors map that toggles any of the
// ~130 Enable* detectors by short name via reflection.
//
// Pointer / omitempty fields distinguish "unset" (keep the profile/default)
// from an explicit zero value, so a client can, e.g., turn a default-on
// detector off without re-stating everything else.
type ScanConfig struct {
	Profile string `json:"profile,omitempty"`

	// Transport (→ scanner.Config)
	Rate             float64           `json:"rate,omitempty"`      // req/sec cap (0 = unlimited)
	Concurrency      int               `json:"concurrency,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Cookie           string            `json:"cookie,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	Method           string            `json:"method,omitempty"`
	Data             string            `json:"data,omitempty"`
	Insecure         bool              `json:"insecure,omitempty"`

	// Intensity (→ InternalScanConfig)
	MaxPayloadsPerParam int   `json:"max_payloads_per_param,omitempty"`
	MaxParams           int   `json:"max_params,omitempty"`
	ParamConcurrency    int   `json:"param_concurrency,omitempty"`
	IncludeWAFBypass    *bool `json:"include_waf_bypass,omitempty"`
	TimeBasedSQLi       *bool `json:"time_based_sqli,omitempty"`

	// Scope
	NoScope           bool     `json:"no_scope,omitempty"`
	ScopeHosts        []string `json:"scope_hosts,omitempty"`
	IncludePath       []string `json:"include_path,omitempty"`
	ExcludePath       []string `json:"exclude_path,omitempty"`
	NoDefaultExcludes bool     `json:"no_default_excludes,omitempty"`

	// Focus
	OnlyTests  []string `json:"only_tests,omitempty"`
	OnlyParams []string `json:"only_params,omitempty"`

	// Auth / identity
	LoginURL      string            `json:"login_url,omitempty"`
	LSRPath       string            `json:"lsr_path,omitempty"`
	AuthACookie   string            `json:"auth_a_cookie,omitempty"`
	AuthAHeaders  map[string]string `json:"auth_a_headers,omitempty"`
	AuthBCookie   string            `json:"auth_b_cookie,omitempty"`
	AuthBHeaders  map[string]string `json:"auth_b_headers,omitempty"`
	IDORTargetURL string            `json:"idor_url,omitempty"`

	// Crawl / discovery (needs Chrome for SPA)
	SPACrawl      bool   `json:"spa_crawl,omitempty"`
	StateCrawl    bool   `json:"state_crawl,omitempty"`
	CrawlMaxDepth int    `json:"crawl_depth,omitempty"`
	CrawlMaxPages int    `json:"crawl_max_pages,omitempty"`
	SubmitForms   bool   `json:"submit_forms,omitempty"`
	ChromePath    string `json:"chrome_path,omitempty"`

	// Templates / misc
	Templates       []string `json:"templates,omitempty"`
	TemplateTags    []string `json:"template_tags,omitempty"`
	APISpecURL      string   `json:"api_spec,omitempty"`
	RegistrationURL string   `json:"registration_url,omitempty"`
	NVDAPIKey       string   `json:"nvd_api_key,omitempty"`
	IAST            bool     `json:"iast,omitempty"`
	IASTAddr        string   `json:"iast_addr,omitempty"`
	Verbose         bool     `json:"verbose,omitempty"`

	// Detectors toggles any Enable* detector by short name (e.g. "sqli",
	// "xss", "cachedeception"). true enables, false disables. Unknown names
	// are rejected (fail closed) so a typo never silently does nothing.
	Detectors map[string]bool `json:"detectors,omitempty"`
}

// detectorFields maps a short detector name to its InternalScanConfig bool
// field name, built by reflecting over every Enable* bool field. Computed once.
var detectorFields = buildDetectorFields()

func buildDetectorFields() map[string]string {
	m := make(map[string]string)
	t := reflect.TypeOf(scanner.InternalScanConfig{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type.Kind() == reflect.Bool && strings.HasPrefix(f.Name, "Enable") {
			m[strings.ToLower(strings.TrimPrefix(f.Name, "Enable"))] = f.Name
		}
	}
	return m
}

// DetectorNames returns the sorted set of detector short names a client may
// toggle via ScanConfig.Detectors (used by GET /api/config/defaults).
func DetectorNames() []string {
	out := make([]string, 0, len(detectorFields))
	for name := range detectorFields {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// build turns the DTO into the two concrete scanner config structs. It starts
// from the named profile (or defaults) for InternalScanConfig and from
// scanner.DefaultConfig() for transport, then applies the DTO's overrides.
func (c *ScanConfig) Build() (*scanner.Config, *scanner.InternalScanConfig, error) {
	transport := scanner.DefaultConfig()
	var internal *scanner.InternalScanConfig
	if c.Profile != "" {
		internal = scanner.GetProfile(c.Profile).Config
	} else {
		internal = scanner.DefaultInternalConfig()
	}

	// Transport overrides.
	if c.Rate > 0 {
		internal.RateLimitPerSec = c.Rate
	}
	if c.Concurrency > 0 {
		transport.Concurrency = c.Concurrency
	}
	if c.TimeoutSeconds > 0 {
		transport.Timeout = time.Duration(c.TimeoutSeconds) * time.Second
	}
	if len(c.Headers) > 0 {
		transport.Headers = c.Headers
	}
	if c.Cookie != "" {
		transport.Cookies = c.Cookie
	}
	if c.UserAgent != "" {
		transport.UserAgent = c.UserAgent
	}
	if c.Method != "" {
		transport.Method = c.Method
	}
	if c.Data != "" {
		transport.Data = c.Data
	}
	transport.Insecure = c.Insecure
	internal.Verbose = c.Verbose
	transport.Verbose = c.Verbose

	// Intensity.
	if c.MaxPayloadsPerParam > 0 {
		internal.MaxPayloadsPerParam = c.MaxPayloadsPerParam
	}
	if c.MaxParams > 0 {
		internal.MaxParams = c.MaxParams
	}
	if c.ParamConcurrency > 0 {
		internal.ParamConcurrency = c.ParamConcurrency
	}
	if c.IncludeWAFBypass != nil {
		internal.IncludeWAFBypass = *c.IncludeWAFBypass
	}
	if c.TimeBasedSQLi != nil {
		internal.EnableTimeBasedSQLi = *c.TimeBasedSQLi
	}

	// Focus.
	internal.OnlyTests = c.OnlyTests
	internal.OnlyParams = c.OnlyParams

	// Auth / identity.
	if c.AuthACookie != "" || len(c.AuthAHeaders) > 0 {
		internal.AuthA = scanner.AuthState{Cookies: c.AuthACookie, Headers: c.AuthAHeaders}
	}
	if c.AuthBCookie != "" || len(c.AuthBHeaders) > 0 {
		internal.AuthB = scanner.AuthState{Cookies: c.AuthBCookie, Headers: c.AuthBHeaders}
	}
	internal.LoginURL = firstNonEmpty(c.LoginURL, internal.LoginURL)
	internal.LSRPath = firstNonEmpty(c.LSRPath, internal.LSRPath)
	internal.IDORTargetURL = firstNonEmpty(c.IDORTargetURL, internal.IDORTargetURL)

	// Crawl / discovery.
	if c.SPACrawl {
		internal.EnableSPACrawl = true
	}
	if c.StateCrawl {
		internal.EnableStateCrawl = true
	}
	if c.CrawlMaxDepth > 0 {
		internal.CrawlMaxDepth = c.CrawlMaxDepth
	}
	if c.CrawlMaxPages > 0 {
		internal.CrawlMaxPages = c.CrawlMaxPages
	}
	if c.SubmitForms {
		internal.SubmitForms = true
	}
	internal.ChromePath = firstNonEmpty(c.ChromePath, internal.ChromePath)

	// Templates / misc.
	if len(c.Templates) > 0 {
		internal.EnableTemplates = true
		internal.TemplatePaths = c.Templates
	}
	if len(c.TemplateTags) > 0 {
		internal.TemplateTags = c.TemplateTags
	}
	internal.APISpecURL = firstNonEmpty(c.APISpecURL, internal.APISpecURL)
	internal.RegistrationURL = firstNonEmpty(c.RegistrationURL, internal.RegistrationURL)
	internal.NVDAPIKey = firstNonEmpty(c.NVDAPIKey, internal.NVDAPIKey)
	if c.IAST {
		internal.EnableIAST = true
	}
	internal.IASTCallbackAddr = firstNonEmpty(c.IASTAddr, internal.IASTCallbackAddr)

	// Scope.
	if !c.NoScope && (len(c.ScopeHosts) > 0 || len(c.IncludePath) > 0 || len(c.ExcludePath) > 0) {
		sc, err := scope.New(c.ScopeHosts, c.IncludePath, c.ExcludePath, !c.NoDefaultExcludes)
		if err != nil {
			return nil, nil, fmt.Errorf("scope: %w", err)
		}
		internal.Scope = sc
	}

	// Per-detector toggles last, so an explicit toggle wins over a typed field.
	if len(c.Detectors) > 0 {
		v := reflect.ValueOf(internal).Elem()
		for name, on := range c.Detectors {
			field, ok := detectorFields[strings.ToLower(name)]
			if !ok {
				return nil, nil, fmt.Errorf("unknown detector %q", name)
			}
			v.FieldByName(field).SetBool(on)
		}
	}

	return transport, internal, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
