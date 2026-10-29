// Package openapiexpose detects publicly accessible OpenAPI/Swagger
// documentation (WSTG-CONF-05, CWE-200). Production APIs that expose
// /docs, /redoc, /openapi.json, or /swagger.json give an attacker the
// full endpoint map — parameters, auth requirements, and data types.
package openapiexpose

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/vigil/internal/core"
	vigilhttp "github.com/TyrusRC/vigil/internal/http"
)

// probePaths are the standard locations frameworks serve API docs from.
var probePaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/docs",
	"/redoc",
	"/swagger-ui.html",
	"/api/docs",
	"/api/openapi.json",
	"/api-docs",
	"/swagger/v1/swagger.json",
	"/api/v1/docs",
}

// jsonMarkers appear in valid OpenAPI/Swagger JSON specs.
var jsonMarkers = []string{"\"paths\"", "\"openapi\"", "\"swagger\""}

// htmlMarkers appear in rendered documentation UIs.
var htmlMarkers = []string{"swagger", "redoc", "FastAPI", "Swagger UI", "openapi"}

// Detector probes for publicly accessible API documentation.
type Detector struct {
	client *vigilhttp.Client
}

// New returns a Detector backed by the shared HTTP client.
func New(client *vigilhttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect probes the target for exposed API documentation endpoints.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}
	origin := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	var exposed []string

	for _, path := range probePaths {
		probeURL := origin + path
		resp, respErr := d.client.Get(ctx, probeURL)
		if respErr != nil || resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		body := string(resp.Body)
		if len(body) < 50 {
			continue
		}

		if isSpecOrDocs(body) {
			exposed = append(exposed, path)
		}
	}

	if len(exposed) == 0 {
		return res, nil
	}

	evidence := fmt.Sprintf("Exposed API documentation at: %s\nPaths: %s",
		origin, strings.Join(exposed, ", "))

	endpointCount := ""
	for _, p := range exposed {
		if strings.HasSuffix(p, ".json") {
			probeURL := origin + p
			resp, _ := d.client.Get(ctx, probeURL)
			if resp != nil && resp.StatusCode == 200 {
				n := strings.Count(string(resp.Body), "\"paths\"")
				if n > 0 {
					pathCount := strings.Count(string(resp.Body), "\"/")
					endpointCount = fmt.Sprintf(" (%d+ endpoints)", pathCount)
				}
			}
			break
		}
	}

	res.Findings = append(res.Findings, &core.Finding{
		Type:        "OpenAPI/Swagger Documentation Exposed",
		Severity:    "medium",
		Confidence:  "high",
		Title:       "OpenAPI/Swagger Documentation Exposed",
		Description: fmt.Sprintf("API documentation is publicly accessible without authentication%s. An attacker can map every endpoint, parameter, and data type before testing. Paths: %s", endpointCount, strings.Join(exposed, ", ")),
		URL:         origin + exposed[0],
		Parameter:   strings.Join(exposed, ", "),
		Evidence:    evidence,
		WSTG:        []string{"WSTG-CONF-05"},
		CWE:         []string{"CWE-200"},
		Remediation: "Restrict API documentation endpoints to authenticated users or internal networks. In FastAPI, set docs_url=None and redoc_url=None in production. In Spring Boot, restrict springdoc.swagger-ui.path behind auth.",
	})

	return res, nil
}

// isSpecOrDocs checks if a response body looks like an OpenAPI spec or
// a rendered documentation page.
func isSpecOrDocs(body string) bool {
	lower := strings.ToLower(body)
	for _, m := range jsonMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	for _, m := range htmlMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
