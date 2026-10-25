package discovery

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/http"
)

// JSAPIDiscoverer extracts API endpoints and configuration from JavaScript
// bundles — catches Supabase/Firebase client init, REST API base URLs,
// GraphQL endpoints, and WebSocket URLs that other discoverers miss on
// static SPA/ISR sites.
type JSAPIDiscoverer struct{ client *http.Client }

func NewJSAPIDiscoverer() *JSAPIDiscoverer { return &JSAPIDiscoverer{} }

func (d *JSAPIDiscoverer) WithClient(c *http.Client) *JSAPIDiscoverer {
	d.client = c
	return d
}

func (d *JSAPIDiscoverer) Name() string { return "jsapi" }

var (
	// REST API base URLs: "/api/v1/users", "/api/auth/login"
	restAPIPathRe = regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_-]{3,60})["']`)
	// Absolute API URLs: "https://api.example.com/v1/..."
	absAPIURLRe = regexp.MustCompile(`["'](https?://[a-zA-Z0-9.-]+/(?:api|v[0-9]|rest|graphql)[a-zA-Z0-9/_.-]{0,60})["']`)
	// GraphQL endpoint: "/graphql", "/gql", "graphql"
	graphqlPathRe = regexp.MustCompile(`["']([a-zA-Z0-9/._-]*graphql[a-zA-Z0-9/._-]*)["']`)
	// WebSocket URLs: "wss://...", "ws://..."
	wsURLRe = regexp.MustCompile(`["'](wss?://[a-zA-Z0-9._:/-]{5,100})["']`)
	// Supabase/Firebase/Appwrite client init
	baasURLRe = regexp.MustCompile(`["'](https://[a-zA-Z0-9-]+\.(?:supabase\.co|firebaseio\.com|firebaseapp\.com|appwrite\.io)[^"'\s]*)["']`)
	// Environment-style config: BASE_URL, API_URL, BACKEND_URL
	envConfigRe = regexp.MustCompile(`(?:BASE_URL|API_URL|BACKEND_URL|SERVER_URL|ENDPOINT)\s*[:=]\s*["']([^"']{5,100})["']`)
)

func (d *JSAPIDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}
	base, _ := url.Parse(targetURL)
	if base == nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	// Collect JS sources
	bodies := []string{resp.Body}
	if d.client != nil {
		for _, m := range scriptSrcRegex.FindAllStringSubmatch(resp.Body, maxScriptFetches) {
			ref, err := url.Parse(strings.TrimSpace(m[1]))
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			rr, err := d.client.Get(ctx, abs)
			if err != nil || rr == nil {
				continue
			}
			bodies = append(bodies, rr.Body)
		}
	}

	add := func(endpoint, paramName, loc, method string) {
		key := endpoint + ":" + paramName
		if seen[key] {
			return
		}
		seen[key] = true
		params = append(params, core.Parameter{
			Name:      paramName,
			Location:  loc,
			Method:    method,
			SourceURL: endpoint,
		})
	}

	resolve := func(raw string) string {
		if strings.HasPrefix(raw, "http") {
			return raw
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return base.ResolveReference(ref).String()
	}

	for _, js := range bodies {
		// REST API paths → synthesize as endpoints to test
		for _, m := range restAPIPathRe.FindAllStringSubmatch(js, 30) {
			ep := resolve(m[1])
			if ep == "" {
				continue
			}
			// Extract the last path segment as a param hint
			parts := strings.Split(strings.TrimRight(m[1], "/"), "/")
			lastPart := parts[len(parts)-1]
			if isLikelyParam(lastPart) {
				add(ep, lastPart, core.ParamLocationPath, "GET")
			}
		}

		// Absolute API URLs
		for _, m := range absAPIURLRe.FindAllStringSubmatch(js, 20) {
			ep := m[1]
			parts := strings.Split(strings.TrimRight(ep, "/"), "/")
			lastPart := parts[len(parts)-1]
			if isLikelyParam(lastPart) {
				add(ep, lastPart, core.ParamLocationPath, "GET")
			}
		}

		// GraphQL endpoints
		for _, m := range graphqlPathRe.FindAllStringSubmatch(js, 5) {
			ep := resolve(m[1])
			if ep != "" {
				add(ep, "query", core.ParamLocationBody, "POST")
			}
		}

		// WebSocket URLs — note as endpoints for the websocket detector
		for _, m := range wsURLRe.FindAllStringSubmatch(js, 5) {
			add(m[1], "message", core.ParamLocationBody, "GET")
		}

		// BaaS URLs (Supabase, Firebase, Appwrite)
		for _, m := range baasURLRe.FindAllStringSubmatch(js, 5) {
			add(m[1], "select", core.ParamLocationQuery, "GET")
		}

		// Environment config URLs
		for _, m := range envConfigRe.FindAllStringSubmatch(js, 10) {
			ep := resolve(m[1])
			if ep != "" && strings.HasPrefix(ep, "http") {
				add(ep, "", core.ParamLocationQuery, "GET")
			}
		}
	}
	return params, nil
}

// isLikelyParam checks if a URL path segment looks like a parameter name
// (not a version number, not a static resource).
func isLikelyParam(s string) bool {
	if len(s) < 2 || len(s) > 30 {
		return false
	}
	// Skip version segments like v1, v2
	if len(s) == 2 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		return false
	}
	// Skip file extensions
	if strings.Contains(s, ".") {
		return false
	}
	// Skip pure numbers (likely static IDs in examples)
	allDigit := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigit = false
			break
		}
	}
	return !allDigit
}
