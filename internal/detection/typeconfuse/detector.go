// Package typeconfuse detects server-side type confusion errors by
// sending unexpected types (boolean, JSON object, array, negative
// number) to parameters that look numeric (page, limit, id, offset,
// count). A server that crashes (500) instead of returning a validation
// error has an unhandled input-type bug — potential DoS, error-message
// info leak, or a stepping stone to NoSQL injection.
//
// This is distinct from typejuggling (PHP loose-equality auth bypass):
// typeconfuse tests arbitrary endpoints, not just login forms, and
// targets server errors rather than auth state changes.
package typeconfuse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/vigil/internal/core"
	vigilhttp "github.com/TyrusRC/vigil/internal/http"
)

// integerParamHints identifies query parameters likely to be integers.
var integerParamHints = []string{
	"page", "limit", "offset", "count", "size", "per_page",
	"perPage", "pageSize", "page_size", "num", "skip", "take",
	"start", "end", "from", "to", "max", "min",
}

// confusionPayloads are values that cause type confusion on weakly typed
// backends (JavaScript parseInt, Python int(), Prisma/Sequelize ORMs).
var confusionPayloads = []struct {
	label string
	value string
}{
	{"boolean_true", "true"},
	{"negative", "-1"},
	{"json_object", `{"$gt":0}`},
	{"array", "[]"},
	{"float", "1.5e2"},
}

// Detector sends type-confused values to integer-like query parameters.
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

// Detect tests every integer-hint query parameter on targetURL.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	// Collect integer-like params already in the URL.
	params := intParams(u)
	if len(params) == 0 {
		return res, nil
	}

	// Baseline: the URL as-is.
	baseResp, err := d.client.Get(ctx, targetURL)
	if err != nil || baseResp == nil {
		return res, nil
	}
	baseStatus := baseResp.StatusCode

	// Only test when baseline succeeds (2xx/3xx).
	if baseStatus < 200 || baseStatus >= 400 {
		return res, nil
	}

	for _, p := range params {
		for _, payload := range confusionPayloads {
			probeURL := replaceParam(u, p, payload.value)
			resp, err := d.client.Get(ctx, probeURL)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 500 && baseStatus != 500 {
				evidence := fmt.Sprintf(
					"Payload: %s=%s (%s)\nBaseline: %s=%s → HTTP %d\nProbe: → HTTP %d\n"+
						"Server returned 500 on non-integer input where baseline returned %d.",
					p, u.Query().Get(p), "integer", p, payload.value, baseStatus,
					resp.StatusCode, baseStatus)
				finding := &core.Finding{
					Type:        "Type Confusion Error",
					Severity:    core.SeverityLow,
					Confidence:  core.ConfidenceHigh,
					Title:       fmt.Sprintf("Type Confusion Error (param %s)", p),
					Description: fmt.Sprintf("Parameter '%s' causes HTTP 500 when sent '%s' (%s) instead of an integer. "+
						"The server does not validate the parameter type before passing it to the backend. "+
						"This can leak stack traces, enable DoS, or indicate deeper injection surface.", p, payload.value, payload.label),
					URL:       targetURL,
					Parameter: p,
					Evidence:  evidence,
					WSTG:     []string{"WSTG-INPV-17"},
					APITop10: []string{"API8:2023"},
				}
				res.Findings = append(res.Findings, finding)
				break // one proof per param is enough
			}
		}
	}
	return res, nil
}

// intParams returns query-param names from u that match integer hints.
func intParams(u *url.URL) []string {
	var out []string
	for key := range u.Query() {
		kl := strings.ToLower(key)
		for _, hint := range integerParamHints {
			if kl == strings.ToLower(hint) {
				out = append(out, key)
				break
			}
		}
	}
	return out
}

// replaceParam returns a new URL string with param set to val.
func replaceParam(u *url.URL, param, val string) string {
	q := u.Query()
	q.Set(param, val)
	clone := *u
	clone.RawQuery = q.Encode()
	return clone.String()
}

// bodyKeys returns JSON object keys from a response body, or nil.
func bodyKeys(body []byte) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	return keys
}
