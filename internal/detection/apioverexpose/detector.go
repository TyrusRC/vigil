// Package apioverexpose detects excessive data exposure via list-vs-detail
// field-count differential (OWASP API3:2023). When a detail endpoint
// (e.g. /api/products/{id}) returns significantly more fields than the
// corresponding list endpoint (/api/products), the extra fields are often
// internal data (promoCode, scoutScore, hiddenBadges, userId) that the
// frontend never renders but any HTTP client can read.
//
// The detector looks for REST-style list endpoints in the discovered URLs,
// extracts an ID from the first array element, fetches the detail URL, and
// compares field counts. A >2× difference with sensitive field names in
// the delta triggers a finding.
package apioverexpose

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TyrusRC/vigil/internal/core"
	vigilhttp "github.com/TyrusRC/vigil/internal/http"
)

// sensitiveFieldRe matches JSON key names that are internal / sensitive
// and should not appear in unauthenticated API responses.
var sensitiveFieldRe = regexp.MustCompile(
	`(?i)(userId|user_id|teamId|team_id|` +
		`internalId|internal_id|` +
		`secret|token|apiKey|api_key|` +
		`password|passwd|hash|` +
		`promo|discount|coupon|` +
		`score|rating_internal|scout|hidden|` +
		`admin|role|permission|` +
		`ssn|dob|salary|payroll)`)

// Detector compares list vs detail API responses.
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

// Detect tests targetURL as a potential REST list endpoint. It fetches
// the list, extracts an ID from the first item, fetches the detail, and
// compares field counts.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	// Only test URLs that look like REST list endpoints: /api/something
	if !looksLikeListEndpoint(targetURL) {
		return res, nil
	}

	// Fetch the list.
	listResp, err := d.client.Get(ctx, targetURL)
	if err != nil || listResp == nil || listResp.StatusCode != 200 {
		return res, nil
	}

	// Parse the response — expect JSON array or {items:[...]} wrapper.
	listFields, firstID := parseListResponse([]byte(listResp.Body))
	if listFields == 0 || firstID == "" {
		return res, nil
	}

	// Build the detail URL: append /{id} to the list URL.
	detailURL := strings.TrimRight(targetURL, "/") + "/" + firstID
	detailResp, err := d.client.Get(ctx, detailURL)
	if err != nil || detailResp == nil || detailResp.StatusCode != 200 {
		return res, nil
	}

	// Parse detail response.
	detailFieldNames := jsonObjectKeys([]byte(detailResp.Body))
	if len(detailFieldNames) == 0 {
		return res, nil
	}

	// Compare: detail has significantly more fields than list?
	ratio := float64(len(detailFieldNames)) / float64(listFields)
	if ratio < 1.5 {
		return res, nil
	}

	// Check for sensitive fields in the delta.
	var sensitiveExtras []string
	for _, k := range detailFieldNames {
		if sensitiveFieldRe.MatchString(k) {
			sensitiveExtras = append(sensitiveExtras, k)
		}
	}

	if len(sensitiveExtras) == 0 && ratio < 2.0 {
		return res, nil
	}

	severity := core.SeverityMedium
	if len(sensitiveExtras) >= 3 {
		severity = core.SeverityHigh
	}

	evidence := fmt.Sprintf(
		"List endpoint: %s → %d fields per item\n"+
			"Detail endpoint: %s → %d fields (%.1f× more)\n"+
			"Sensitive extra fields: %v",
		targetURL, listFields, detailURL, len(detailFieldNames),
		ratio, sensitiveExtras)

	finding := &core.Finding{
		Type:       "Excessive Data Exposure (List vs Detail)",
		Severity:   severity,
		Confidence: core.ConfidenceMedium,
		Title:      fmt.Sprintf("API detail endpoint returns %.0f%% more fields than list", (ratio-1)*100),
		Description: fmt.Sprintf(
			"The detail endpoint %s returns %d fields while the list endpoint returns %d (%d extra). "+
				"The additional fields include sensitive names: %v. "+
				"These internal fields are accessible without authentication.",
			detailURL, len(detailFieldNames), listFields,
			len(detailFieldNames)-listFields, sensitiveExtras),
		URL:      targetURL,
		Evidence: evidence,
		WSTG:     []string{"WSTG-CONF-06"},
		APITop10: []string{"API3:2023"},
	}
	res.Findings = append(res.Findings, finding)
	return res, nil
}

// looksLikeListEndpoint returns true for paths like /api/products,
// /api/v1/users — a path segment starting with /api.
func looksLikeListEndpoint(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/api?")
}

// parseListResponse tries to extract: field count per item, and the
// first item's "id" value. Handles both [{...}] and {"items":[{...}]}.
func parseListResponse(body []byte) (fieldCount int, firstID string) {
	// Try direct array.
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil && len(arr) > 0 {
		return extractFromFirstItem(arr[0])
	}
	// Try wrapped object with a list field.
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return 0, ""
	}
	for _, key := range []string{"items", "data", "results", "products", "users", "entries", "records", "events", "list"} {
		if raw, ok := obj[key]; ok {
			if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
				return extractFromFirstItem(arr[0])
			}
		}
	}
	return 0, ""
}

func extractFromFirstItem(raw json.RawMessage) (int, string) {
	var item map[string]json.RawMessage
	if json.Unmarshal(raw, &item) != nil {
		return 0, ""
	}
	id := ""
	for _, k := range []string{"id", "ID", "_id", "uuid", "slug"} {
		if v, ok := item[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				id = s
				break
			}
			var n json.Number
			if json.Unmarshal(v, &n) == nil {
				id = n.String()
				break
			}
		}
	}
	return len(item), id
}

func jsonObjectKeys(body []byte) []string {
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
