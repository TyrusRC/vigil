package apioverexpose

import (
	"encoding/json"
	"testing"
)

func TestLooksLikeListEndpoint(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/api/products", true},
		{"https://example.com/api/v1/users?limit=10", true},
		{"https://example.com/about", false},
		{"https://example.com/graphql", false},
	}
	for _, tc := range cases {
		got := looksLikeListEndpoint(tc.url)
		if got != tc.want {
			t.Errorf("looksLikeListEndpoint(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestParseListResponse_Array(t *testing.T) {
	body := `[{"id":"abc","name":"Test","slug":"test"},{"id":"def","name":"Other","slug":"other"}]`
	count, id := parseListResponse([]byte(body))
	if count != 3 || id != "abc" {
		t.Errorf("got count=%d id=%q, want 3/abc", count, id)
	}
}

func TestParseListResponse_Wrapped(t *testing.T) {
	body := `{"products":[{"id":"xyz","name":"Prod","price":10}],"pagination":{"total":1}}`
	count, id := parseListResponse([]byte(body))
	if count != 3 || id != "xyz" {
		t.Errorf("got count=%d id=%q, want 3/xyz", count, id)
	}
}

func TestParseListResponse_NumericID(t *testing.T) {
	body := `[{"id":42,"title":"Foo"}]`
	count, id := parseListResponse([]byte(body))
	if count != 2 || id != "42" {
		t.Errorf("got count=%d id=%q, want 2/42", count, id)
	}
}

func TestSensitiveFieldRe(t *testing.T) {
	cases := []struct {
		field string
		want  bool
	}{
		{"userId", true},
		{"promoCode", true},
		{"scoutScore", true},
		{"hiddenBadges", true},
		{"name", false},
		{"slug", false},
		{"created_at", false},
	}
	for _, tc := range cases {
		got := sensitiveFieldRe.MatchString(tc.field)
		if got != tc.want {
			t.Errorf("sensitiveFieldRe.MatchString(%q) = %v, want %v", tc.field, got, tc.want)
		}
	}
}

func TestJSONObjectKeys(t *testing.T) {
	body := `{"id":"1","name":"test","secret_token":"abc"}`
	keys := jsonObjectKeys([]byte(body))
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
	_ = json.RawMessage{} // keep import
}
