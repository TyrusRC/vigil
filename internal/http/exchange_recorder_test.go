package http

import "testing"

func TestExchangeRecorder_KeepsFirstAndCaps(t *testing.T) {
	r := newExchangeRecorder(2)

	// keep-first: a second record for the same URL must not overwrite.
	r.record("http://x/a", "REQ-A1", "RESP-A1")
	r.record("http://x/a", "REQ-A2", "RESP-A2")
	if req, resp, ok := r.lookup("http://x/a"); !ok || req != "REQ-A1" || resp != "RESP-A1" {
		t.Fatalf("keep-first broken: got (%q,%q,%v)", req, resp, ok)
	}

	// cap: once full (2 keys), new URLs are dropped.
	r.record("http://x/b", "REQ-B", "RESP-B") // 2nd key — fills to cap
	r.record("http://x/c", "REQ-C", "RESP-C") // over cap — dropped
	if _, _, ok := r.lookup("http://x/b"); !ok {
		t.Error("second key should be recorded")
	}
	if _, _, ok := r.lookup("http://x/c"); ok {
		t.Error("over-cap key should be dropped")
	}

	// empties and nil receiver are no-ops, never a panic.
	r.record("http://x/d", "", "")
	if _, _, ok := r.lookup("http://x/d"); ok {
		t.Error("empty exchange should not be recorded")
	}
	var nilRec *exchangeRecorder
	nilRec.record("http://x/e", "r", "s") // must not panic
	if _, _, ok := nilRec.lookup("http://x/e"); ok {
		t.Error("nil recorder lookup should be false")
	}
}
