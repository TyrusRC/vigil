package http

import "sync"

// exchangeRecorder keeps the real wire-format HTTP exchange (request + response
// dumps) for URLs the client fetched, so findings whose detector never attached
// an exchange of its own (security-header, cookie, CSP, exposure checks — they
// examine a response but build no proof) can still be backfilled with the
// genuine request and response instead of a synthetic stub.
//
// Semantics are keep-FIRST per URL with a hard entry cap: the first fetch of a
// URL during a scan is the baseline GET (discovery runs before payload probes),
// which is exactly the clean evidence a header/cookie finding wants. Later
// payload probes carry the payload in the query string, so they key under a
// different URL and never overwrite a baseline. The cap bounds memory on large
// scans; once full the recorder stops taking new keys (baselines, fetched
// early, are already captured) rather than evicting.
type exchangeRecorder struct {
	mu    sync.Mutex
	byURL map[string]recordedExchange
	cap   int
}

type recordedExchange struct {
	request  string
	response string
}

func newExchangeRecorder(max int) *exchangeRecorder {
	if max <= 0 {
		max = 2048
	}
	return &exchangeRecorder{byURL: make(map[string]recordedExchange), cap: max}
}

// record stores the exchange for url, keeping the first one seen and ignoring
// empties. It is safe for concurrent use by cloned clients sharing the recorder.
func (r *exchangeRecorder) record(url, request, response string) {
	if r == nil || url == "" || (request == "" && response == "") {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byURL[url]; ok {
		return
	}
	if len(r.byURL) >= r.cap {
		return
	}
	r.byURL[url] = recordedExchange{request: request, response: response}
}

// lookup returns the recorded exchange for url, if any.
func (r *exchangeRecorder) lookup(url string) (request, response string, ok bool) {
	if r == nil {
		return "", "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byURL[url]
	return e.request, e.response, ok
}
