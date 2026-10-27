package api

import (
	"fmt"
	"net/http"
)

// handleSSE streams scan events to the client via Server-Sent Events.
// GET /api/scans/{id}/events
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, `{"error":"missing or invalid API key"}`, http.StatusUnauthorized)
		return
	}
	scanID := r.PathValue("id")
	if scanID == "" {
		http.Error(w, `{"error":"missing scan id"}`, http.StatusBadRequest)
		return
	}

	job, ok2 := s.store.Get(scanID)
	if !ok2 || job == nil {
		http.Error(w, `{"error":"scan not found"}`, http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Subscribe to events for this scan
	ch := s.events.Subscribe(scanID)
	defer s.events.Unsubscribe(scanID, ch)

	// Send initial connected event
	fmt.Fprintf(w, "event: connected\ndata: {\"scan_id\":%q,\"status\":%q}\n\n", scanID, job.Status)
	flusher.Flush()

	// If scan is already complete, send the result and close
	if job.Status == StatusCompleted || job.Status == StatusFailed || job.Status == StatusCancelled {
		fmt.Fprintf(w, "event: complete\ndata: {\"scan_id\":%q,\"status\":%q}\n\n", scanID, job.Status)
		flusher.Flush()
		return
	}

	// Stream events until scan completes or client disconnects
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, event.JSON())
			flusher.Flush()
			if event.Type == EventComplete || event.Type == EventError {
				return
			}
		}
	}
}
