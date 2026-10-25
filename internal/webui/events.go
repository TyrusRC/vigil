package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/TyrusRC/vigil/internal/core"
)

// Event types sent over SSE.
const (
	EventFinding  = "finding"
	EventProgress = "progress"
	EventPhase    = "phase"
	EventComplete = "complete"
)

// ScanEvent is a single SSE event.
type ScanEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// ProgressData carries scan progress.
type ProgressData struct {
	Tested   int    `json:"tested"`
	Total    int    `json:"total"`
	Findings int    `json:"findings"`
	Phase    string `json:"phase"`
	Elapsed  string `json:"elapsed"`
}

// EventBus fans out scan events to all connected SSE clients.
type EventBus struct {
	mu      sync.RWMutex
	clients map[chan ScanEvent]struct{}
}

// NewEventBus creates a new event bus.
func NewEventBus() *EventBus {
	return &EventBus{
		clients: make(map[chan ScanEvent]struct{}),
	}
}

// Subscribe adds a client channel. Returns an unsubscribe function.
func (b *EventBus) Subscribe() (<-chan ScanEvent, func()) {
	ch := make(chan ScanEvent, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
		// drain to prevent goroutine leak
		go func() { for range ch {} }()
		close(ch)
	}
}

// Publish sends an event to all clients. Non-blocking: slow clients drop events.
func (b *EventBus) Publish(ev ScanEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

// PublishFinding sends a finding event.
func (b *EventBus) PublishFinding(f *core.Finding) {
	b.Publish(ScanEvent{Type: EventFinding, Data: f})
}

// PublishProgress sends a progress update.
func (b *EventBus) PublishProgress(p ProgressData) {
	b.Publish(ScanEvent{Type: EventProgress, Data: p})
}

// PublishPhase sends a phase change.
func (b *EventBus) PublishPhase(phase string) {
	b.Publish(ScanEvent{Type: EventPhase, Data: map[string]string{"phase": phase}})
}

// PublishComplete signals scan completion.
func (b *EventBus) PublishComplete(summary map[string]interface{}) {
	b.Publish(ScanEvent{Type: EventComplete, Data: summary})
}

// SSEHandler returns an http.HandlerFunc that streams events to the client.
func (b *EventBus) SSEHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		events, unsub := b.Subscribe()
		defer unsub()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				data, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
				flusher.Flush()
			}
		}
	}
}
