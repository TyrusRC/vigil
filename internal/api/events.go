package api

import (
	"encoding/json"
	"sync"

	"github.com/TyrusRC/vigil/internal/core"
)

// EventType identifies the kind of scan event.
type EventType string

const (
	EventFinding  EventType = "finding"
	EventProgressType EventType = "progress"
	EventPhase    EventType = "phase"
	EventComplete EventType = "complete"
	EventError    EventType = "error"
)

// ScanEvent is one event emitted during a scan.
type ScanEvent struct {
	Type    EventType    `json:"type"`
	ScanID  string       `json:"scan_id"`
	Finding *core.Finding `json:"finding,omitempty"`
	Phase   string       `json:"phase,omitempty"`
	Progress *EventProgress `json:"progress,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// EventProgress carries live scan metrics.
type EventProgress struct {
	Tested   int `json:"tested"`
	Total    int `json:"total"`
	Findings int `json:"findings"`
	Percent  int `json:"percent"`
}

// JSON returns the event as a JSON string (for SSE data field).
func (e ScanEvent) JSON() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// ScanEventBus is a pub/sub bus for scan events. The scan pipeline publishes
// events; SSE clients subscribe and receive them in real time.
type ScanEventBus struct {
	mu   sync.RWMutex
	subs map[string][]chan ScanEvent // scanID → subscriber channels
}

// NewScanEventBus creates a new event bus.
func NewScanEventBus() *ScanEventBus {
	return &ScanEventBus{subs: make(map[string][]chan ScanEvent)}
}

// Subscribe returns a channel that receives events for the given scan ID.
// Call Unsubscribe when done to prevent leaks.
func (b *ScanEventBus) Subscribe(scanID string) chan ScanEvent {
	ch := make(chan ScanEvent, 64)
	b.mu.Lock()
	b.subs[scanID] = append(b.subs[scanID], ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (b *ScanEventBus) Unsubscribe(scanID string, ch chan ScanEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[scanID]
	for i, s := range subs {
		if s == ch {
			b.subs[scanID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Publish sends an event to all subscribers of the given scan.
// Non-blocking: if a subscriber's buffer is full, the event is dropped.
func (b *ScanEventBus) Publish(event ScanEvent) {
	b.mu.RLock()
	subs := b.subs[event.ScanID]
	b.mu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
}

// Cleanup removes all subscribers for a scan ID.
func (b *ScanEventBus) Cleanup(scanID string) {
	b.mu.Lock()
	for _, ch := range b.subs[scanID] {
		close(ch)
	}
	delete(b.subs, scanID)
	b.mu.Unlock()
}
