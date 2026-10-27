package api

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Target is a persistent, re-scannable target (Acunetix-style). It is a thin
// convenience over scans: launching a scan from a target just creates a normal
// scan for its URL and records the resulting scan id.
type Target struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Label      string    `json:"label,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastScanID string    `json:"last_scan_id,omitempty"`
}

// TargetStore holds targets in memory and, when path is set, persists them to a
// JSON file atomically. Mirrors the Store persistence pattern.
type TargetStore struct {
	mu      sync.RWMutex
	targets map[string]*Target
	order   []string
	path    string
}

// NewTargetStore returns a target store. path "" means in-memory only.
func NewTargetStore(path string) (*TargetStore, error) {
	ts := &TargetStore{targets: map[string]*Target{}, path: path}
	var persisted struct {
		Order   []string           `json:"order"`
		Targets map[string]*Target `json:"targets"`
	}
	if err := readJSONFile(path, &persisted); err != nil {
		return nil, err
	}
	if persisted.Targets != nil {
		ts.targets = persisted.Targets
		ts.order = persisted.Order
	}
	return ts, nil
}

func (ts *TargetStore) persistLocked() {
	_ = writeJSONFile(ts.path, struct {
		Order   []string           `json:"order"`
		Targets map[string]*Target `json:"targets"`
	}{ts.order, ts.targets})
}

// List returns targets in insertion order.
func (ts *TargetStore) List() []*Target {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]*Target, 0, len(ts.order))
	for _, id := range ts.order {
		if t := ts.targets[id]; t != nil {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out
}

// Get returns one target.
func (ts *TargetStore) Get(id string) (*Target, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	t, ok := ts.targets[id]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// Create adds a target.
func (ts *TargetStore) Create(url, label string) *Target {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := &Target{ID: uuid.NewString(), URL: url, Label: label, CreatedAt: time.Now()}
	ts.targets[t.ID] = t
	ts.order = append(ts.order, t.ID)
	ts.persistLocked()
	cp := *t
	return &cp
}

// Delete removes a target; returns false if it did not exist.
func (ts *TargetStore) Delete(id string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.targets[id]; !ok {
		return false
	}
	delete(ts.targets, id)
	for i, oid := range ts.order {
		if oid == id {
			ts.order = append(ts.order[:i], ts.order[i+1:]...)
			break
		}
	}
	ts.persistLocked()
	return true
}

// SetLastScan records the most recent scan id launched for a target.
func (ts *TargetStore) SetLastScan(id, scanID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if t, ok := ts.targets[id]; ok {
		t.LastScanID = scanID
		ts.persistLocked()
	}
}
