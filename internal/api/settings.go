package api

import "sync"

// SettingsStore holds the default ScanConfig applied to new scans whose request
// omits a config. It persists to a JSON file when path is set.
type SettingsStore struct {
	mu       sync.RWMutex
	defaults ScanConfig
	path     string
}

// NewSettingsStore returns a settings store. path "" means in-memory only.
func NewSettingsStore(path string) (*SettingsStore, error) {
	ss := &SettingsStore{path: path}
	if err := readJSONFile(path, &ss.defaults); err != nil {
		return nil, err
	}
	return ss, nil
}

// Get returns the stored default scan config.
func (ss *SettingsStore) Get() ScanConfig {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.defaults
}

// Put replaces the default scan config after validating it builds.
func (ss *SettingsStore) Put(cfg ScanConfig) error {
	if _, _, err := cfg.Build(); err != nil {
		return err
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.defaults = cfg
	return writeJSONFile(ss.path, ss.defaults)
}
