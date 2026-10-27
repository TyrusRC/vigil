package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// writeJSONFile atomically writes v as indented JSON to path (0600) via a
// temp file + rename, creating parent dirs as needed. A path of "" is a no-op
// so a store can run purely in-memory.
func writeJSONFile(path string, v any) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readJSONFile loads path into v. A missing or empty file is not an error so a
// store starts clean on first run.
func readJSONFile(path string, v any) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}
