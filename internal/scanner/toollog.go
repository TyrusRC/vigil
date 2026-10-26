package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TyrusRC/vigil/internal/tools"
)

// writeToolLog persists an external tool's raw output to <dir>/<tool>.log so
// every integrated tool's run is saved, not just the few that happen to write
// a native output file. A no-op when dir is empty or there is nothing to log.
//
// Multiple tasks can run the same tool (e.g. autonomous + focused sqlmap), so
// runs are appended with a header separator. Each run is written in a single
// O_APPEND write, which is atomic on POSIX, so concurrent writers don't
// interleave.
func writeToolLog(dir, tool string, result *tools.ToolResult) {
	if dir == "" || result == nil || result.RawOutput == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := filepath.Join(dir, tool+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	header := fmt.Sprintf("===== %s @ %s =====\n", tool, time.Now().Format(time.RFC3339))
	_, _ = f.WriteString(header + result.RawOutput + "\n")
}
