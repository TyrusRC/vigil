package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TyrusRC/vigil/internal/tools"
)

func TestWriteToolLog_WritesRawOutputPerTool(t *testing.T) {
	dir := t.TempDir()

	res := tools.NewToolResult("sqlmap")
	res.RawOutput = "sqlmap identified the following injection point"
	writeToolLog(dir, "sqlmap", res)

	data, err := os.ReadFile(filepath.Join(dir, "sqlmap.log"))
	if err != nil {
		t.Fatalf("expected sqlmap.log to be written: %v", err)
	}
	if !strings.Contains(string(data), "injection point") {
		t.Fatalf("log missing raw output, got: %q", data)
	}
}

func TestWriteToolLog_AppendsMultipleRuns(t *testing.T) {
	dir := t.TempDir()

	first := tools.NewToolResult("nuclei")
	first.RawOutput = "run-one-output"
	writeToolLog(dir, "nuclei", first)

	second := tools.NewToolResult("nuclei")
	second.RawOutput = "run-two-output"
	writeToolLog(dir, "nuclei", second)

	data, err := os.ReadFile(filepath.Join(dir, "nuclei.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "run-one-output") || !strings.Contains(s, "run-two-output") {
		t.Fatalf("expected both runs appended, got: %q", s)
	}
}

func TestWriteToolLog_NoOutputNoFile(t *testing.T) {
	dir := t.TempDir()

	res := tools.NewToolResult("nikto")
	res.RawOutput = ""
	writeToolLog(dir, "nikto", res)

	if _, err := os.Stat(filepath.Join(dir, "nikto.log")); !os.IsNotExist(err) {
		t.Fatalf("expected no log file for empty output, err=%v", err)
	}
}

func TestWriteToolLog_EmptyDirNoop(t *testing.T) {
	res := tools.NewToolResult("nikto")
	res.RawOutput = "something"
	// Must not panic or error when no output dir is configured.
	writeToolLog("", "nikto", res)
}
