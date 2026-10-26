package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/vigil/internal/core"
	"github.com/TyrusRC/vigil/internal/tools"
)

func readToolLog(t *testing.T, dir string) []toolRunRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, toolLogName))
	if err != nil {
		t.Fatalf("read %s: %v", toolLogName, err)
	}
	var recs []toolRunRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r toolRunRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestWriteToolLog_OneJSONLRecordPerRun(t *testing.T) {
	dir := t.TempDir()

	res := tools.NewToolResult("sqlmap")
	res.RawOutput = "sqlmap identified the following injection point"
	res.Success = true
	res.ExecutionTime = 1500 * time.Millisecond
	f := core.NewFinding("SQL Injection", core.SeverityHigh)
	f.URL = "http://t/item"
	f.Parameter = "id"
	res.AddFinding(f)

	writeToolLog(dir, "http://t/item", "sqlmap", res)

	recs := readToolLog(t, dir)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Tool != "sqlmap" || r.Target != "http://t/item" {
		t.Errorf("tool/target wrong: %+v", r)
	}
	if r.DurationMS != 1500 || !r.Success || r.Findings != 1 {
		t.Errorf("metadata wrong: %+v", r)
	}
	if !strings.Contains(r.Raw, "injection point") {
		t.Errorf("raw missing: %q", r.Raw)
	}
	if len(r.Summary) != 1 || r.Summary[0].Severity != "high" || r.Summary[0].Parameter != "id" {
		t.Errorf("finding summary wrong: %+v", r.Summary)
	}
}

func TestWriteToolLog_AppendsAcrossTools(t *testing.T) {
	dir := t.TempDir()

	a := tools.NewToolResult("nuclei")
	a.RawOutput = "run-one"
	writeToolLog(dir, "http://t", "nuclei", a)

	b := tools.NewToolResult("nikto")
	b.Errors = []string{"connect failed"}
	writeToolLog(dir, "http://t", "nikto", b)

	recs := readToolLog(t, dir)
	if len(recs) != 2 {
		t.Fatalf("want 2 records (one per tool), got %d", len(recs))
	}
	if recs[0].Tool != "nuclei" || recs[1].Tool != "nikto" {
		t.Errorf("order/tools wrong: %q, %q", recs[0].Tool, recs[1].Tool)
	}
	if len(recs[1].Errors) != 1 {
		t.Errorf("nikto error not recorded: %+v", recs[1])
	}
}

func TestWriteToolLog_SkipsEmptyRun(t *testing.T) {
	dir := t.TempDir()
	// No output, no findings, no errors → nothing worth a record.
	writeToolLog(dir, "http://t", "nikto", tools.NewToolResult("nikto"))
	if _, err := os.Stat(filepath.Join(dir, toolLogName)); !os.IsNotExist(err) {
		t.Fatalf("expected no log file for empty run, err=%v", err)
	}
}

func TestWriteToolLog_EmptyDirNoop(t *testing.T) {
	res := tools.NewToolResult("nikto")
	res.RawOutput = "x"
	writeToolLog("", "http://t", "nikto", res) // must not panic
}
