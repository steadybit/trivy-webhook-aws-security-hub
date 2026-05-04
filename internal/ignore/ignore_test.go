package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var refTime = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadIgnoreFile_MissingFileReturnsEmpty(t *testing.T) {
	cfg, err := LoadIgnoreFile(filepath.Join(t.TempDir(), "nope.yaml"), refTime)
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if cfg == nil || len(cfg.Vulnerabilities) != 0 {
		t.Errorf("want empty config, got %+v", cfg)
	}
}

func TestLoadIgnoreFile_EmptyPath(t *testing.T) {
	cfg, err := LoadIgnoreFile("", refTime)
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if cfg == nil || len(cfg.Vulnerabilities) != 0 {
		t.Errorf("want empty config, got %+v", cfg)
	}
}

func TestLoadIgnoreFile_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "bad.yaml", "vulnerabilities: [\n  - id: CVE-1\n  this is not yaml\n")
	_, err := LoadIgnoreFile(p, refTime)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse ignore file") {
		t.Errorf("error = %v, want parse-error wrapping", err)
	}
}

func TestLoadIgnoreFile_InvalidGlob(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ignore.yaml", `vulnerabilities:
  - id: CVE-2024-1
    paths:
      - "[unclosed"
`)
	_, err := LoadIgnoreFile(p, refTime)
	if err == nil {
		t.Fatal("expected pattern validation error")
	}
	if !strings.Contains(err.Error(), "invalid path pattern") {
		t.Errorf("error = %v, want invalid-pattern error", err)
	}
}

func TestLoadIgnoreFile_PrunesExpired(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ignore.yaml", `vulnerabilities:
  - id: CVE-EXPIRED
    expired_at: 2026-04-01
    statement: gone
  - id: CVE-FUTURE
    expired_at: 2027-01-01
  - id: CVE-FOREVER
`)
	cfg, err := LoadIgnoreFile(p, refTime)
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	ids := make([]string, len(cfg.Vulnerabilities))
	for i, f := range cfg.Vulnerabilities {
		ids[i] = f.ID
	}
	want := []string{"CVE-FUTURE", "CVE-FOREVER"}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] {
		t.Errorf("kept ids = %v, want %v", ids, want)
	}
}

func TestLoadIgnoreFile_ExpiryBoundaryIsExclusive(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ignore.yaml", `vulnerabilities:
  - id: CVE-EQUAL
    expired_at: 2026-05-01T00:00:00Z
`)
	cfg, err := LoadIgnoreFile(p, refTime)
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if len(cfg.Vulnerabilities) != 0 {
		t.Errorf("expected expired-at-equal-now to be pruned, got %d kept", len(cfg.Vulnerabilities))
	}
}

func TestMatchVulnerability_IDOnly(t *testing.T) {
	cfg := &IgnoreConfig{Vulnerabilities: []IgnoreFinding{{ID: "CVE-1"}, {ID: "CVE-2"}}}
	if got := cfg.MatchVulnerability("CVE-2", "", ""); got == nil || got.ID != "CVE-2" {
		t.Errorf("got %+v, want CVE-2", got)
	}
	if got := cfg.MatchVulnerability("CVE-MISSING", "", ""); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestMatchVulnerability_NilReceiver(t *testing.T) {
	var cfg *IgnoreConfig
	if got := cfg.MatchVulnerability("CVE-1", "", ""); got != nil {
		t.Errorf("nil receiver should return nil, got %+v", got)
	}
}

func TestMatchVulnerability_PathGlob(t *testing.T) {
	cfg := &IgnoreConfig{Vulnerabilities: []IgnoreFinding{{
		ID:    "CVE-1",
		Paths: []string{"**/foo", "lib/**/openssl*"},
	}}}
	cases := []struct {
		name        string
		target, pkg string
		expectMatch bool
	}{
		{"target glob hit", "bar/foo", "", true},
		{"pkgPath glob hit", "", "lib/x86_64/openssl.so.3", true},
		{"both empty", "", "", false},
		{"neither matches", "bar/baz", "etc/passwd", false},
		{"pkg matches first pattern", "", "deeply/nested/foo", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.MatchVulnerability("CVE-1", tc.target, tc.pkg)
			if (got != nil) != tc.expectMatch {
				t.Errorf("got %+v, want match=%v", got, tc.expectMatch)
			}
		})
	}
}

func TestMatchVulnerability_EmptyPathsMatchesEverything(t *testing.T) {
	cfg := &IgnoreConfig{Vulnerabilities: []IgnoreFinding{{ID: "CVE-1"}}}
	if got := cfg.MatchVulnerability("CVE-1", "", ""); got == nil {
		t.Error("rule with empty paths should match without target/pkg")
	}
}

func TestLoadIgnoreFile_StatementAndExpiryPreserved(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ignore.yaml", `vulnerabilities:
  - id: CVE-1
    statement: accepted risk per JIRA-123
    expired_at: 2027-01-01
`)
	cfg, err := LoadIgnoreFile(p, refTime)
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	if len(cfg.Vulnerabilities) != 1 {
		t.Fatalf("want 1 entry, got %d", len(cfg.Vulnerabilities))
	}
	f := cfg.Vulnerabilities[0]
	if f.Statement != "accepted risk per JIRA-123" {
		t.Errorf("Statement = %q", f.Statement)
	}
	if f.ExpiredAt.Year() != 2027 {
		t.Errorf("ExpiredAt = %v", f.ExpiredAt)
	}
}
