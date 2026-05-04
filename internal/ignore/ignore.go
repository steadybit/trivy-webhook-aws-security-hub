// Package ignore parses a trivy YAML ignore file and matches vulnerabilities
// against its rules. The schema mirrors the vulnerabilities-only subset of
// trivy's own .trivyignore.yaml format (see
// github.com/aquasecurity/trivy/pkg/result/ignore.go) so files written for
// trivy work here without modification. PURL-based matching, the
// misconfigurations/secrets/licenses sections, and the legacy plain-text
// .trivyignore format are intentionally not supported.
package ignore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// IgnoreFinding mirrors the vulnerability entry in a .trivyignore.yaml file.
type IgnoreFinding struct {
	ID        string    `yaml:"id"`
	Paths     []string  `yaml:"paths"`
	ExpiredAt time.Time `yaml:"expired_at"`
	Statement string    `yaml:"statement"`
}

// IgnoreConfig is the top-level structure of a parsed ignore file.
type IgnoreConfig struct {
	Vulnerabilities []IgnoreFinding `yaml:"vulnerabilities"`
}

// LoadIgnoreFile parses an ignore file and prunes any expired entries against
// the supplied clock. A missing file is not an error — it returns an empty
// config so callers can pass through cleanly when no file is configured. This
// matches trivy's own ParseIgnoreFile behavior.
func LoadIgnoreFile(path string, now time.Time) (*IgnoreConfig, error) {
	if path == "" {
		return &IgnoreConfig{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &IgnoreConfig{}, nil
		}
		return nil, fmt.Errorf("read ignore file %q: %w", path, err)
	}
	var cfg IgnoreConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse ignore file %q: %w", path, err)
	}
	for _, f := range cfg.Vulnerabilities {
		for _, p := range f.Paths {
			if !doublestar.ValidatePattern(p) {
				return nil, fmt.Errorf("invalid path pattern in ignore file, id=%s pattern=%q", f.ID, p)
			}
		}
	}
	cfg.prune(now)
	return &cfg, nil
}

// MatchVulnerability returns the first ignore rule that applies to the given
// CVE id and target/package paths, or nil if none. Path matching mirrors
// trivy's: an entry with no paths matches everything; otherwise the rule
// matches if any of its glob patterns matches either the artifact target or
// the package path.
func (c *IgnoreConfig) MatchVulnerability(vulnID, target, pkgPath string) *IgnoreFinding {
	if c == nil {
		return nil
	}
	for i := range c.Vulnerabilities {
		f := &c.Vulnerabilities[i]
		if f.ID != vulnID {
			continue
		}
		if !matchPath(f.Paths, target, pkgPath) {
			continue
		}
		return f
	}
	return nil
}

func matchPath(patterns []string, candidates ...string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if ok, _ := doublestar.Match(p, c); ok {
				return true
			}
		}
	}
	return false
}

func (c *IgnoreConfig) prune(now time.Time) {
	kept := c.Vulnerabilities[:0]
	for _, f := range c.Vulnerabilities {
		if !f.ExpiredAt.IsZero() && !f.ExpiredAt.After(now) {
			continue
		}
		kept = append(kept, f)
	}
	c.Vulnerabilities = kept
}
