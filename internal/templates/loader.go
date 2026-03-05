package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load walks dir recursively, parses every .yaml / .yml file as a Template,
// compiles regex fields, and returns the full slice.
// Files that fail to parse are returned as an error immediately.
func Load(dir string) ([]Template, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("template directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("template path %q is not a directory", dir)
	}

	var templates []Template

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		t, err := parseFile(path)
		if err != nil {
			return fmt.Errorf("template %s: %w", path, err)
		}
		templates = append(templates, t)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("loading templates from %q: %w", dir, err)
	}

	return templates, nil
}

// parseFile reads and validates a single YAML template file.
func parseFile(path string) (Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Template{}, fmt.Errorf("reading: %w", err)
	}

	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Template{}, fmt.Errorf("parsing YAML: %w", err)
	}

	if err := validate(&t, path); err != nil {
		return Template{}, err
	}

	// Compile regexes and apply defaults at load time (not at match time).
	for i := range t.Matchers {
		m := &t.Matchers[i]

		if m.Regex != "" {
			re, err := regexp.Compile(m.Regex)
			if err != nil {
				return Template{}, fmt.Errorf("matcher regex in %q: %w", t.ID, err)
			}
			m.SetCompiledRegex(re)
		}

		if m.Condition == "" {
			m.Condition = "or"
		}
	}

	if t.MatchersCondition == "" {
		t.MatchersCondition = "and"
	}

	return t, nil
}

// validate checks required fields and basic consistency.
func validate(t *Template, path string) error {
	if t.ID == "" {
		return fmt.Errorf("missing required field 'id' in %s", path)
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template %q: missing required field 'info.name'", t.ID)
	}
	if t.Info.RiskScore == 0 {
		return fmt.Errorf("template %q: info.risk-score must be > 0", t.ID)
	}
	if len(t.Matchers) == 0 {
		return fmt.Errorf("template %q: must have at least one matcher", t.ID)
	}
	for i, m := range t.Matchers {
		if m.Type == "" {
			return fmt.Errorf("template %q: matcher[%d] missing required field 'type'", t.ID, i)
		}
	}
	return nil
}
