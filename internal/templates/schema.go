// Package templates defines the YAML detection-template schema and loader.
//
// Templates follow a Nuclei-inspired design adapted for system-level events:
// each template specifies a set of matchers that are evaluated against an
// EnrichedEvent (and its Session) to decide whether the rule fires.
//
// Example template (templates/file/ssh-key-access.yaml):
//
//	id: ssh_key_access
//	info:
//	  name: SSH Key Access
//	  severity: high
//	  risk-score: 50
//	matchers:
//	  - type: event-type
//	    values: [file_open, file_rw]
//	  - type: filepath
//	    words: [/.ssh/, /id_rsa, /id_ed25519, /authorized_keys]
//	    condition: or
//	matchers-condition: and
package templates

import "regexp"

// ── Severity constants (mirrors Nuclei convention) ────────────────────────

const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Template is a single YAML detection rule.
// The template ID is used as the event tag and session tag when the rule fires.
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	// Matchers is the ordered list of conditions to evaluate.
	Matchers []Matcher `yaml:"matchers"`

	// MatchersCondition controls how matchers are combined.
	// "and" (default): all matchers must pass.
	// "or":            any matcher suffices.
	MatchersCondition string `yaml:"matchers-condition"`
}

// Info holds human-readable template metadata.
type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"` // info | low | medium | high | critical
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`

	// RiskScore is added to the event and session score when the template fires.
	RiskScore int `yaml:"risk-score"`
}

// Matcher is a single condition within a template.
//
// The Type field selects the event field group to inspect:
//
//	event-type   – ev.EventType
//	process      – ev.Comm / ev.Binary / ev.Cmdline / ev.IsAIProcess
//	filepath     – ev.FilePath
//	network      – ev.Network (DstPort, DstIP, HTTPMethod, Protocol)
//	risk-flag    – ev.RiskFlags bitmask
//	session      – session-level state (cross-event patterns)
//	tls-payload  – ev.TLSPayload
type Matcher struct {
	// Type selects the matcher implementation.
	Type string `yaml:"type"`

	// Field selects a sub-field within the type (e.g. "comm", "dst_port").
	Field string `yaml:"field"`

	// Values is a list for exact-match comparisons (OR semantics between entries).
	Values []string `yaml:"values"`

	// Words is a list for substring-match comparisons.
	// Condition controls whether all words must match ("and") or any suffices ("or").
	Words []string `yaml:"words"`

	// Extensions is a list of file extensions for filepath matchers (e.g. ".pt", ".gguf").
	Extensions []string `yaml:"extensions"`

	// Flags is a list of risk-flag names for risk-flag matchers.
	// Supported names: sensitive | large_mmap | http
	Flags []string `yaml:"flags"`

	// Regex is a single regular expression pattern (pre-compiled by the loader).
	Regex string `yaml:"regex"`

	// Equals is used for boolean or string equality checks.
	// yaml.v3 decodes "equals: true" as bool, "equals: foo" as string.
	Equals interface{} `yaml:"equals"`

	// Contains is used for single-value substring checks (e.g. session tag lookup).
	Contains string `yaml:"contains"`

	// Lt / Gt are numeric comparators (less-than / greater-than).
	Lt *float64 `yaml:"lt"`
	Gt *float64 `yaml:"gt"`

	// Condition controls how Words / Values entries are combined within this matcher.
	// "or" (default): any entry matches → matcher passes.
	// "and":          all entries must match.
	Condition string `yaml:"condition"`

	// Negate inverts the final matcher result.
	Negate bool `yaml:"negate"`

	// compiledRegex is set by the loader after YAML parsing; not part of the schema.
	compiledRegex *regexp.Regexp
}

// CompiledRegex returns the pre-compiled regex for this matcher (nil if not set).
func (m *Matcher) CompiledRegex() *regexp.Regexp { return m.compiledRegex }

// SetCompiledRegex is called by the loader to store the compiled regex.
func (m *Matcher) SetCompiledRegex(re *regexp.Regexp) { m.compiledRegex = re }
