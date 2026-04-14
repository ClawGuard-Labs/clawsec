//go:build linux

// engine.go — pure template-evaluation logic.
//
// Evaluate() is the only exported function. It takes a compiled Template and
// an (event, session) pair, runs every matcher, combines results with the
// template's matchers-condition ("and" / "or"), and returns whether the
// template fired.
//
// No state is mutated here — callers (detector.go) handle tagging and scoring.
package detector

import (
	"strconv"
	"strings"
	"time"

	"github.com/ClawGuard-Labs/akmon/internal/constants"
	"github.com/ClawGuard-Labs/akmon/internal/consumer"
	"github.com/ClawGuard-Labs/akmon/internal/correlator"
	tmpl "github.com/ClawGuard-Labs/akmon/internal/templates"
)

// Evaluate returns true if all (or any, depending on matchers-condition)
// matchers in t fire against the given event and session.
func Evaluate(t *tmpl.Template, ev *consumer.EnrichedEvent, sess *correlator.Session) bool {
	if len(t.Matchers) == 0 {
		return false
	}

	useOR := strings.EqualFold(t.MatchersCondition, "or")

	for i := range t.Matchers {
		result := evalMatcher(&t.Matchers[i], ev, sess)
		if useOR {
			if result {
				return true // any matcher suffices
			}
		} else {
			if !result {
				return false // all matchers required; short-circuit on first failure
			}
		}
	}

	if useOR {
		return false // no matcher fired
	}
	return true // all matchers passed
}

// ── Dispatcher ────────────────────────────────────────────────────────────

func evalMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent, sess *correlator.Session) bool {
	var result bool
	switch strings.ToLower(m.Type) {
	case "event-type":
		result = evalEventTypeMatcher(m, ev)
	case "process":
		result = evalProcessMatcher(m, ev)
	case "filepath":
		result = evalFilepathMatcher(m, ev)
	case "file":
		result = evalFileMatcher(m, ev)
	case "network":
		result = evalNetworkMatcher(m, ev)
	case "risk-flag":
		result = evalRiskFlagMatcher(m, ev)
	case "session":
		result = evalSessionMatcher(m, ev, sess)
	case "tls-payload":
		result = evalTLSPayloadMatcher(m, ev)
	default:
		return false
	}

	if m.Negate {
		return !result
	}
	return result
}

// ── event-type ────────────────────────────────────────────────────────────

// evalEventTypeMatcher checks ev.EventType against the values list (OR).
func evalEventTypeMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	return matchAnyExact(ev.EventType, m.Values)
}

// ── process ───────────────────────────────────────────────────────────────

// evalProcessMatcher inspects process-level fields.
//
// Supported Field values:
//
//	comm         – ev.Comm (lowercased comparison)
//	binary       – ev.Binary (full path)
//	cmdline      – ev.Cmdline (full command line string)
//	is_ai_process – ev.IsAIProcess boolean
func evalProcessMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	switch strings.ToLower(m.Field) {
	case "comm":
		return matchField(strings.ToLower(ev.Comm), m)
	case "binary":
		return matchField(ev.Binary, m)
	case "cmdline":
		return matchField(ev.Cmdline, m)
	case "is_ai_process":
		if b, ok := m.Equals.(bool); ok {
			return ev.IsAIProcess == b
		}
		return ev.IsAIProcess
	}
	return false
}

// ── filepath ──────────────────────────────────────────────────────────────

// evalFilepathMatcher checks ev.FilePath.
// All configured checks (extensions, words, values, regex) must pass (AND).
// Returns false if no checks are configured.
func evalFilepathMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	hasCheck := false
	path := ev.FilePath

	if len(m.Extensions) > 0 {
		hasCheck = true
		if !matchAnyExact(constants.FileExt(path), m.Extensions) {
			return false
		}
	}

	if len(m.Words) > 0 {
		hasCheck = true
		if !matchWords(path, m.Words, m.Condition) {
			return false
		}
	}

	if len(m.Values) > 0 {
		hasCheck = true
		if !matchAnyExact(path, m.Values) {
			return false
		}
	}

	if re := m.CompiledRegex(); re != nil {
		hasCheck = true
		if !re.MatchString(path) {
			return false
		}
	}

	return hasCheck // false if no checks configured
}

// evalFileMatcher checks file syscall metadata (flags, sizes).
//
// Supported Field values:
//
//	is_write_open – O_WRONLY, O_RDWR, or O_CREAT set on open flags (file_open / file_rw)
func evalFileMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	switch strings.ToLower(m.Field) {
	case "is_write_open", "write_open":
		if ev.EventType != "file_open" && ev.EventType != "file_rw" {
			return false
		}
		w := constants.IsWriteOpen(ev.FileFlags)
		if b, ok := m.Equals.(bool); ok {
			return w == b
		}
		return w
	}
	return false
}

// ── network ───────────────────────────────────────────────────────────────

// evalNetworkMatcher inspects ev.Network fields.
//
// Supported Field values:
//
//	dst_port    – ev.Network.DstPort  (values for exact, lt/gt for numeric range)
//	dst_ip      – ev.Network.DstIP    (words / values / regex)
//	http_method – ev.Network.HTTPMethod (values, case-insensitive)
//	protocol    – ev.Network.Protocol   (values, case-insensitive)
func evalNetworkMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	if ev.Network == nil {
		return false
	}
	net := ev.Network

	switch strings.ToLower(m.Field) {
	case "dst_port":
		if len(m.Values) > 0 {
			return matchAnyExact(strconv.Itoa(int(net.DstPort)), m.Values)
		}
		return matchNumeric(float64(net.DstPort), m)

	case "dst_ip":
		return matchField(net.DstIP, m)

	case "http_method":
		return matchAnyExact(
			strings.ToUpper(net.HTTPMethod),
			mapStrings(m.Values, strings.ToUpper),
		)

	case "protocol":
		return matchAnyExact(
			strings.ToLower(net.Protocol),
			mapStrings(m.Values, strings.ToLower),
		)
	}
	return false
}

// ── risk-flag ─────────────────────────────────────────────────────────────

// evalRiskFlagMatcher checks ev.RiskFlags bitmask.
// All listed flags must be set (AND semantics between flags).
func evalRiskFlagMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	if len(m.Flags) == 0 {
		return false
	}
	for _, flag := range m.Flags {
		bit := riskFlagBit(flag)
		if bit == 0 || ev.RiskFlags&bit == 0 {
			return false
		}
	}
	return true
}

// ── session ───────────────────────────────────────────────────────────────

// evalSessionMatcher checks cross-event session state.
//
// Supported Field values:
//
//	exec_after_net              – sess.ExecAfterNet (bool, use equals:)
//	has_ai_process              – any event in session has IsAIProcess=true (bool)
//	duration_minutes            – time since session created (gt:/lt:)
//	last_net_age_seconds        – seconds since last net_connect (gt:/lt:)
//	has_tag                     – tag exists in session (contains: or values:)
//	has_exec_comm               – any exec in session has comm in values list
//	exec_binary_match_filepath  – any exec binary == current ev.FilePath (equals: true)
//	exec_binary_match_filepath_same_pid – same PID exec binary == ev.FilePath (equals: true)
//	other_file_rw               – session has file_rw with different path (equals: true)
func evalSessionMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent, sess *correlator.Session) bool {
	if sess == nil {
		return false
	}

	sess.RLock()
	defer sess.RUnlock()

	switch strings.ToLower(m.Field) {
	case "exec_after_net":
		result := sess.ExecAfterNet
		if b, ok := m.Equals.(bool); ok {
			return result == b
		}
		return result

	case "has_ai_process":
		result := sessionHasAIProcess(sess)
		if b, ok := m.Equals.(bool); ok {
			return result == b
		}
		return result

	case "duration_minutes":
		return matchNumeric(time.Since(sess.CreatedAt).Minutes(), m)

	case "last_net_age_seconds":
		if sess.LastNetTime.IsZero() {
			return false
		}
		return matchNumeric(time.Since(sess.LastNetTime).Seconds(), m)

	case "has_tag":
		// contains: checks a single tag name; values: checks any of a list.
		if m.Contains != "" {
			_, ok := sess.Tags[m.Contains]
			return ok
		}
		for _, v := range m.Values {
			if _, ok := sess.Tags[v]; ok {
				return true
			}
		}
		return false

	case "has_exec_comm":
		// True if any exec event in session history has comm in m.Values.
		lv := mapStrings(m.Values, strings.ToLower)
		for _, sev := range sess.Events {
			if sev.EventType == "exec" {
				if matchAnyExact(strings.ToLower(sev.Comm), lv) {
					return true
				}
			}
		}
		return false

	case "exec_binary_match_filepath":
		// True if any exec event binary in this session matches the current filepath.
		found := false
		for _, sev := range sess.Events {
			if sev.EventType == "exec" && sev.Binary == ev.FilePath {
				found = true
				break
			}
		}
		if b, ok := m.Equals.(bool); ok {
			return found == b
		}
		return found

	case "exec_binary_match_filepath_same_pid":
		if ev.FilePath == "" {
			return false
		}
		found := false
		for _, sev := range sess.Events {
			if sev.EventType == "exec" && sev.Pid == ev.Pid && sev.Binary == ev.FilePath {
				found = true
				break
			}
		}
		if b, ok := m.Equals.(bool); ok {
			return found == b
		}
		return found

	case "other_file_rw":
		// True if session has a file_rw event with a different (non-empty) filepath.
		if ev.FilePath == "" {
			return false
		}
		found := false
		for _, sev := range sess.Events {
			if sev.EventType == "file_rw" && sev.FilePath != "" && sev.FilePath != ev.FilePath {
				found = true
				break
			}
		}
		if b, ok := m.Equals.(bool); ok {
			return found == b
		}
		return found
	}

	return false
}

// ── tls-payload ───────────────────────────────────────────────────────────

// evalTLSPayloadMatcher checks ev.TLSPayload content.
func evalTLSPayloadMatcher(m *tmpl.Matcher, ev *consumer.EnrichedEvent) bool {
	if ev.TLSPayload == "" {
		return false
	}
	hasCheck := false

	if len(m.Words) > 0 {
		hasCheck = true
		if !matchWords(ev.TLSPayload, m.Words, m.Condition) {
			return false
		}
	}
	if re := m.CompiledRegex(); re != nil {
		hasCheck = true
		if !re.MatchString(ev.TLSPayload) {
			return false
		}
	}

	return hasCheck
}

// ── Shared helpers ────────────────────────────────────────────────────────

// matchField applies values (exact), words (substring), and regex checks to target.
// All configured checks must pass (AND semantics between check types).
// Returns false if no checks are configured.
func matchField(target string, m *tmpl.Matcher) bool {
	hasCheck := false

	if len(m.Values) > 0 {
		hasCheck = true
		if !matchAnyExact(target, m.Values) {
			return false
		}
	}
	if len(m.Words) > 0 {
		hasCheck = true
		if !matchWords(target, m.Words, m.Condition) {
			return false
		}
	}
	if re := m.CompiledRegex(); re != nil {
		hasCheck = true
		if !re.MatchString(target) {
			return false
		}
	}

	return hasCheck
}

// matchAnyExact returns true if s equals any element of vals (case-sensitive).
func matchAnyExact(s string, vals []string) bool {
	for _, v := range vals {
		if s == v {
			return true
		}
	}
	return false
}

// matchWords checks substring conditions against target (case-insensitive).
// condition "and": all words must be substrings of target.
// condition "or" (default): any word suffices.
func matchWords(target string, words []string, condition string) bool {
	if len(words) == 0 {
		return false
	}
	lower := strings.ToLower(target)
	if strings.EqualFold(condition, "and") {
		for _, w := range words {
			if !strings.Contains(lower, strings.ToLower(w)) {
				return false
			}
		}
		return true
	}
	// OR (default)
	for _, w := range words {
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// matchNumeric applies lt / gt comparators to val.
// Returns false if neither comparator is set.
func matchNumeric(val float64, m *tmpl.Matcher) bool {
	if m.Lt == nil && m.Gt == nil {
		return false
	}
	if m.Lt != nil && !(val < *m.Lt) {
		return false
	}
	if m.Gt != nil && !(val > *m.Gt) {
		return false
	}
	return true
}

// riskFlagBit maps a flag name to its bitmask constant.
func riskFlagBit(name string) uint32 {
	switch strings.ToLower(name) {
	case "sensitive":
		return consumer.RFlagSensitive
	case "large_mmap":
		return consumer.RFlagLargeMmap
	case "http":
		return consumer.RFlagHTTP
	}
	return 0
}

// sessionHasAIProcess reports whether any event in the session is AI-related.
// Must be called with the session read lock held.
func sessionHasAIProcess(sess *correlator.Session) bool {
	for _, ev := range sess.Events {
		if ev.IsAIProcess {
			return true
		}
	}
	return false
}

// mapStrings applies fn to every element of vals and returns the results.
func mapStrings(vals []string, fn func(string) string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = fn(v)
	}
	return out
}
