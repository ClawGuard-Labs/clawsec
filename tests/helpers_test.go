package tests

import (
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/onyx/internal/consumer"
	"github.com/onyx/internal/correlator"
	"github.com/onyx/internal/templates"
)

// Sibling of the onyx repo: ../onyx-templates from repo root; tests/ is one level deeper.
const templatesDir = "../../onyx-templates/behavioral-templates"

var (
	allTemplates []templates.Template

	loggersMu sync.Mutex
	logFiles  []*os.File
	loggers   = map[string]*log.Logger{}
)

func TestMain(m *testing.M) {
	if err := os.MkdirAll("logs", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot create logs dir: %v\n", err)
		os.Exit(1)
	}

	var err error
	allTemplates, err = templates.Load(templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load templates from %s: %v\n", templatesDir, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded %d templates from %s\n", len(allTemplates), templatesDir)

	code := m.Run()

	loggersMu.Lock()
	for _, f := range logFiles {
		f.Close()
	}
	loggersMu.Unlock()

	os.Exit(code)
}

// categoryLogger returns a *log.Logger that writes to logs/<name>.log.
// Created lazily on first call per category.
func categoryLogger(name string) *log.Logger {
	loggersMu.Lock()
	defer loggersMu.Unlock()

	if l, ok := loggers[name]; ok {
		return l
	}

	f, err := os.OpenFile(
		fmt.Sprintf("logs/%s.log", name),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0o644,
	)
	if err != nil {
		panic(fmt.Sprintf("cannot create log file for %q: %v", name, err))
	}
	logFiles = append(logFiles, f)

	l := log.New(f, fmt.Sprintf("[%s] ", name), log.Ltime)
	loggers[name] = l
	return l
}

// findTemplate looks up a loaded template by ID.
func findTemplate(t *testing.T, id string) *templates.Template {
	t.Helper()
	for i := range allTemplates {
		if allTemplates[i].ID == id {
			return &allTemplates[i]
		}
	}
	t.Fatalf("template %q not found among %d loaded templates", id, len(allTemplates))
	return nil
}

// ── Event builders ───────────────────────────────────────────────────────────

func newFileEvent(eventType, filePath, comm string) *consumer.EnrichedEvent {
	return &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Pid:       1000,
		Ppid:      999,
		Uid:       1000,
		Comm:      comm,
		FilePath:  filePath,
		Tags:      []string{},
	}
}

func newFileEventWithFlags(eventType, filePath, comm string, riskFlags uint32) *consumer.EnrichedEvent {
	ev := newFileEvent(eventType, filePath, comm)
	ev.RiskFlags = riskFlags
	return ev
}

func newNetEvent(eventType, dstIP string, dstPort uint16, protocol, httpMethod string) *consumer.EnrichedEvent {
	return &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Pid:       1000,
		Ppid:      999,
		Uid:       1000,
		Comm:      "curl",
		Network: &consumer.NetworkInfo{
			DstIP:      dstIP,
			DstPort:    dstPort,
			Protocol:   protocol,
			HTTPMethod: httpMethod,
		},
		Tags: []string{},
	}
}

func newExecEvent(comm, binary, cmdline string, isAI bool) *consumer.EnrichedEvent {
	return &consumer.EnrichedEvent{
		Timestamp:   time.Now(),
		EventType:   "exec",
		Pid:         1000,
		Ppid:        999,
		Uid:         1000,
		Comm:        comm,
		Binary:      binary,
		Cmdline:     cmdline,
		IsAIProcess: isAI,
		Tags:        []string{},
	}
}

// ── Session builder ──────────────────────────────────────────────────────────

func newSession(events []*consumer.EnrichedEvent, tags map[string]struct{}) *correlator.Session {
	now := time.Now()
	if tags == nil {
		tags = map[string]struct{}{}
	}
	return &correlator.Session{
		ID:        "sess_test0001",
		RootPID:   1000,
		PIDs:      map[uint32]struct{}{1000: {}},
		Events:    events,
		CreatedAt: now,
		LastSeen:  now,
		Tags:      tags,
	}
}
