//go:build linux

// Package nucleiscanner integrates the Nuclei v3 engine to actively probe
// AI/ML services detected by the eBPF monitor.
//
// Trigger: when the eBPF monitor sees a net_connect event to a localhost
// address on a known AI service port (Qdrant :6333, Ollama :11434, etc.),
// this scanner fires an active Nuclei scan against that target.
//
// Both detectors run simultaneously on the trigger event:
//   - Our YAML behavioral detector (always runs on all events)
//   - This Nuclei scanner (runs async when a local AI service is detected)
//
// Findings are emitted as synthetic EnrichedEvents with EventType="nuclei_finding"
// and written to the same JSON output stream.
//
// Deduplication: each unique "ip:port" target is scanned at most once per
// scanTTL (default 10 minutes) to avoid hammering local services.
package nucleiscanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.uber.org/zap"

	"github.com/ClawGuard-Labs/akmon/internal/aiprofile"
	"github.com/ClawGuard-Labs/akmon/internal/constants"
	"github.com/ClawGuard-Labs/akmon/internal/consumer"
	outpkg "github.com/ClawGuard-Labs/akmon/internal/output"
)

const (
	// discoveryInterval is how often the background probe checks known AI ports.
	discoveryInterval = 30 * time.Second
	// discoveryDialTimeout is the TCP dial timeout used during port probing.
	discoveryDialTimeout = 500 * time.Millisecond
)

// scanMeta correlates an active scan back to the session that triggered it.
type scanMeta struct {
	sessionID string
	service   string
	pid       uint32
	ppid      uint32
	comm      string
}

// Scanner wraps a ThreadSafeNucleiEngine and manages async AI-service scanning.
type Scanner struct {
	engine       *nuclei.ThreadSafeNucleiEngine
	templatesDir string
	logger       *zap.Logger
	writer       outpkg.EventWriter // main output (all events)
	rulesWriter  outpkg.EventWriter // rules output (only matched events); may be nil

	// dedup: scan each target at most once per scanTTL
	scanned sync.Map // key: "http://host:port" → time.Time
	scanTTL time.Duration

	// pending maps "http://host:port" → scanMeta for result correlation
	mu      sync.RWMutex
	pending map[string]*scanMeta
	cfg     *aiprofile.Profile
}

// SetRulesWriter registers an additional writer that receives every Nuclei
// finding. Intended for the rules-only output file. Must be called before
// any scans are triggered (not concurrency-safe after startup).
func (s *Scanner) SetRulesWriter(w outpkg.EventWriter) {
	s.rulesWriter = w
}

// New initialises the Nuclei engine and returns a ready Scanner.
// templatesDir must point to the nuclei-templates/ directory.
// writer is the shared event output writer.
func New(ctx context.Context, templatesDir string, writer outpkg.EventWriter, logger *zap.Logger, cfg *aiprofile.Profile) (*Scanner, error) {
	// Validate the templates directory before touching the engine.
	// nuclei.NewThreadSafeNucleiEngine() will auto-download community templates
	// when no local templates are found, which is undesirable here.
	if _, err := os.Stat(templatesDir); err != nil {
		return nil, fmt.Errorf("nuclei templates directory %q not found\n"+
			"  Add templates to that path or disable active scanning with: --no-nuclei\n"+
			"  Original error: %w", templatesDir, err)
	}
	if !dirHasYAML(templatesDir) {
		return nil, fmt.Errorf("nuclei templates directory %q contains no .yaml files\n"+
			"  Add templates to that path or disable active scanning with: --no-nuclei", templatesDir)
	}

	s := &Scanner{
		templatesDir: templatesDir,
		logger:       logger,
		writer:       writer,
		scanTTL:      10 * time.Minute,
		pending:      make(map[string]*scanMeta),
		cfg:          cfg,
	}

	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("nuclei engine init: %w", err)
	}

	// Register the global result callback — receives findings from all scans.
	engine.GlobalResultCallback(func(event *output.ResultEvent) {
		s.handleResult(ctx, event)
	})

	s.engine = engine
	logger.Info("nuclei engine ready",
		zap.String("templates_dir", templatesDir),
	)

	// Background goroutine: actively probe known AI ports on localhost.
	// This detects services that are already running (e.g. a Docker container
	// that started before the monitor) without waiting for a client connection.
	go s.periodicDiscover(ctx)

	return s, nil
}

// MaybeScan checks whether ev should trigger a Nuclei scan and if so,
// enqueues an async scan. Safe to call from the main event loop on every event.
//
// Triggers when:
//  1. EventType == "net_connect"
//  2. DstIP is loopback (127.x.x.x / ::1)
//  3. DstPort is a known AI service port
//  4. The same target has not been scanned within scanTTL
func (s *Scanner) MaybeScan(ctx context.Context, ev *consumer.EnrichedEvent) {
	if ev.EventType != "net_connect" || ev.Network == nil {
		return
	}
	if !constants.IsLocalhost(ev.Network.DstIP) {
		return
	}
	svcName, ok := s.cfg.ServiceNameForPort(ev.Network.DstPort)
	if !ok {
		return
	}

	target := fmt.Sprintf("http://%s:%d", ev.Network.DstIP, ev.Network.DstPort)
	s.triggerScan(ctx, target, svcName, &scanMeta{
		sessionID: ev.AISessionID,
		service:   svcName,
		pid:       ev.Pid,
		ppid:      ev.Ppid,
		comm:      ev.Comm,
	})
}

// periodicDiscover probes known AI service ports on localhost on a timer.
// It detects services that started before the monitor, or that no eBPF
// net_connect event was observed for (e.g. a Docker-forwarded port).
// An initial probe fires 5 s after startup; subsequent probes every 30 s.
func (s *Scanner) periodicDiscover(ctx context.Context) {
	initial := time.NewTimer(5 * time.Second)
	defer initial.Stop()
	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-initial.C:
			s.discoverServices(ctx)
		case <-ticker.C:
			s.discoverServices(ctx)
		}
	}
}

// discoverServices TCP-dials each known AI service port on 127.0.0.1.
// Open ports are passed to triggerScan (dedup prevents re-scanning within TTL).
func (s *Scanner) discoverServices(ctx context.Context) {
	for port, svcName := range s.cfg.ServicePorts() {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, discoveryDialTimeout)
		if err != nil {
			continue // port not open
		}
		conn.Close()

		target := fmt.Sprintf("http://127.0.0.1:%d", port)
		s.logger.Info("nuclei: discovered local AI service",
			zap.String("service", svcName),
			zap.String("target", target),
		)
		s.triggerScan(ctx, target, svcName, &scanMeta{
			service:   svcName,
			sessionID: "auto-discovery",
		})
	}
}

// triggerScan deduplicates and enqueues an async Nuclei scan for target.
// meta is stored in the pending map so handleResult can correlate findings
// back to a session. Safe to call from any goroutine.
func (s *Scanner) triggerScan(ctx context.Context, target, svcName string, meta *scanMeta) {
	// Dedup: skip if this target was scanned within scanTTL.
	now := time.Now()
	if prev, loaded := s.scanned.LoadOrStore(target, now); loaded {
		if now.Sub(prev.(time.Time)) < s.scanTTL {
			s.logger.Debug("nuclei: skipping recently scanned target",
				zap.String("target", target),
			)
			return
		}
		s.scanned.Store(target, now) // refresh TTL
	}

	s.mu.Lock()
	s.pending[target] = meta
	s.mu.Unlock()

	s.logger.Info("nuclei: scan triggered",
		zap.String("target", target),
		zap.String("service", svcName),
		zap.String("session", meta.sessionID),
	)

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.pending, target)
			s.mu.Unlock()
		}()

		err := s.engine.ExecuteNucleiWithOpts(
			[]string{target},
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
				Templates: []string{s.templatesDir},
			}),
		)
		if err != nil && err != nuclei.ErrNoTemplatesAvailable && err != nuclei.ErrNoTargetsAvailable {
			s.logger.Warn("nuclei scan error",
				zap.String("target", target),
				zap.Error(err),
			)
		} else {
			s.logger.Info("nuclei: scan complete", zap.String("target", target))
		}
	}()
}

// handleResult converts a nuclei ResultEvent into an EnrichedEvent and
// emits it to the output writer. Called from the global result callback.
func (s *Scanner) handleResult(ctx context.Context, event *output.ResultEvent) {
	// Resolve session metadata from the pending map using the target host.
	s.mu.RLock()
	meta, ok := s.pending[event.Host]
	s.mu.RUnlock()

	var sessionID, service, comm string
	var pid, ppid uint32
	if ok {
		sessionID = meta.sessionID
		service = meta.service
		pid = meta.pid
		ppid = meta.ppid
		comm = meta.comm
	}

	severity := event.Info.SeverityHolder.Severity.String()

	// Convert tags StringSlice → []string
	tags := strings.Split(event.Info.Tags.String(), ",")
	cleaned := tags[:0]
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}

	finding := &consumer.NucleiResult{
		TemplateID:  event.TemplateID,
		Name:        event.Info.Name,
		Severity:    severity,
		Description: event.Info.Description,
		MatchedURL:  event.Matched,
		Service:     service,
		Tags:        cleaned,
	}

	ev := &consumer.EnrichedEvent{
		Timestamp:    time.Now(),
		EventType:    "nuclei_finding",
		Pid:          pid,
		Ppid:         ppid,
		Comm:         comm,
		AISessionID:  sessionID,
		RiskScore:    constants.SeverityScore(severity),
		Tags:         []string{"nuclei_finding", event.TemplateID},
		NucleiResult: finding,
	}

	s.logger.Info("nuclei finding",
		zap.String("template_id", event.TemplateID),
		zap.String("name", event.Info.Name),
		zap.String("severity", severity),
		zap.String("matched", event.Matched),
		zap.String("session", sessionID),
	)

	s.writer.Write(ctx, ev)

	// Nuclei findings always match by definition — mirror to rules file.
	if s.rulesWriter != nil {
		s.rulesWriter.Write(ctx, ev)
	}
}

// Close shuts down the nuclei engine and releases resources.
func (s *Scanner) Close() {
	if s.engine != nil {
		s.engine.Close()
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// dirHasYAML reports whether dir (recursively) contains at least one .yaml/.yml file.
// Used to detect an empty or missing template directory before engine init.
func dirHasYAML(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			if dirHasYAML(filepath.Join(dir, e.Name())) {
				return true
			}
		} else {
			name := strings.ToLower(e.Name())
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				return true
			}
		}
	}
	return false
}
