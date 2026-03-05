// output.go — structured JSON writer, SSE broadcaster, and grouped session writer.
//
// Two output modes:
//
//  1. Flat NDJSON (default):
//     Each event is one JSON line. Suitable for log pipelines, grep, jq.
//
//  2. Grouped JSON (--grouped flag):
//     Events are buffered per session. After the session goes idle for
//     idleTimeout (default 500 ms), all buffered events are flushed as
//     a single JSON block:
//
//       {
//         "session_id":   "sess_376ecc2c",
//         "parent_pid":   65712,
//         "parent_comm":  "bash",
//         "first_seen":   "...",
//         "last_seen":    "...",
//         "duration_ms":  4,
//         "peak_risk":    30,
//         "tags":         ["sensitive_read"],
//         "event_count":  8,
//         "events": [
//           { ...exec bpftool... },
//           { ...file_open...   },
//           { ...exec grep...   },
//           ...
//         ]
//       }
//
//     This makes the full chain of events for a shell pipeline / AI agent
//     action visible in one block rather than scattered across many lines.
//
// SSE:
//     Both modes fan-out to SSE subscribers at GET /events.
//     Flat mode sends one SSE event per event.
//     Grouped mode sends one SSE event per flushed session group.
package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ai-agent-monitor/internal/consumer"
	"go.uber.org/zap"
)

// EventWriter is the common interface for flat and grouped output.
type EventWriter interface {
	Write(ctx context.Context, ev *consumer.EnrichedEvent)
}

// ── Flat NDJSON writer ────────────────────────────────────────────────────────

// Writer handles flat JSON serialisation and SSE distribution.
type Writer struct {
	mu     sync.Mutex
	w      io.Writer
	logger *zap.Logger

	// SSE broadcaster
	sseClients map[chan []byte]struct{}
	sseMu      sync.RWMutex
}

// New creates a Writer that emits flat NDJSON to w.
// If listenAddr is non-empty, an SSE server is started on that address.
func New(w io.Writer, listenAddr string, logger *zap.Logger) *Writer {
	wr := &Writer{
		w:          w,
		logger:     logger,
		sseClients: make(map[chan []byte]struct{}),
	}
	if listenAddr != "" {
		go wr.startSSE(listenAddr)
	}
	return wr
}

// Write serialises ev to flat NDJSON and fans it out to SSE subscribers.
func (w *Writer) Write(_ context.Context, ev *consumer.EnrichedEvent) {
	if ev.Tags == nil {
		ev.Tags = []string{}
	}

	data, err := json.Marshal(ev)
	if err != nil {
		w.logger.Error("json marshal failed", zap.Error(err))
		return
	}
	line := append(data, '\n')

	w.mu.Lock()
	_, _ = w.w.Write(line)
	w.mu.Unlock()

	w.fanoutSSE(data)
}

// ── Grouped session writer ────────────────────────────────────────────────────

// GroupedWriter buffers events by session and flushes them as a single nested
// JSON block after the session has been idle for idleTimeout.
// This produces one output record per "chain of events" rather than one per event.
type GroupedWriter struct {
	mu          sync.Mutex
	groups      map[string]*sessionGroup
	w           io.Writer
	wmu         sync.Mutex // guards writes to w
	idleTimeout time.Duration
	logger      *zap.Logger

	// SSE broadcaster (same fan-out as Writer)
	sseClients map[chan []byte]struct{}
	sseMu      sync.RWMutex
}

// sessionGroup accumulates events for one AI session.
type sessionGroup struct {
	SessionID  string `json:"session_id"`
	ParentPID  uint32 `json:"parent_pid,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	DurationMs int64  `json:"duration_ms"`
	PeakRisk   int    `json:"peak_risk_score"`
	Tags       []string `json:"tags"`
	EventCount int    `json:"event_count"`
	Events     []*consumer.EnrichedEvent `json:"events"`

	tagSet map[string]struct{} // dedup helper, not serialised
}

// NewGroupedWriter creates a GroupedWriter that flushes sessions after idleTimeout
// of inactivity. Call Start(ctx) to enable the background flush goroutine.
func NewGroupedWriter(w io.Writer, idleTimeout time.Duration, listenAddr string, logger *zap.Logger) *GroupedWriter {
	gw := &GroupedWriter{
		groups:      make(map[string]*sessionGroup),
		w:           w,
		idleTimeout: idleTimeout,
		logger:      logger,
		sseClients:  make(map[chan []byte]struct{}),
	}
	if listenAddr != "" {
		go gw.startSSE(listenAddr)
	}
	return gw
}

// Start launches the background goroutine that checks for idle sessions and
// flushes them. Blocks until ctx is cancelled, then flushes all remaining groups.
func (gw *GroupedWriter) Start(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			gw.flushIdle(true) // flush everything on shutdown
			return
		case <-ticker.C:
			gw.flushIdle(false) // flush only idle sessions
		}
	}
}

// Write buffers ev into its session group, resetting the idle clock.
func (gw *GroupedWriter) Write(_ context.Context, ev *consumer.EnrichedEvent) {
	if ev.Tags == nil {
		ev.Tags = []string{}
	}

	gw.mu.Lock()
	defer gw.mu.Unlock()

	g, exists := gw.groups[ev.AISessionID]
	if !exists {
		g = &sessionGroup{
			SessionID:  ev.AISessionID,
			ParentPID:  ev.Ppid,
			ParentComm: ev.ParentComm,
			FirstSeen:  ev.Timestamp,
			LastSeen:   ev.Timestamp,
			tagSet:     make(map[string]struct{}),
		}
		gw.groups[ev.AISessionID] = g
	}

	g.LastSeen = ev.Timestamp
	g.Events = append(g.Events, ev)

	if ev.RiskScore > g.PeakRisk {
		g.PeakRisk = ev.RiskScore
	}
	// Inherit parent info from exec events (most reliable source)
	if ev.EventType == "exec" && ev.ParentComm != "" && g.ParentComm == "" {
		g.ParentComm = ev.ParentComm
		g.ParentPID = ev.Ppid
	}
	for _, tag := range ev.Tags {
		g.tagSet[tag] = struct{}{}
	}
}

// flushIdle emits all groups that have been idle >= idleTimeout.
// If force=true, all groups are flushed regardless of idle time.
func (gw *GroupedWriter) flushIdle(force bool) {
	gw.mu.Lock()

	var toFlush []*sessionGroup
	now := time.Now()
	for id, g := range gw.groups {
		if force || now.Sub(g.LastSeen) >= gw.idleTimeout {
			toFlush = append(toFlush, g)
			delete(gw.groups, id)
		}
	}
	gw.mu.Unlock()

	for _, g := range toFlush {
		gw.emit(g)
	}
}

// emit serialises and writes one session group.
func (gw *GroupedWriter) emit(g *sessionGroup) {
	// Build sorted tag list from dedup set
	tags := make([]string, 0, len(g.tagSet))
	for tag := range g.tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	g.Tags = tags
	g.EventCount = len(g.Events)
	g.DurationMs = g.LastSeen.Sub(g.FirstSeen).Milliseconds()

	// Serialise with indentation for human readability
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		gw.logger.Error("grouped marshal failed", zap.Error(err))
		return
	}
	data = append(data, '\n')

	gw.wmu.Lock()
	_, _ = gw.w.Write(data)
	gw.wmu.Unlock()

	// Fan-out compact (non-indented) version to SSE subscribers
	compact, _ := json.Marshal(g)
	gw.fanoutSSE(compact)
}

// ── Shared SSE infrastructure ─────────────────────────────────────────────────

func (w *Writer) fanoutSSE(data []byte) {
	w.sseMu.RLock()
	for ch := range w.sseClients {
		select {
		case ch <- data:
		default:
		}
	}
	w.sseMu.RUnlock()
}

func (gw *GroupedWriter) fanoutSSE(data []byte) {
	gw.sseMu.RLock()
	for ch := range gw.sseClients {
		select {
		case ch <- data:
		default:
		}
	}
	gw.sseMu.RUnlock()
}

func (w *Writer) startSSE(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", w.handleSSE)
	mux.HandleFunc("/healthz", healthz)
	listenAndServe(addr, mux, w.logger)
}

func (gw *GroupedWriter) startSSE(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", gw.handleSSE)
	mux.HandleFunc("/healthz", healthz)
	listenAndServe(addr, mux, gw.logger)
}

func healthz(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok"))
}

func listenAndServe(addr string, mux *http.ServeMux, logger *zap.Logger) {
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	logger.Info("SSE server starting",
		zap.String("addr", addr),
		zap.String("endpoint", "GET "+addr+"/events"),
	)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("SSE server error", zap.Error(err))
	}
}

func (w *Writer) handleSSE(rw http.ResponseWriter, r *http.Request) {
	ch := sseConnect(rw, r, w.logger)
	defer sseDisconnect(rw, r, ch, &w.sseMu, w.sseClients, w.logger)

	w.sseMu.Lock()
	w.sseClients[ch] = struct{}{}
	w.sseMu.Unlock()

	sseStream(rw, r, ch)
}

func (gw *GroupedWriter) handleSSE(rw http.ResponseWriter, r *http.Request) {
	ch := sseConnect(rw, r, gw.logger)
	defer sseDisconnect(rw, r, ch, &gw.sseMu, gw.sseClients, gw.logger)

	gw.sseMu.Lock()
	gw.sseClients[ch] = struct{}{}
	gw.sseMu.Unlock()

	sseStream(rw, r, ch)
}

func sseConnect(rw http.ResponseWriter, r *http.Request, logger *zap.Logger) chan []byte {
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, ": ai-agent-monitor stream connected\n\n")
	if f, ok := rw.(http.Flusher); ok {
		f.Flush()
	}
	logger.Info("SSE client connected", zap.String("remote", r.RemoteAddr))
	return make(chan []byte, 256)
}

func sseDisconnect(rw http.ResponseWriter, r *http.Request, ch chan []byte,
	mu *sync.RWMutex, clients map[chan []byte]struct{}, logger *zap.Logger) {
	mu.Lock()
	delete(clients, ch)
	close(ch)
	mu.Unlock()
	logger.Info("SSE client disconnected", zap.String("remote", r.RemoteAddr))
}

func sseStream(rw http.ResponseWriter, r *http.Request, ch chan []byte) {
	flusher, canFlush := rw.(http.Flusher)
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(rw, "data: %s\n\n", data)
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

// ── Summary stats ─────────────────────────────────────────────────────────────

// PrintSummary writes a human-readable summary of session stats to the logger.
func PrintSummary(logger *zap.Logger, sessions int, decoded, dropped uint64) {
	logger.Info("monitor summary",
		zap.Int("active_sessions", sessions),
		zap.Uint64("events_decoded", decoded),
		zap.Uint64("events_dropped", dropped),
	)
}
