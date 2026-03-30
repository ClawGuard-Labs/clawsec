// Package graphapi serves the provenance graph dashboard over HTTP.
//
// Routes:
//
//	GET  /api/graph         — full Snapshot (JSON)
//	GET  /api/graph/events  — SSE stream of GraphDiff updates
//	GET  /api/alerts        — all alerts so far (JSON)
//	GET  /api/chains        — aggregated chain data (JSON, requires --compact)
//	GET  /*                 — React SPA (embedded static files)
//
// The static/ subdirectory is populated by `make ui` (Vite build).
// When running without a built UI, the bare REST + SSE endpoints still work.
package graphapi

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/clawsec/internal/chagg"
	"github.com/clawsec/internal/graph"
)

//go:embed static
var staticFiles embed.FS

// Server is the HTTP server for the graph dashboard.
type Server struct {
	g      *graph.Graph
	agg    *chagg.Aggregator // nil when --compact is not enabled
	logger *zap.Logger
	srv    *http.Server
}

// New creates a Server bound to addr (e.g. ":9090") backed by g.
// agg may be nil when chain aggregation is disabled.
func New(addr string, g *graph.Graph, agg *chagg.Aggregator, logger *zap.Logger) *Server {
	s := &Server{g: g, agg: agg, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/graph/events", s.handleSSE)
	mux.HandleFunc("/api/graph", s.handleSnapshot)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/chains", s.handleChains)

	// Serve the embedded React SPA for all other paths.
	// Fall back to index.html for client-side routing (SPA 404 → index.html).
	uiFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		logger.Warn("graphapi: could not sub static/ from embed.FS", zap.Error(err))
	} else {
		mux.Handle("/", spaHandler{fs: http.FS(uiFS)})
	}

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE connections stream indefinitely
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// Start begins listening. It returns when ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutCtx); err != nil {
			s.logger.Warn("graphapi: shutdown error", zap.Error(err))
		}
	}()

	s.logger.Info("graphapi: UI server listening",
		zap.String("addr", s.srv.Addr),
		zap.String("ui", "http://"+s.srv.Addr),
	)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error("graphapi: server error", zap.Error(err))
	}
}

// ─── handlers ────────────────────────────────────────────────────────────────

// handleSnapshot serves a full graph snapshot as JSON.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := s.g.Snapshot()
	writeJSON(w, snap)
}

// handleAlerts serves the alert list as JSON.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := s.g.Snapshot()
	writeJSON(w, snap.Alerts)
}

// handleSSE streams GraphDiff updates as Server-Sent Events.
//
// Protocol:
//
//	event: init
//	data: <full Snapshot JSON>
//
//	event: diff
//	data: <GraphDiff JSON>
//
//	: heartbeat (every 15 s)
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// Subscribe before sending snapshot so we don't miss events that arrive
	// between snapshot and subscription.
	ch := s.g.Subscribe()
	defer s.g.Unsubscribe(ch)

	// Send full graph state as the initial "init" event.
	snap := s.g.Snapshot()
	if err := writeSSEEvent(w, "init", snap); err != nil {
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case diff, open := <-ch:
			if !open {
				return
			}
			if err := writeSSEEvent(w, "diff", diff); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// handleChains serves the aggregated chain data as JSON.
// Returns an empty array when chain aggregation is not enabled.
func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.agg == nil {
		writeJSON(w, []struct{}{})
		return
	}
	writeJSON(w, s.agg.Snapshot())
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
	}
}

func writeSSEEvent(w http.ResponseWriter, eventType string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
	return err
}

// corsMiddleware adds permissive CORS headers so the Vite dev server
// (running on a different port during development) can reach the API.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves static files and falls back to index.html for paths that
// don't match a real file (client-side routing support).
type spaHandler struct {
	fs http.FileSystem
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Try to open the exact path.
	f, err := h.fs.Open(path)
	if err == nil {
		f.Close()
		http.FileServer(h.fs).ServeHTTP(w, r)
		return
	}

	// Fall back to index.html for the SPA router.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	http.FileServer(h.fs).ServeHTTP(w, r2)
}
