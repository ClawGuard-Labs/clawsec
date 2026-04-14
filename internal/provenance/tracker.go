// Package provenance tracks file and process taint across sessions.
//
// # Problem
//
// The correlator groups events by PID ancestry (session). But an attack chain
// often crosses session boundaries:
//
//	Session A:  openclaw ──[net_connect]──▶ evil.com:443
//	                     ──[file_open write]▶ /models/mal.gguf
//
//	Session B:  python3  ──[file_open read]──▶ /models/mal.gguf   (different session!)
//	                     ──[exec]───────────▶  bash               ← ALERT
//
// The shared artifact (the file) links A and B, but the session tracker
// cannot see this because it only follows PID ancestry.
//
// # Current capability vs future work
//
// File-level taint (net_connect → file_write → file_read by another process)
// requires eBPF to emit file_open events for model file paths. Currently the
// eBPF kernel program only emits file_open for "sensitive" paths (/proc, /sys,
// /etc, .ssh).
//
// Until then this tracker operates at the process+network level:
//
//  1. A process makes net_connect to an external (non-localhost) host
//     → it is marked as a "potential downloader"
//  2. If a tainted process (or one of its children) later execs a new process
//     → the child inherits the taint
//  3. A tainted process performing suspicious actions generates alerts
//
// If a file_open write IS observed for a known model extension (e.g. the path
// was coincidentally in a sensitive directory) we DO record file provenance.
//
// # Thread safety
//
// All exported methods are safe for concurrent use.
package provenance

import (
	"fmt"
	"sync"
	"time"

	"github.com/onyx/internal/aiprofile"
	"github.com/onyx/internal/constants"
	"github.com/onyx/internal/consumer"
)

// ─── constants ───────────────────────────────────────────────────────────────

const (
	// downloadCorrelationWindow: if a file_open write follows a net_connect
	// within this window from the same PID, the file is considered downloaded.
	downloadCorrelationWindow = 60 * time.Second

	// taintExpiryDuration: tainted PID records are removed after this duration
	// to prevent unbounded memory growth. See TODO.md for a configurable flag.
	taintExpiryDuration = 2 * time.Hour
)

// TaintInfo is the result of processing a single event through the tracker.
// It is attached to the event before the detector runs.
type TaintInfo struct {
	IsTainted    bool
	IsNewTaint   bool   // first time this specific entity became tainted
	TaintReason  string // human-readable explanation
	SourceIP     string // IP of the external host that triggered the chain
	SourcePort   uint16
	TaintedFile  string // file path that carries the taint (if known)
	ChainSession string // ai_session_id of the session that started the chain
}

// FileRecord captures the lifecycle of a file suspected of being downloaded.
type FileRecord struct {
	Path       string
	SourceIP   string
	SourcePort uint16
	WrittenBy  uint32 // PID
	WrittenAt  time.Time
	SessionID  string
	OpenedBy   []FileAccess
}

// FileAccess records one read-open of a tracked file.
type FileAccess struct {
	PID       uint32
	Comm      string
	SessionID string
	At        time.Time
}

// ─── internal types ──────────────────────────────────────────────────────────

type taintedEntry struct {
	Reason       string
	TaintedAt    time.Time
	SourceIP     string
	SourcePort   uint16
	TaintedFile  string
	ChainSession string
}

type pendingConnect struct {
	DstIP   string
	DstPort uint16
	At      time.Time
}

// ─── Tracker ─────────────────────────────────────────────────────────────────

// Tracker is the central state machine for provenance and taint.
type Tracker struct {
	mu sync.RWMutex

	// files: path → record for files confirmed as network-sourced.
	// Populated only when we actually observe the file_open write event,
	// which currently requires the file to be in a sensitive eBPF-tracked path.
	files map[string]*FileRecord

	// taintedPIDs: pid → taint entry.
	// A PID is tainted when it (a) makes an outbound net_connect that is
	// correlated with a subsequent suspicious action, or (b) is a child of
	// a tainted PID, or (c) opens a tainted file.
	taintedPIDs map[uint32]*taintedEntry

	// pendingConnects: pid → most-recent external net_connect.
	// Cleared when the PID becomes tainted or after downloadCorrelationWindow.
	pendingConnects map[uint32]*pendingConnect
	cfg             *aiprofile.Profile
}

// New returns a ready Tracker. cfg is the loaded config.yaml profile.
func New(cfg *aiprofile.Profile) *Tracker {
	return &Tracker{
		files:           make(map[string]*FileRecord),
		taintedPIDs:     make(map[uint32]*taintedEntry),
		pendingConnects: make(map[uint32]*pendingConnect),
		cfg:             cfg,
	}
}

// ─── public API ──────────────────────────────────────────────────────────────

// Track processes one event and returns taint information for it.
// Called from the main event loop (single goroutine) so no lock is held
// by the caller — Track acquires its own lock.
func (t *Tracker) Track(ev *consumer.EnrichedEvent) TaintInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.expirePendingConnects()

	switch ev.EventType {
	case "net_connect":
		return t.handleNetConnect(ev)
	case "file_open":
		return t.handleFileOpen(ev)
	case "exec":
		return t.handleExec(ev)
	default:
		// For all other event types, just report whether this PID is
		// already tainted (e.g. file_rw, net_send, tls_send from a
		// tainted process all carry the same taint).
		return t.existingTaint(ev.Pid)
	}
}

// IsPIDTainted reports whether pid is currently in the tainted set.
func (t *Tracker) IsPIDTainted(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.taintedPIDs[pid]
	return ok
}

// GetFile returns the FileRecord for path if it is tracked (nil otherwise).
func (t *Tracker) GetFile(path string) *FileRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.files[path]
}

// ─── event handlers ──────────────────────────────────────────────────────────

func (t *Tracker) handleNetConnect(ev *consumer.EnrichedEvent) TaintInfo {
	if ev.Network == nil {
		return TaintInfo{}
	}

	ip, port := ev.Network.DstIP, ev.Network.DstPort

	// Skip localhost and known AI-service ports — not a suspicious download.
	_, knownPort := t.cfg.ServiceNameForPort(port)
	if constants.IsLocalhost(ip) || knownPort {
		return t.existingTaint(ev.Pid)
	}

	// Record as a potential download start.
	t.pendingConnects[ev.Pid] = &pendingConnect{
		DstIP:   ip,
		DstPort: port,
		At:      ev.Timestamp,
	}

	// The net_connect itself is not a taint; wait for a corroborating event.
	return t.existingTaint(ev.Pid)
}

func (t *Tracker) handleFileOpen(ev *consumer.EnrichedEvent) TaintInfo {
	// ── Case 1: write-open after pending connect → potential model download ──
	if constants.IsWriteOpen(ev.FileFlags) {
		if pc, ok := t.pendingConnects[ev.Pid]; ok {
			if ev.Timestamp.Sub(pc.At) <= downloadCorrelationWindow && t.hasModelExt(ev.FilePath) {
				// Confirm: this file is being written after an external connection.
				if _, exists := t.files[ev.FilePath]; !exists {
					t.files[ev.FilePath] = &FileRecord{
						Path:       ev.FilePath,
						SourceIP:   pc.DstIP,
						SourcePort: pc.DstPort,
						WrittenBy:  ev.Pid,
						WrittenAt:  ev.Timestamp,
						SessionID:  ev.AISessionID,
					}
				}
				delete(t.pendingConnects, ev.Pid)

				info := TaintInfo{
					IsTainted:    true,
					IsNewTaint:   true,
					TaintReason:  fmt.Sprintf("model file written after connecting to %s:%d", pc.DstIP, pc.DstPort),
					SourceIP:     pc.DstIP,
					SourcePort:   pc.DstPort,
					TaintedFile:  ev.FilePath,
					ChainSession: ev.AISessionID,
				}
				// Also taint the writing process itself.
				t.setTaint(ev.Pid, info)
				return info
			}
		}
	}

	// ── Case 2: read-open of a tainted file → taint the opener ──────────────
	if rec, ok := t.files[ev.FilePath]; ok && !constants.IsWriteOpen(ev.FileFlags) {
		rec.OpenedBy = append(rec.OpenedBy, FileAccess{
			PID: ev.Pid, Comm: ev.Comm,
			SessionID: ev.AISessionID, At: ev.Timestamp,
		})

		if existing, alreadyTainted := t.taintedPIDs[ev.Pid]; alreadyTainted {
			return TaintInfo{
				IsTainted: true, TaintReason: existing.Reason,
				SourceIP: existing.SourceIP, SourcePort: existing.SourcePort,
				TaintedFile: existing.TaintedFile, ChainSession: existing.ChainSession,
			}
		}

		info := TaintInfo{
			IsTainted:    true,
			IsNewTaint:   true,
			TaintReason:  fmt.Sprintf("opened network-sourced file %s (from %s:%d)", rec.Path, rec.SourceIP, rec.SourcePort),
			SourceIP:     rec.SourceIP,
			SourcePort:   rec.SourcePort,
			TaintedFile:  rec.Path,
			ChainSession: rec.SessionID,
		}
		t.setTaint(ev.Pid, info)
		return info
	}

	return t.existingTaint(ev.Pid)
}

func (t *Tracker) handleExec(ev *consumer.EnrichedEvent) TaintInfo {
	// Propagate taint from parent (ppid) to child (pid).
	parent, parentTainted := t.taintedPIDs[ev.Ppid]
	if !parentTainted {
		return t.existingTaint(ev.Pid)
	}

	childInfo := TaintInfo{
		IsTainted:    true,
		IsNewTaint:   true,
		TaintReason:  fmt.Sprintf("child of tainted process (ppid=%d): %s", ev.Ppid, parent.Reason),
		SourceIP:     parent.SourceIP,
		SourcePort:   parent.SourcePort,
		TaintedFile:  parent.TaintedFile,
		ChainSession: parent.ChainSession,
	}
	t.setTaint(ev.Pid, childInfo)
	return childInfo
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (t *Tracker) setTaint(pid uint32, info TaintInfo) {
	t.taintedPIDs[pid] = &taintedEntry{
		Reason:       info.TaintReason,
		TaintedAt:    time.Now(),
		SourceIP:     info.SourceIP,
		SourcePort:   info.SourcePort,
		TaintedFile:  info.TaintedFile,
		ChainSession: info.ChainSession,
	}
}

func (t *Tracker) existingTaint(pid uint32) TaintInfo {
	e, ok := t.taintedPIDs[pid]
	if !ok {
		return TaintInfo{}
	}
	return TaintInfo{
		IsTainted:    true,
		TaintReason:  e.Reason,
		SourceIP:     e.SourceIP,
		SourcePort:   e.SourcePort,
		TaintedFile:  e.TaintedFile,
		ChainSession: e.ChainSession,
	}
}

// expirePendingConnects removes stale entries outside the correlation window.
// Must be called with t.mu held (write lock).
func (t *Tracker) expirePendingConnects() {
	now := time.Now()
	for pid, pc := range t.pendingConnects {
		if now.Sub(pc.At) > downloadCorrelationWindow {
			delete(t.pendingConnects, pid)
		}
	}
}

func (t *Tracker) hasModelExt(path string) bool {
	return t.cfg.IsModelExtension(constants.FileExt(path))
}
