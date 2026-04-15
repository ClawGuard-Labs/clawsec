//go:build linux

// correlator.go — AI activity session management engine.
//
// The Correlator receives decoded events from the consumer and:
//  1. Assigns each event to an AI activity Session
//  2. Maintains the PID ancestry tree for session inheritance
//  3. Enriches the event with session ID, parent comm, and process tree
//  4. Periodically GCs expired sessions
//
// Session Assignment Algorithm:
//
//	For each incoming event with (pid, ppid):
//	  a) If pid is already in pidToSession → use that session
//	  b) Walk pidToParent: pid → ppid → ppid.ppid → ...
//	     until we hit a known session or reach a root (ppid == 0/1)
//	  c) Check ppid directly from the event (covers first-time exec events)
//	  d) If no ancestor found → create a new session with pid as root
//
// Process Tree Enrichment:
//
//	pidToComm tracks the most recent comm seen per PID (populated from
//	exec events). buildProcessTree() walks pidToParent to reconstruct
//	the ancestry chain from the session root down to the event's parent.
//	The chain is attached to ev.ProcessTree as []ProcessAncestor.
//
// Thread safety: all public methods are safe for concurrent use.
package correlator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ClawGuard-Labs/akmon/internal/consumer"
	"go.uber.org/zap"
)

const (
	maxAncestorWalkDepth = 16
	gcInterval           = 2 * time.Minute
)

// Correlator manages AI activity sessions and PID ancestry tracking.
type Correlator struct {
	mu sync.RWMutex

	pidToSession map[uint32]string // pid → session ID
	pidToParent  map[uint32]uint32 // pid → ppid
	pidToComm    map[uint32]string // pid → most recent comm (from exec events)
	sessions     map[string]*Session

	logger *zap.Logger
}

// New creates a Correlator and starts the background GC goroutine.
// The GC goroutine stops when ctx is cancelled.
func New(ctx context.Context, logger *zap.Logger) *Correlator {
	c := &Correlator{
		pidToSession: make(map[uint32]string),
		pidToParent:  make(map[uint32]uint32),
		pidToComm:    make(map[uint32]string),
		sessions:     make(map[string]*Session),
		logger:       logger,
	}
	go c.gcLoop(ctx)
	return c
}

// Process assigns the event to a session, enriches it with the session ID,
// parent comm, and process ancestry chain.
// Must be called from a single goroutine (the consumer loop) for ordering.
func (c *Correlator) Process(ev *consumer.EnrichedEvent) *consumer.EnrichedEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Record parent relationship from exec events (most reliable source).
	if ev.EventType == "exec" && ev.Ppid != 0 {
		c.pidToParent[ev.Pid] = ev.Ppid
	}

	// Track comm per PID from exec events (for process tree display).
	if ev.EventType == "exec" && ev.Comm != "" {
		c.pidToComm[ev.Pid] = ev.Comm
	}

	// Enrich: parent comm (direct parent name).
	// Primary source: our pidToComm cache (populated from exec events).
	// Fallback: /proc/<ppid>/comm for processes that existed before monitoring
	// started (e.g. the shell that launched the monitored command).
	if comm, ok := c.pidToComm[ev.Ppid]; ok {
		ev.ParentComm = comm
	} else if ev.Ppid > 1 {
		if comm := readProcComm(ev.Ppid); comm != "" {
			c.pidToComm[ev.Ppid] = comm // cache so siblings get it too
			ev.ParentComm = comm
		}
	}

	// Enrich: process ancestry chain [root → ... → direct parent].
	ev.ProcessTree = c.buildProcessTree(ev.Pid)

	sessID := c.findOrCreateSession(ev.Pid, ev.Ppid, ev.CgroupID)
	ev.AISessionID = sessID

	sess := c.sessions[sessID]
	if sess == nil {
		return ev
	}

	sess.Lock()

	sess.AddPID(ev.Pid)

	// Track event timing for cross-event pattern detection (used by detector).
	switch ev.EventType {
	case "exec":
		sess.LastExecTime = ev.Timestamp
		// download → exec: exec within 30s of the last outbound connection
		if !sess.LastNetTime.IsZero() &&
			ev.Timestamp.Sub(sess.LastNetTime) <= 30*time.Second {
			sess.ExecAfterNet = true
		}
	case "net_connect":
		sess.LastNetTime = ev.Timestamp
	}

	sess.AddEvent(ev)
	sess.Unlock()

	// Snapshot tags onto the event (for JSON output).
	ev.Tags = append(ev.Tags, sess.TagList()...)

	return ev
}

// GetSession returns the session for a given ID (nil if not found).
func (c *Correlator) GetSession(sessID string) *Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[sessID]
}

// SessionCount returns the number of currently active sessions.
func (c *Correlator) SessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// ─── Internal helpers ────────────────────────────────────────────────────────

// buildProcessTree returns the ancestry chain from the session root (or the
// oldest known ancestor) down to the direct parent of pid.
// The result is [oldest_ancestor, ..., direct_parent] — pid itself is excluded.
// Must be called with c.mu held (any lock).
func (c *Correlator) buildProcessTree(pid uint32) []consumer.ProcessAncestor {
	// Walk up to collect the chain, then reverse it.
	// We collect [direct_parent, grandparent, ..., root] and reverse.
	chain := make([]consumer.ProcessAncestor, 0, 8)

	current := pid
	for depth := 0; depth < maxAncestorWalkDepth; depth++ {
		parent, ok := c.pidToParent[current]
		if !ok || parent <= 1 {
			break
		}
		chain = append(chain, consumer.ProcessAncestor{
			Pid:  parent,
			Comm: c.pidToComm[parent],
		})
		current = parent
	}

	if len(chain) == 0 {
		return nil
	}

	// Reverse so the result reads root → ... → direct parent
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// findOrCreateSession returns the session ID for pid, creating one if needed.
// Must be called with c.mu held (write lock).
func (c *Correlator) findOrCreateSession(pid, ppid uint32, cgroupID uint64) string {
	// Fast path: pid already mapped to a session.
	if sessID, ok := c.pidToSession[pid]; ok {
		return sessID
	}

	// Walk the ancestor chain through our recorded parent relationships.
	current := pid
	for depth := 0; depth < maxAncestorWalkDepth; depth++ {
		parent, ok := c.pidToParent[current]
		if !ok {
			break
		}
		if sessID, ok := c.pidToSession[parent]; ok {
			c.pidToSession[pid] = sessID
			return sessID
		}
		current = parent
	}

	// Check ppid from the event directly (covers first exec from a new child).
	if ppid > 1 {
		if sessID, ok := c.pidToSession[ppid]; ok {
			c.pidToSession[pid] = sessID
			c.pidToParent[pid] = ppid
			return sessID
		}
	}

	// No ancestor in any known session — create a new session.
	sessID := makeSessionID(pid)
	sess := newSession(sessID, pid, cgroupID)
	c.sessions[sessID] = sess
	c.pidToSession[pid] = sessID

	// Register the parent PID in this session so future siblings (other
	// children of ppid, e.g. processes in the same shell pipeline) inherit
	// the same session rather than creating isolated one-process sessions.
	if ppid > 1 {
		if _, exists := c.pidToSession[ppid]; !exists {
			c.pidToSession[ppid] = sessID
		}
	}

	c.logger.Debug("new session",
		zap.String("id", sessID),
		zap.Uint32("root_pid", pid),
		zap.Uint32("ppid", ppid),
		zap.String("parent_comm", c.pidToComm[ppid]),
	)
	return sessID
}

// readProcComm reads the process name from /proc/<pid>/comm.
// Returns empty string on any error (process may have exited).
// Used as a fallback when a process existed before monitoring started.
func readProcComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func makeSessionID(rootPID uint32) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", rootPID, time.Now().UnixNano())))
	return fmt.Sprintf("sess_%x", h[:4])
}

// gcLoop removes expired sessions on a timer. Stops when ctx is done.
func (c *Correlator) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.gc()
		}
	}
}

func (c *Correlator) gc() {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expired []string
	for id, sess := range c.sessions {
		if sess.IsExpired() {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		sess := c.sessions[id]
		if sess != nil {
			sess.RLock()
			for pid := range sess.PIDs {
				delete(c.pidToSession, pid)
				delete(c.pidToParent, pid)
				delete(c.pidToComm, pid)
			}
			sess.RUnlock()
		}
		delete(c.sessions, id)
	}
	if len(expired) > 0 {
		c.logger.Debug("session GC",
			zap.Int("expired", len(expired)),
			zap.Int("remaining", len(c.sessions)),
		)
	}
}
