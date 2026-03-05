// session.go — AI activity session definition.
//
// A Session groups all events from a single AI agent's execution tree.
// It tracks the PID family, event history, risk accumulation, and detected
// behaviour tags.
//
// Session lifecycle:
//   1. Created when an event arrives with an unknown PID that has no
//      known ancestor in our PID→session map.
//   2. Extended whenever a new PID whose parent is in this session executes.
//   3. Marked idle after sessionIdleTimeout of inactivity.
//   4. Expired and GC'd after sessionExpireTimeout.
package correlator

import (
	"sync"
	"time"

	"github.com/ai-agent-monitor/internal/consumer"
)

const (
	sessionIdleTimeout   = 5 * time.Minute
	sessionExpireTimeout = 30 * time.Minute
	maxSessionEvents     = 500 // cap to control memory
)

// Session represents one AI agent's observable activity window.
type Session struct {
	mu sync.RWMutex

	// ── Identity ──────────────────────────────────────────────────────
	ID       string // "sess_" + 8-char hex hash
	RootPID  uint32 // first PID observed (likely the AI agent itself)
	CgroupID uint64 // cgroup of the root process

	// ── Membership ────────────────────────────────────────────────────
	// All PIDs that belong to this session (root + all descendants).
	PIDs map[uint32]struct{}

	// ── Event history ─────────────────────────────────────────────────
	// Capped at maxSessionEvents — oldest events drop off the front.
	Events []*consumer.EnrichedEvent

	// ── Timing ────────────────────────────────────────────────────────
	CreatedAt time.Time
	LastSeen  time.Time

	// ── Risk accumulation ─────────────────────────────────────────────
	RiskScore int
	Tags      map[string]struct{} // deduped tag set

	// ── Detected patterns (used by detector) ─────────────────────────
	// LastNetTime is the most recent outbound connection timestamp.
	// Used to detect "download → execute" within a time window.
	LastNetTime time.Time
	// LastExecTime is the most recent exec event timestamp.
	LastExecTime time.Time
	// ExecAfterNet flags that exec occurred within 30s of a net_connect.
	ExecAfterNet bool
}

// newSession allocates a Session with the given root PID.
func newSession(id string, rootPID uint32, cgroupID uint64) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		RootPID:   rootPID,
		CgroupID:  cgroupID,
		PIDs:      map[uint32]struct{}{rootPID: {}},
		Events:    make([]*consumer.EnrichedEvent, 0, 32),
		CreatedAt: now,
		LastSeen:  now,
		Tags:      map[string]struct{}{},
	}
}

// AddEvent appends an event to the session history (capped).
// Must be called with the session lock held (write).
func (s *Session) AddEvent(ev *consumer.EnrichedEvent) {
	s.LastSeen = time.Now()
	if len(s.Events) >= maxSessionEvents {
		// Drop oldest event (ring-buffer semantics)
		copy(s.Events, s.Events[1:])
		s.Events = s.Events[:len(s.Events)-1]
	}
	s.Events = append(s.Events, ev)
}

// AddPID registers a new PID as belonging to this session.
// Must be called with the session lock held (write).
func (s *Session) AddPID(pid uint32) {
	s.PIDs[pid] = struct{}{}
}

// Tag adds a behaviour tag (deduped).
// Must be called with the session lock held (write).
func (s *Session) Tag(tag string) {
	s.Tags[tag] = struct{}{}
}

// TagList returns a sorted snapshot of all tags.
// Thread-safe (acquires read lock).
func (s *Session) TagList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tags := make([]string, 0, len(s.Tags))
	for t := range s.Tags {
		tags = append(tags, t)
	}
	return tags
}

// IsExpired returns true if the session has been idle past the expiry limit.
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastSeen) > sessionExpireTimeout
}

// ── Exported lock methods ─────────────────────────────────────────────────
// These let packages outside the correlator package (e.g. detector) hold
// the session lock while reading or writing session fields.
// Pattern: sess.Lock(); defer sess.Unlock(); ... access sess.Fields ...

func (s *Session) Lock()    { s.mu.Lock() }
func (s *Session) Unlock()  { s.mu.Unlock() }
func (s *Session) RLock()   { s.mu.RLock() }
func (s *Session) RUnlock() { s.mu.RUnlock() }
