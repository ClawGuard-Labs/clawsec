package chagg

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Aggregator collects graph edges per process, finalizes idle chains, and
// deduplicates identical edge patterns (within the same session) into counted
// Chain entries.
type Aggregator struct {
	mu         sync.Mutex
	pending    map[string]*pendingChain // keyed by procID
	chains     map[string]*Chain        // keyed by chainKey()
	idleWindow time.Duration
}

// New returns an Aggregator that finalizes pending chains after idleWindow of
// inactivity.
func New(idleWindow time.Duration) *Aggregator {
	return &Aggregator{
		pending:    make(map[string]*pendingChain),
		chains:     make(map[string]*Chain),
		idleWindow: idleWindow,
	}
}

// TrackEdge records a new edge for the process identified by procID.
// If no pending chain exists, one is created. Each call extends the pending
// chain and resets the idle timer.
//
// Called from graph.Builder.Process() after each edge creation.
func (a *Aggregator) TrackEdge(
	procID, initiatorComm, comm, cmdline string,
	pid, uid uint32,
	sessionID string,
	edgeType, target string,
) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	pc, ok := a.pending[procID]
	if !ok {
		pc = &pendingChain{
			procID:        procID,
			initiatorComm: initiatorComm,
			comm:          comm,
			cmdline:       cmdline,
			pid:           pid,
			uid:           uid,
			sessionID:     sessionID,
			startedAt:     now,
		}
		a.pending[procID] = pc
	}

	pc.edges = append(pc.edges, EdgeDetail{Type: edgeType, Target: target})
	pc.lastEdgeAt = now
}

// Start runs a background goroutine that periodically scans pending chains and
// finalizes any that have been idle for longer than the configured window. It
// also performs periodic GC of old finalized chains.
// Blocks until ctx is cancelled.
func (a *Aggregator) Start(ctx context.Context) {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	gcTick := time.NewTicker(5 * time.Minute)
	defer gcTick.Stop()

	for {
		select {
		case <-ctx.Done():
			a.finalizeAll()
			return
		case <-tick.C:
			a.sweep()
		case <-gcTick.C:
			a.gc()
		}
	}
}

// Snapshot returns a deep copy of all finalized chains.
func (a *Aggregator) Snapshot() []Chain {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Chain, 0, len(a.chains))
	for _, c := range a.chains {
		cp := *c
		cp.EdgeDetails = make([]EdgeDetail, len(c.EdgeDetails))
		copy(cp.EdgeDetails, c.EdgeDetails)
		cp.Occurrences = make([]Occurrence, len(c.Occurrences))
		copy(cp.Occurrences, c.Occurrences)
		out = append(out, cp)
	}
	return out
}

// sweep finalizes all pending chains whose last edge was more than idleWindow ago.
func (a *Aggregator) sweep() {
	cutoff := time.Now().Add(-a.idleWindow)
	a.mu.Lock()
	defer a.mu.Unlock()

	for id, pc := range a.pending {
		if pc.lastEdgeAt.Before(cutoff) {
			a.finalize(pc)
			delete(a.pending, id)
		}
	}
}

// finalizeAll flushes every pending chain (used on shutdown).
func (a *Aggregator) finalizeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for id, pc := range a.pending {
		a.finalize(pc)
		delete(a.pending, id)
	}
}

// gc removes finalized chains older than 1 hour to bound memory.
func (a *Aggregator) gc() {
	cutoff := time.Now().Add(-1 * time.Hour)
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, c := range a.chains {
		if c.LastSeen.Before(cutoff) {
			delete(a.chains, key)
		}
	}
}

// finalize converts a pending chain into a finalized Chain entry, merging with
// an existing one if the chain key matches.
// Caller must hold a.mu.
func (a *Aggregator) finalize(pc *pendingChain) {
	if len(pc.edges) == 0 {
		return
	}

	key := chainKey(pc)
	now := pc.lastEdgeAt

	occ := Occurrence{
		PID:       pc.pid,
		UID:       pc.uid,
		Timestamp: pc.startedAt,
	}

	if existing, ok := a.chains[key]; ok {
		existing.OccurrenceCount++
		existing.LastSeen = now
		occ.Seq = existing.OccurrenceCount

		if len(existing.Occurrences) < maxOccurrences {
			existing.Occurrences = append(existing.Occurrences, occ)
		}
		return
	}

	// Build chain pattern string: "spawned->read->connected"
	parts := make([]string, len(pc.edges))
	for i, e := range pc.edges {
		parts[i] = e.Type
	}
	pattern := strings.Join(parts, "->")

	edges := make([]EdgeDetail, len(pc.edges))
	copy(edges, pc.edges)

	occ.Seq = 1

	a.chains[key] = &Chain{
		SessionID:       pc.sessionID,
		Initiator:       pc.initiatorComm,
		Process:         pc.comm,
		CommandLine:     pc.cmdline,
		ChainPattern:    pattern,
		EdgeDetails:     edges,
		OccurrenceCount: 1,
		FirstSeen:       pc.startedAt,
		LastSeen:        now,
		Occurrences:     []Occurrence{occ},
	}
}

// chainKey computes the deduplication key for a pending chain.
// Session-scoped: chains from different sessions are never merged.
func chainKey(pc *pendingChain) string {
	parts := make([]string, len(pc.edges))
	for i, e := range pc.edges {
		parts[i] = e.Type + ":" + e.Target
	}
	return pc.sessionID + "|" + pc.initiatorComm + "|" + pc.comm + "|" + pc.cmdline + "|" + strings.Join(parts, "->")
}
