package tests

import (
	"context"
	"testing"
	"time"

	"github.com/clawsec/internal/chagg"
)

var chainLogger = categoryLogger("chain")

// TestChainDedup verifies that two identical edge sequences within the same
// session are deduplicated into a single Chain with occurrence_count=2.
func TestChainDedup(t *testing.T) {
	agg := chagg.New(50 * time.Millisecond)

	// First occurrence
	agg.TrackEdge("proc:100", "bash", "python3", "python3 train.py",
		100, 1000, "sess_a", "spawned", "python3")
	agg.TrackEdge("proc:100", "bash", "python3", "python3 train.py",
		100, 1000, "sess_a", "read", "/data/input.csv")

	// Wait for idle finalization
	time.Sleep(120 * time.Millisecond)

	// Second occurrence — same pattern, different PID
	agg.TrackEdge("proc:200", "bash", "python3", "python3 train.py",
		200, 1000, "sess_a", "spawned", "python3")
	agg.TrackEdge("proc:200", "bash", "python3", "python3 train.py",
		200, 1000, "sess_a", "read", "/data/input.csv")

	// Wait for finalization again
	time.Sleep(120 * time.Millisecond)

	// Trigger sweep manually via Start+cancel pattern
	snap := triggerSweepAndSnapshot(t, agg, 200*time.Millisecond)

	if len(snap) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(snap))
	}

	c := snap[0]
	chainLogger.Printf("TestChainDedup: chain=%s count=%d pattern=%s",
		c.Process, c.OccurrenceCount, c.ChainPattern)

	if c.OccurrenceCount != 2 {
		t.Errorf("expected occurrence_count=2, got %d", c.OccurrenceCount)
	}
	if c.ChainPattern != "spawned->read" {
		t.Errorf("expected pattern 'spawned->read', got %q", c.ChainPattern)
	}
	if c.SessionID != "sess_a" {
		t.Errorf("expected session_id 'sess_a', got %q", c.SessionID)
	}
	if c.Initiator != "bash" {
		t.Errorf("expected initiator 'bash', got %q", c.Initiator)
	}
	if len(c.Occurrences) != 2 {
		t.Errorf("expected 2 occurrences, got %d", len(c.Occurrences))
	}
	pids := map[uint32]bool{}
	for _, o := range c.Occurrences {
		pids[o.PID] = true
	}
	if !pids[100] {
		t.Error("expected occurrence with PID 100")
	}
	if !pids[200] {
		t.Error("expected occurrence with PID 200")
	}
}

// TestChainExtension verifies that A->B and A->B->C are treated as separate
// chains (different patterns produce different chain keys).
func TestChainExtension(t *testing.T) {
	agg := chagg.New(50 * time.Millisecond)

	// Short chain: spawned
	agg.TrackEdge("proc:300", "bash", "curl", "curl http://example.com",
		300, 1000, "sess_b", "spawned", "curl")
	time.Sleep(120 * time.Millisecond)

	// Extended chain: spawned -> connected
	agg.TrackEdge("proc:400", "bash", "curl", "curl http://example.com",
		400, 1000, "sess_b", "spawned", "curl")
	agg.TrackEdge("proc:400", "bash", "curl", "curl http://example.com",
		400, 1000, "sess_b", "connected", "93.184.216.34:80")
	time.Sleep(120 * time.Millisecond)

	snap := triggerSweepAndSnapshot(t, agg, 200*time.Millisecond)

	if len(snap) != 2 {
		t.Fatalf("expected 2 distinct chains, got %d", len(snap))
	}

	patterns := map[string]bool{}
	for _, c := range snap {
		patterns[c.ChainPattern] = true
		chainLogger.Printf("TestChainExtension: pattern=%s count=%d",
			c.ChainPattern, c.OccurrenceCount)
	}

	if !patterns["spawned"] {
		t.Error("missing chain with pattern 'spawned'")
	}
	if !patterns["spawned->connected"] {
		t.Error("missing chain with pattern 'spawned->connected'")
	}
}

// TestChainSessionIsolation verifies that identical edge patterns in different
// sessions are NOT deduplicated — each session gets its own Chain entry.
func TestChainSessionIsolation(t *testing.T) {
	agg := chagg.New(50 * time.Millisecond)

	// Session A
	agg.TrackEdge("proc:500", "bash", "python3", "python3 train.py",
		500, 1000, "sess_x", "spawned", "python3")
	time.Sleep(120 * time.Millisecond)

	// Session B — same pattern
	agg.TrackEdge("proc:600", "bash", "python3", "python3 train.py",
		600, 1000, "sess_y", "spawned", "python3")
	time.Sleep(120 * time.Millisecond)

	snap := triggerSweepAndSnapshot(t, agg, 200*time.Millisecond)

	if len(snap) != 2 {
		t.Fatalf("expected 2 chains (one per session), got %d", len(snap))
	}

	sessions := map[string]bool{}
	for _, c := range snap {
		sessions[c.SessionID] = true
		chainLogger.Printf("TestChainSessionIsolation: session=%s pattern=%s",
			c.SessionID, c.ChainPattern)
	}

	if !sessions["sess_x"] {
		t.Error("missing chain for session 'sess_x'")
	}
	if !sessions["sess_y"] {
		t.Error("missing chain for session 'sess_y'")
	}
}

// TestChainFinalization verifies that chains are finalized after the idle
// window expires and appear in the snapshot.
func TestChainFinalization(t *testing.T) {
	agg := chagg.New(50 * time.Millisecond)

	agg.TrackEdge("proc:700", "systemd", "sshd", "sshd -D",
		700, 0, "sess_z", "spawned", "sshd")
	agg.TrackEdge("proc:700", "systemd", "sshd", "sshd -D",
		700, 0, "sess_z", "connected", "10.0.0.1:22")
	agg.TrackEdge("proc:700", "systemd", "sshd", "sshd -D",
		700, 0, "sess_z", "read", "/etc/ssh/sshd_config")

	// Before idle window: should still be pending
	snap := agg.Snapshot()
	if len(snap) != 0 {
		t.Errorf("expected 0 finalized chains before idle window, got %d", len(snap))
	}

	// After idle window
	snap = triggerSweepAndSnapshot(t, agg, 200*time.Millisecond)

	if len(snap) != 1 {
		t.Fatalf("expected 1 finalized chain, got %d", len(snap))
	}

	c := snap[0]
	chainLogger.Printf("TestChainFinalization: pattern=%s edges=%d",
		c.ChainPattern, len(c.EdgeDetails))

	if c.ChainPattern != "spawned->connected->read" {
		t.Errorf("expected pattern 'spawned->connected->read', got %q", c.ChainPattern)
	}
	if len(c.EdgeDetails) != 3 {
		t.Errorf("expected 3 edge details, got %d", len(c.EdgeDetails))
	}
	if c.EdgeDetails[0].Target != "sshd" {
		t.Errorf("expected first target 'sshd', got %q", c.EdgeDetails[0].Target)
	}
	if c.EdgeDetails[1].Target != "10.0.0.1:22" {
		t.Errorf("expected second target '10.0.0.1:22', got %q", c.EdgeDetails[1].Target)
	}
}

// triggerSweepAndSnapshot starts the aggregator in a background goroutine,
// waits for the given duration (allowing idle sweeps to run), then cancels
// the context and returns a snapshot.
func triggerSweepAndSnapshot(t *testing.T, agg *chagg.Aggregator, wait time.Duration) []chagg.Chain {
	t.Helper()

	// The aggregator's Start method runs sweep every 1s, which is too slow
	// for tests. Instead, we rely on the fact that Start calls finalizeAll
	// on context cancellation. Just wait for the idle window to expire
	// (the pending chains need their lastEdgeAt to be old enough), then
	// use a short-lived Start to trigger the finalizeAll path.
	time.Sleep(wait)

	// Short-lived context to trigger finalizeAll via Start's ctx.Done path
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		agg.Start(ctx)
		close(done)
	}()
	<-done

	return agg.Snapshot()
}
