package tests

import (
	"testing"
	"time"

	"github.com/ClawGuard-Labs/akmon/internal/consumer"
	"github.com/ClawGuard-Labs/akmon/internal/graph"
	"github.com/ClawGuard-Labs/akmon/internal/provenance"
)

func TestNoDuplicateAlertsSamePidSameCategory(t *testing.T) {
	g := graph.New()
	b := graph.NewBuilder(g, nil, false, 0)

	at := time.Now().UTC()

	ev1 := &consumer.EnrichedEvent{
		Timestamp:   at,
		EventType:   "exec",
		Pid:         1234,
		Ppid:        1,
		Uid:         1000,
		Comm:        "python3",
		AISessionID: "sess_test0001",
		RiskScore:   70,
		Tags:        []string{"large_mmap"},
		MatchedRules: []consumer.MatchedRule{
			{ID: "large_memory_mapped_file", Name: "Large Memory Mapped File", Severity: "high"},
		},
	}

	// Same PID, same rule/category, same timestamp (simulates concurrent detections).
	ev2 := &consumer.EnrichedEvent{
		Timestamp:   at,
		EventType:   "file_mmap",
		Pid:         1234,
		Ppid:        1,
		Uid:         1000,
		Comm:        "python3",
		AISessionID: "sess_test0001",
		RiskScore:   70,
		Tags:        []string{"large_mmap"},
		MatchedRules: []consumer.MatchedRule{
			{ID: "large_memory_mapped_file", Name: "Large Memory Mapped File", Severity: "high"},
		},
	}

	b.Process(ev1, provenance.TaintInfo{})
	b.Process(ev2, provenance.TaintInfo{})

	snap := g.Snapshot()
	if got, want := len(snap.Alerts), 1; got != want {
		t.Fatalf("expected %d alert after duplicate category triggers, got %d", want, got)
	}

	// Different category for same PID should still produce an additional alert.
	ev3 := &consumer.EnrichedEvent{
		Timestamp:   at,
		EventType:   "net_connect",
		Pid:         1234,
		Ppid:        1,
		Uid:         1000,
		Comm:        "python3",
		AISessionID: "sess_test0001",
		RiskScore:   90,
		Tags:        []string{"net"},
		MatchedRules: []consumer.MatchedRule{
			{ID: "outbound_connection", Name: "Outbound Connection", Severity: "medium"},
		},
	}

	b.Process(ev3, provenance.TaintInfo{})
	snap = g.Snapshot()
	if got, want := len(snap.Alerts), 2; got != want {
		t.Fatalf("expected %d alerts after second category, got %d", want, got)
	}
}
