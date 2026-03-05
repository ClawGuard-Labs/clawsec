package graph

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ai-agent-monitor/internal/consumer"
	"github.com/ai-agent-monitor/internal/provenance"
)

// Builder converts enriched events + taint information into graph mutations.
// Create one Builder per Graph.
type Builder struct {
	g       *Graph
	alertID uint64 // atomically incremented
}

// NewBuilder returns a Builder wired to g.
func NewBuilder(g *Graph) *Builder {
	return &Builder{g: g}
}

// Process inspects ev and taint and applies the resulting graph mutations.
// It is a no-op when the event carries neither taint nor detections.
//
// Called from the main event loop; must not block.
func (b *Builder) Process(ev *consumer.EnrichedEvent, taint provenance.TaintInfo) {
	if !taint.IsTainted && len(ev.Tags) == 0 && ev.NucleiResult == nil {
		return
	}

	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	diff := GraphDiff{}

	// Acquire write lock for the entire mutation so Snapshot() never sees a
	// half-built state.
	b.g.mu.Lock()

	// ── Process node ─────────────────────────────────────────────────────
	procID := fmt.Sprintf("proc:%d", ev.Pid)
	procLabel := ev.Comm
	if procLabel == "" {
		procLabel = fmt.Sprintf("pid:%d", ev.Pid)
	}

	procMeta := map[string]interface{}{
		"pid":  ev.Pid,
		"ppid": ev.Ppid,
		"comm": ev.Comm,
	}
	if ev.Binary != "" {
		procMeta["binary"] = ev.Binary
	}
	if ev.Cmdline != "" {
		procMeta["cmdline"] = ev.Cmdline
	}
	if taint.TaintReason != "" {
		procMeta["taint_reason"] = taint.TaintReason
	}
	if taint.SourceIP != "" {
		procMeta["taint_source"] = fmt.Sprintf("%s:%d", taint.SourceIP, taint.SourcePort)
	}

	tags := make([]string, len(ev.Tags))
	copy(tags, ev.Tags)

	procNode, procNew := b.g.upsertNode(procID, NodeProcess, procLabel,
		taint.IsTainted, ev.RiskScore, ev.AISessionID, procMeta, tags, now)
	if procNew {
		diff.AddedNodes = append(diff.AddedNodes, procNode)
	} else if procNode != nil {
		diff.UpdatedNodes = append(diff.UpdatedNodes, procNode)
	}

	// ── Parent process node + spawned edge (exec events only) ────────────
	if ev.EventType == "exec" && ev.Ppid != 0 {
		parentID := fmt.Sprintf("proc:%d", ev.Ppid)
		parentLabel := ev.ParentComm
		if parentLabel == "" {
			parentLabel = fmt.Sprintf("pid:%d", ev.Ppid)
		}
		parentMeta := map[string]interface{}{
			"pid":  ev.Ppid,
			"comm": ev.ParentComm,
		}
		pNode, pNew := b.g.upsertNode(parentID, NodeProcess, parentLabel,
			false, 0, ev.AISessionID, parentMeta, nil, now)
		if pNew {
			diff.AddedNodes = append(diff.AddedNodes, pNode)
		} else if pNode != nil {
			diff.UpdatedNodes = append(diff.UpdatedNodes, pNode)
		}

		if e, isNew := b.g.ensureEdge(parentID, procID, EdgeSpawned, taint.IsTainted, now); isNew {
			diff.AddedEdges = append(diff.AddedEdges, e)
		}
	}

	// ── File node + read / write edges ────────────────────────────────────
	// Only create a file node when the file is genuinely interesting:
	//   • it was downloaded from the network (tainted file)
	//   • it is a model file (e.g. .gguf, .safetensors)
	// Skipping every /proc/, locale, and library read prevents the
	// graph from exploding with hundreds of system-noise nodes.
	if ev.FilePath != "" &&
		(ev.EventType == "file_open" || ev.EventType == "file_rw") {

		fileTainted := taint.TaintedFile == ev.FilePath
		isModelFile := ev.ModelDetected != ""

		if fileTainted || isModelFile {
			fileID := "file:" + ev.FilePath

			fileNode, fileNew := b.g.upsertNode(fileID, NodeFile, ev.FilePath,
				fileTainted, 0, "", nil, nil, now)
			if fileNew {
				diff.AddedNodes = append(diff.AddedNodes, fileNode)
			} else if fileNode != nil {
				diff.UpdatedNodes = append(diff.UpdatedNodes, fileNode)
			}

			edgeType := EdgeRead
			if isWriteFlags(ev.FileFlags) {
				edgeType = EdgeWrote
			}
			if e, isNew := b.g.ensureEdge(procID, fileID, edgeType, taint.IsTainted, now); isNew {
				diff.AddedEdges = append(diff.AddedEdges, e)
			}

			// If the file was downloaded from the network, add a network→file edge.
			if fileTainted && taint.SourceIP != "" {
				netID := fmt.Sprintf("net:%s:%d", taint.SourceIP, taint.SourcePort)
				netLabel := fmt.Sprintf("%s:%d", taint.SourceIP, taint.SourcePort)
				netNode, netNew := b.g.upsertNode(netID, NodeNetwork, netLabel,
					true, 0, taint.ChainSession, nil, nil, now)
				if netNew {
					diff.AddedNodes = append(diff.AddedNodes, netNode)
				} else if netNode != nil {
					diff.UpdatedNodes = append(diff.UpdatedNodes, netNode)
				}
				if e, isNew := b.g.ensureEdge(netID, fileID, EdgeSourced, true, now); isNew {
					diff.AddedEdges = append(diff.AddedEdges, e)
				}
			}
		}
	}

	// ── Network node + connected edge ─────────────────────────────────────
	if ev.EventType == "net_connect" && ev.Network != nil {
		netID := fmt.Sprintf("net:%s:%d", ev.Network.DstIP, ev.Network.DstPort)
		netLabel := fmt.Sprintf("%s:%d", ev.Network.DstIP, ev.Network.DstPort)
		netNode, netNew := b.g.upsertNode(netID, NodeNetwork, netLabel,
			false, 0, ev.AISessionID, nil, nil, now)
		if netNew {
			diff.AddedNodes = append(diff.AddedNodes, netNode)
		} else if netNode != nil {
			diff.UpdatedNodes = append(diff.UpdatedNodes, netNode)
		}
		if e, isNew := b.g.ensureEdge(procID, netID, EdgeConnected, taint.IsTainted, now); isNew {
			diff.AddedEdges = append(diff.AddedEdges, e)
		}
	}

	// ── Alerts for matched detection rules ────────────────────────────────
	for _, rule := range ev.MatchedRules {
		a := b.newAlert(
			rule.Severity,
			fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
			fmt.Sprintf("Process %s (pid %d) triggered rule %q", ev.Comm, ev.Pid, rule.ID),
			[]string{procID},
			ev.AISessionID,
			now,
		)
		b.g.storeAlert(a)
		diff.Alerts = append(diff.Alerts, a)
	}

	// ── Alert for Nuclei findings ─────────────────────────────────────────
	if ev.NucleiResult != nil {
		a := b.newAlert(
			ev.NucleiResult.Severity,
			fmt.Sprintf("[nuclei] %s", ev.NucleiResult.Name),
			ev.NucleiResult.Description,
			[]string{procID},
			ev.AISessionID,
			now,
		)
		b.g.storeAlert(a)
		diff.Alerts = append(diff.Alerts, a)
	}

	b.g.mu.Unlock()

	// Broadcast outside the write lock so subscribers never observe a deadlock
	// path (they may call Snapshot which acquires the read lock).
	if !diff.IsEmpty() {
		b.g.broadcast(diff)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (b *Builder) newAlert(severity, title, detail string, nodeIDs []string, sessionID string, at time.Time) *Alert {
	id := fmt.Sprintf("alert:%d", atomic.AddUint64(&b.alertID, 1))
	return &Alert{
		ID:        id,
		Severity:  severity,
		Title:     title,
		Detail:    detail,
		NodeIDs:   nodeIDs,
		SessionID: sessionID,
		At:        at,
	}
}

// isWriteFlags mirrors the logic from provenance/tracker.go.
// O_WRONLY=0x1, O_RDWR=0x2, O_CREAT=0x40.
func isWriteFlags(flags uint32) bool {
	return flags&0x1 != 0 || flags&0x2 != 0 || flags&0x40 != 0
}
