//go:build linux

package graph

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClawGuard-Labs/akmon/internal/chagg"
	"github.com/ClawGuard-Labs/akmon/internal/constants"
	"github.com/ClawGuard-Labs/akmon/internal/consumer"
	"github.com/ClawGuard-Labs/akmon/internal/provenance"
)

// liveChain tracks a spawned-edge path from a parent for chain-wise compaction.
type liveChain struct {
	parentID string   // graph node ID the chain hangs off
	nodeIDs  []string // ordered: child, grandchild, …, leaf
	comms    []string
	cmdlines []string
	lastEdge time.Time
	count    int
	removed  bool
}

// Builder converts enriched events + taint information into graph mutations.
// Create one Builder per Graph.
type Builder struct {
	g       *Graph
	chagg   *chagg.Aggregator
	alertID uint64 // atomically incremented

	compact      bool
	compactIdle  time.Duration
	chains       []*liveChain
	leafToChain  map[string]*liveChain
	parentChains map[string][]*liveChain

	// alertDedup suppresses near-simultaneous duplicate alerts for the same PID
	// and alert category (rule/template ID). This prevents alert spam when multiple
	// events trigger the same category concurrently for a single process.
	//
	// Key format: "<pid>|<category>"
	alertDedup       map[string]time.Time
	alertDedupWindow time.Duration
}

// NewBuilder returns a Builder wired to g.
// agg may be nil when chain aggregation is disabled.
// When compact is true, the builder tracks spawned-edge chains and periodically
// merges identical chains from the same parent, removing duplicates from the graph.
func NewBuilder(g *Graph, agg *chagg.Aggregator, compact bool, compactIdle time.Duration) *Builder {
	b := &Builder{
		g:           g,
		chagg:       agg,
		compact:     compact,
		compactIdle: compactIdle,
		// Default: suppress duplicates that arrive within this window.
		// This matches the "same timestamp / nearly the same time" spam scenario.
		alertDedupWindow: 1 * time.Second,
		alertDedup:       make(map[string]time.Time),
	}
	if compact {
		b.leafToChain = make(map[string]*liveChain)
		b.parentChains = make(map[string][]*liveChain)
	}
	return b
}

// shouldEmitAlert reports whether an alert for (pid, category) should be emitted
// at the given time. When an alert is emitted, the category becomes "active" for
// alertDedupWindow to prevent concurrent duplicates.
//
// Caller must hold b.g.mu.
func (b *Builder) shouldEmitAlert(pid uint32, category string, now time.Time) bool {
	if category == "" {
		return true
	}
	key := fmt.Sprintf("%d|%s", pid, category)
	if last, ok := b.alertDedup[key]; ok {
		if now.Sub(last) < b.alertDedupWindow {
			return false
		}
	}
	b.alertDedup[key] = now

	// Opportunistic GC to keep the map bounded.
	// Remove entries older than 10× the window.
	cutoff := now.Add(-10 * b.alertDedupWindow)
	for k, t := range b.alertDedup {
		if t.Before(cutoff) {
			delete(b.alertDedup, k)
		}
	}
	return true
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
		if b.chagg != nil {
			b.chagg.TrackEdge(procID, ev.ParentComm, ev.Comm, ev.Cmdline, ev.Pid, ev.Uid, ev.AISessionID, string(EdgeSpawned), ev.Comm)
		}
		if b.compact {
			b.trackSpawnedEdge(parentID, procID, ev.Comm, ev.Cmdline, now)
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
			if constants.IsWriteOpen(ev.FileFlags) {
				edgeType = EdgeWrote
			}
			if e, isNew := b.g.ensureEdge(procID, fileID, edgeType, taint.IsTainted, now); isNew {
				diff.AddedEdges = append(diff.AddedEdges, e)
			}
			if b.chagg != nil {
				b.chagg.TrackEdge(procID, ev.ParentComm, ev.Comm, ev.Cmdline, ev.Pid, ev.Uid, ev.AISessionID, string(edgeType), ev.FilePath)
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
				if b.chagg != nil {
					b.chagg.TrackEdge(procID, ev.ParentComm, ev.Comm, ev.Cmdline, ev.Pid, ev.Uid, ev.AISessionID, string(EdgeSourced), ev.FilePath)
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
		if b.chagg != nil {
			b.chagg.TrackEdge(procID, ev.ParentComm, ev.Comm, ev.Cmdline, ev.Pid, ev.Uid, ev.AISessionID, string(EdgeConnected), netLabel)
		}
	}

	// ── Alerts for matched detection rules ────────────────────────────────
	for _, rule := range ev.MatchedRules {
		if !b.shouldEmitAlert(ev.Pid, rule.ID, now) {
			continue
		}
		a := b.newAlert(
			rule.Severity,
			ev.RiskScore,
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
		category := "nuclei:" + ev.NucleiResult.TemplateID
		if category == "nuclei:" {
			category = "nuclei:" + ev.NucleiResult.Name
		}
		if b.shouldEmitAlert(ev.Pid, category, now) {
			a := b.newAlert(
				ev.NucleiResult.Severity,
				constants.SeverityScore(ev.NucleiResult.Severity),
				fmt.Sprintf("[nuclei] %s", ev.NucleiResult.Name),
				ev.NucleiResult.Description,
				[]string{procID},
				ev.AISessionID,
				now,
			)
			b.g.storeAlert(a)
			diff.Alerts = append(diff.Alerts, a)
		}
	}

	b.g.mu.Unlock()

	// Broadcast outside the write lock so subscribers never observe a deadlock
	// path (they may call Snapshot which acquires the read lock).
	if !diff.IsEmpty() {
		b.g.broadcast(diff)
	}
}

func (b *Builder) newAlert(severity string, riskScore int, title, detail string, nodeIDs []string, sessionID string, at time.Time) *Alert {
	id := fmt.Sprintf("alert:%d", atomic.AddUint64(&b.alertID, 1))
	return &Alert{
		ID:        id,
		Severity:  severity,
		RiskScore: riskScore,
		Title:     title,
		Detail:    detail,
		NodeIDs:   nodeIDs,
		SessionID: sessionID,
		At:        at,
	}
}

// ── Chain-wise compaction ────────────────────────────────────────────────────

// trackSpawnedEdge records a spawned edge for chain compaction.
// Caller must hold b.g.mu.
func (b *Builder) trackSpawnedEdge(parentID, procID, comm, cmdline string, now time.Time) {
	if chain, ok := b.leafToChain[parentID]; ok {
		delete(b.leafToChain, parentID)
		chain.nodeIDs = append(chain.nodeIDs, procID)
		chain.comms = append(chain.comms, comm)
		chain.cmdlines = append(chain.cmdlines, cmdline)
		chain.lastEdge = now
		chain.count = 1 // reset — signature changed due to extension
		b.leafToChain[procID] = chain
	} else {
		chain := &liveChain{
			parentID: parentID,
			nodeIDs:  []string{procID},
			comms:    []string{comm},
			cmdlines: []string{cmdline},
			lastEdge: now,
			count:    1,
		}
		b.chains = append(b.chains, chain)
		b.leafToChain[procID] = chain
		b.parentChains[parentID] = append(b.parentChains[parentID], chain)
	}
}

func chainSignature(c *liveChain) string {
	var sb strings.Builder
	for i := range c.comms {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(c.comms[i])
		sb.WriteByte(':')
		sb.WriteString(c.cmdlines[i])
	}
	return sb.String()
}

func foldEarliest(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.Before(a) {
		return b
	}
	return a
}

func foldLatest(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.After(a) {
		return b
	}
	return a
}

// StartCompaction runs a background goroutine that periodically sweeps idle
// chains and merges identical ones. Call when --compact is enabled.
func (b *Builder) StartCompaction(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			b.sweepChains()
		}
	}
}

func (b *Builder) sweepChains() {
	if !b.compact {
		return
	}

	cutoff := time.Now().Add(-b.compactIdle)

	b.g.mu.Lock()

	type gk struct{ parentID, sig string }
	groups := map[gk][]*liveChain{}

	for _, c := range b.chains {
		if c.removed || c.lastEdge.After(cutoff) {
			continue
		}
		sig := chainSignature(c)
		key := gk{c.parentID, sig}
		groups[key] = append(groups[key], c)
	}

	diff := GraphDiff{}

	for _, chains := range groups {
		if len(chains) < 2 {
			continue
		}

		surviving := chains[0]
		totalCount := 0
		for _, c := range chains {
			totalCount += c.count
		}
		surviving.count = totalCount

		for i, nodeID := range surviving.nodeIDs {
			var minFirst, maxLast time.Time
			for _, ch := range chains {
				if i >= len(ch.nodeIDs) {
					continue
				}
				n := b.g.nodes[ch.nodeIDs[i]]
				if n == nil {
					continue
				}
				minFirst = foldEarliest(minFirst, n.FirstSeen)
				maxLast = foldLatest(maxLast, n.LastSeen)
			}
			b.g.setNodeSeenRange(nodeID, minFirst, maxLast)
			if cp := b.g.setNodeMeta(nodeID, "count", totalCount); cp != nil {
				diff.UpdatedNodes = append(diff.UpdatedNodes, cp)
			}
		}

		for i := 1; i < len(chains); i++ {
			dup := chains[i]
			for _, nodeID := range dup.nodeIDs {
				removedEdges := b.g.removeNode(nodeID)
				diff.RemovedNodeIDs = append(diff.RemovedNodeIDs, nodeID)
				diff.RemovedEdgeIDs = append(diff.RemovedEdgeIDs, removedEdges...)
				delete(b.leafToChain, nodeID)
			}
			dup.removed = true
		}
	}
	alive := b.chains[:0]
	for _, c := range b.chains {
		if !c.removed {
			alive = append(alive, c)
		}
	}
	b.chains = alive

	for pid, pchains := range b.parentChains {
		ap := pchains[:0]
		for _, c := range pchains {
			if !c.removed {
				ap = append(ap, c)
			}
		}
		if len(ap) == 0 {
			delete(b.parentChains, pid)
		} else {
			b.parentChains[pid] = ap
		}
	}

	b.g.mu.Unlock()

	if !diff.IsEmpty() {
		b.g.broadcast(diff)
	}
}
