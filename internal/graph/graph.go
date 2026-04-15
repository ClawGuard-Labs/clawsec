//go:build linux

// Package graph maintains an in-memory provenance graph and broadcasts
// incremental diffs to SSE subscribers.
//
// # Data model
//
// Three node types:
//   - process  — a running PID/comm  (circle in the UI)
//   - file     — a file path         (rectangle)
//   - network  — an external IP:port (diamond)
//
// Directed edge types:
//   - spawned   — parent process exec'd a child  (process → process)
//   - wrote     — process write-opened a file    (process → file)
//   - read      — process read-opened a file     (process → file)
//   - connected — process connected to a host    (process → network)
//   - sourced   — file downloaded from a host    (network → file)
//
// Only tainted or alerted entities appear in the graph.
//
// # Thread safety
//
// All exported methods are safe for concurrent use.
package graph

import (
	"fmt"
	"sync"
	"time"
)

// ─── node / edge types ───────────────────────────────────────────────────────

// NodeType classifies a graph vertex.
type NodeType string

const (
	NodeProcess NodeType = "process"
	NodeFile    NodeType = "file"
	NodeNetwork NodeType = "network"
)

// EdgeType classifies a directed arc.
type EdgeType string

const (
	EdgeSpawned   EdgeType = "spawned"   // process → process (exec)
	EdgeWrote     EdgeType = "wrote"     // process → file   (write-open)
	EdgeRead      EdgeType = "read"      // process → file   (read-open)
	EdgeConnected EdgeType = "connected" // process → network
	EdgeSourced   EdgeType = "sourced"   // network → file   (download)
)

// ─── public types ────────────────────────────────────────────────────────────

// Node is a vertex in the provenance graph.
type Node struct {
	ID        string                 `json:"id"`
	Type      NodeType               `json:"type"`
	Label     string                 `json:"label"`
	IsTainted bool                   `json:"is_tainted"`
	RiskScore int                    `json:"risk_score"`
	Tags      []string               `json:"tags"`
	SessionID string                 `json:"session_id,omitempty"`
	Meta      map[string]interface{} `json:"meta,omitempty"`
	FirstSeen time.Time              `json:"first_seen"`
	LastSeen  time.Time              `json:"last_seen"`
}

// Edge is a directed arc in the provenance graph.
type Edge struct {
	ID      string    `json:"id"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	Type    EdgeType  `json:"type"`
	Tainted bool      `json:"tainted"`
	At      time.Time `json:"at"`
}

// Alert captures a security finding associated with one or more graph nodes.
type Alert struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	RiskScore int       `json:"risk_score"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	NodeIDs   []string  `json:"node_ids"`
	SessionID string    `json:"session_id,omitempty"`
	At        time.Time `json:"at"`
}

// GraphDiff is the incremental update streamed to UI subscribers via SSE.
// Each field is omitted from JSON when empty to keep the wire payload small.
type GraphDiff struct {
	AddedNodes     []*Node  `json:"added_nodes,omitempty"`
	UpdatedNodes   []*Node  `json:"updated_nodes,omitempty"`
	AddedEdges     []*Edge  `json:"added_edges,omitempty"`
	RemovedNodeIDs []string `json:"removed_node_ids,omitempty"`
	RemovedEdgeIDs []string `json:"removed_edge_ids,omitempty"`
	Alerts         []*Alert `json:"alerts,omitempty"`
}

// IsEmpty reports whether the diff carries no changes.
func (d *GraphDiff) IsEmpty() bool {
	return len(d.AddedNodes) == 0 && len(d.UpdatedNodes) == 0 &&
		len(d.AddedEdges) == 0 && len(d.RemovedNodeIDs) == 0 &&
		len(d.RemovedEdgeIDs) == 0 && len(d.Alerts) == 0
}

// Snapshot is a full graph export returned by the REST endpoint GET /api/graph.
type Snapshot struct {
	Nodes  []*Node  `json:"nodes"`
	Edges  []*Edge  `json:"edges"`
	Alerts []*Alert `json:"alerts"`
}

// ─── Graph ────────────────────────────────────────────────────────────────────

// Graph is the central in-memory provenance graph.
type Graph struct {
	mu     sync.RWMutex
	nodes  map[string]*Node
	edges  map[string]*Edge
	alerts []*Alert

	subsMu sync.Mutex
	subs   []chan GraphDiff
}

// New returns a ready, empty Graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
	}
}

// Subscribe returns a buffered channel that receives every GraphDiff produced
// after the call. The channel buffer holds 64 diffs; slow consumers lose diffs
// (non-blocking send). Close with Unsubscribe when done.
func (g *Graph) Subscribe() <-chan GraphDiff {
	ch := make(chan GraphDiff, 64)
	g.subsMu.Lock()
	g.subs = append(g.subs, ch)
	g.subsMu.Unlock()
	return ch
}

// Unsubscribe removes and closes the subscription channel returned by Subscribe.
func (g *Graph) Unsubscribe(ch <-chan GraphDiff) {
	g.subsMu.Lock()
	defer g.subsMu.Unlock()
	for i, c := range g.subs {
		if c == ch {
			g.subs = append(g.subs[:i], g.subs[i+1:]...)
			close(c)
			return
		}
	}
}

// Snapshot returns a point-in-time deep copy of all nodes, edges, and alerts.
func (g *Graph) Snapshot() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		cp := *n
		nodes = append(nodes, &cp)
	}
	edges := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		cp := *e
		edges = append(edges, &cp)
	}
	alerts := make([]*Alert, len(g.alerts))
	copy(alerts, g.alerts)

	return Snapshot{Nodes: nodes, Edges: edges, Alerts: alerts}
}

// broadcast sends diff to all subscribers without blocking.
// Must NOT be called with g.mu held.
func (g *Graph) broadcast(diff GraphDiff) {
	g.subsMu.Lock()
	defer g.subsMu.Unlock()
	for _, ch := range g.subs {
		select {
		case ch <- diff:
		default: // slow consumer; skip this diff
		}
	}
}

// ─── internal helpers (called with g.mu write-locked) ────────────────────────

// upsertNode inserts or updates a node.
//
// Returns:
//   - (copy, true)  — node was newly added; caller should add to AddedNodes
//   - (copy, false) — node existed and was changed; caller → UpdatedNodes
//   - (nil,  false) — node existed and was unchanged; nothing to broadcast
func (g *Graph) upsertNode(
	id string, typ NodeType, label string,
	tainted bool, score int,
	sessionID string, meta map[string]interface{}, tags []string,
	now time.Time,
) (*Node, bool) {
	if existing, ok := g.nodes[id]; ok {
		changed := false

		if tainted && !existing.IsTainted {
			existing.IsTainted = true
			changed = true
		}
		if score > existing.RiskScore {
			existing.RiskScore = score
			changed = true
		}
		existing.LastSeen = now

		// Merge new tags
		tagSet := make(map[string]struct{}, len(existing.Tags))
		for _, t := range existing.Tags {
			tagSet[t] = struct{}{}
		}
		for _, t := range tags {
			if _, seen := tagSet[t]; !seen {
				existing.Tags = append(existing.Tags, t)
				changed = true
			}
		}

		// Merge new meta keys
		if meta != nil {
			if existing.Meta == nil {
				existing.Meta = make(map[string]interface{})
			}
			for k, v := range meta {
				if _, exists := existing.Meta[k]; !exists {
					existing.Meta[k] = v
					changed = true
				}
			}
		}

		if !changed {
			return nil, false
		}
		cp := *existing
		return &cp, false
	}

	n := &Node{
		ID:        id,
		Type:      typ,
		Label:     label,
		IsTainted: tainted,
		RiskScore: score,
		Tags:      tags,
		SessionID: sessionID,
		Meta:      meta,
		FirstSeen: now,
		LastSeen:  now,
	}
	g.nodes[id] = n
	cp := *n
	return &cp, true
}

// ensureEdge creates an edge if one with the same (src, type, dst) tuple does
// not already exist. Returns (edge, true) when newly created, (nil, false) when
// the edge was already present.
func (g *Graph) ensureEdge(src, dst string, typ EdgeType, tainted bool, at time.Time) (*Edge, bool) {
	id := fmt.Sprintf("%s--%s--%s", src, string(typ), dst)
	if _, ok := g.edges[id]; ok {
		return nil, false
	}
	e := &Edge{ID: id, Src: src, Dst: dst, Type: typ, Tainted: tainted, At: at}
	g.edges[id] = e
	cp := *e
	return &cp, true
}

// removeNode deletes a node and all edges that reference it.
// Returns the IDs of removed edges. Caller must hold g.mu write lock.
func (g *Graph) removeNode(id string) []string {
	delete(g.nodes, id)
	var removed []string
	for eid, e := range g.edges {
		if e.Src == id || e.Dst == id {
			delete(g.edges, eid)
			removed = append(removed, eid)
		}
	}
	return removed
}

// setNodeMeta overwrites a meta key on an existing node and returns a copy.
// Returns nil if the node does not exist. Caller must hold g.mu write lock.
func (g *Graph) setNodeMeta(id, key string, val interface{}) *Node {
	n, ok := g.nodes[id]
	if !ok {
		return nil
	}
	if n.Meta == nil {
		n.Meta = make(map[string]interface{})
	}
	n.Meta[key] = val
	cp := *n
	return &cp
}

// setNodeSeenRange sets FirstSeen and LastSeen from aggregated bounds (min first,
// max last) after chain compaction. Zero values leave that field unchanged.
// Caller must hold g.mu write lock.
func (g *Graph) setNodeSeenRange(id string, first, last time.Time) {
	n, ok := g.nodes[id]
	if !ok {
		return
	}
	if !first.IsZero() {
		n.FirstSeen = first
	}
	if !last.IsZero() {
		n.LastSeen = last
	}
}

// storeAlert appends an alert to g.alerts. Caller holds g.mu.
func (g *Graph) storeAlert(a *Alert) {
	g.alerts = append(g.alerts, a)
}
