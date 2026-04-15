//go:build linux

// Package chagg implements chain aggregation — deduplication of repetitive
// graph edge patterns into counted chains.
//
// A "chain" is an ordered sequence of graph edge actions (spawned, read,
// connected, …) performed by processes with the same initiator and command
// line within one session. Identical chains are merged: only metadata and
// an occurrence count are kept, drastically reducing log volume.
package chagg

import "time"

// EdgeDetail describes one step in a chain.
// Type uses the existing graph.EdgeType values: "spawned", "wrote", "read",
// "connected", "sourced".
type EdgeDetail struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// Occurrence records one instance of a chain firing.
// session_id lives on the parent Chain — all occurrences share it.
type Occurrence struct {
	Seq       int       `json:"seq"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	Timestamp time.Time `json:"timestamp"`
}

// Chain is one unique edge-pattern with all its occurrences.
type Chain struct {
	SessionID       string       `json:"session_id"`
	Initiator       string       `json:"initiator"`
	Process         string       `json:"process"`
	CommandLine     string       `json:"command_line"`
	ChainPattern    string       `json:"chain_pattern"`
	EdgeDetails     []EdgeDetail `json:"edge_details"`
	OccurrenceCount int          `json:"occurrence_count"`
	FirstSeen       time.Time    `json:"first_seen"`
	LastSeen        time.Time    `json:"last_seen"`
	Occurrences     []Occurrence `json:"occurrences"`
}

// pendingChain tracks in-progress edge accumulation for a single process.
// It is finalized into a Chain after the idle window expires.
type pendingChain struct {
	procID        string
	initiatorComm string
	comm          string
	cmdline       string
	pid           uint32
	uid           uint32
	sessionID     string
	edges         []EdgeDetail
	startedAt     time.Time
	lastEdgeAt    time.Time
}

const maxOccurrences = 1000
