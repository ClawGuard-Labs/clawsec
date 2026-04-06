// Package consumer — raw eBPF event structs and ring-buffer decoder.
//
// These Go structs mirror the C structs in bpf/common.h EXACTLY —
// same field order, same sizes, same explicit padding.
// encoding/binary.Read deserialises ring-buffer bytes into them in one call.
//
// Rule: every field including padding must be EXPORTED so encoding/binary
// can write into it. Padding fields are named Pad0/Pad1/… and carry no
// semantic meaning.
//
// Size audit (must match C):
//   MonHdr        = 8+4+4+4+4+8+1+7+16         = 56 bytes
//   BPFExecEvent  = 56+256+(16×128)+4+4          = 2368 bytes
//   BPFFileEvent  = 56+256+4+4+8+4+4             = 336 bytes
//   BPFNetEvent   = 56+4+2+1+1+256+4+4           = 328 bytes
//   BPFTLSEvent   = 56+1024+4+4                  = 1088 bytes
package consumer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"github.com/clawsec/internal/aiprofile"
)

// ── Event-type constants (must match common.h) ────────────────────────────
const (
	EventExec       uint8 = 1
	EventFileOpen   uint8 = 2
	EventFileRW     uint8 = 3
	EventFileUnlink uint8 = 4
	EventFileMmap   uint8 = 5
	EventNetConnect uint8 = 6
	EventNetSend    uint8 = 7
	EventTLSSend    uint8 = 8
	EventTLSRecv    uint8 = 9
)

// ── Risk-flag constants (must match common.h) ─────────────────────────────
const (
	RFlagSensitive uint32 = 1 << 0
	RFlagLargeMmap uint32 = 1 << 1
	RFlagHTTP      uint32 = 1 << 2
)

// ══════════════════════════════════════════════════════════════════════════
//  RAW BPF STRUCTS (mirrors of C structs for binary decoding)
// ══════════════════════════════════════════════════════════════════════════

// MonHdr mirrors struct mon_hdr in bpf/common.h.
type MonHdr struct {
	TimestampNs uint64
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	CgroupId    uint64
	EventType   uint8
	Pad0        [7]byte
	Comm        [16]byte
}

// BPFExecEvent mirrors struct exec_event in bpf/common.h.
type BPFExecEvent struct {
	Hdr       MonHdr
	Filename  [256]byte
	Args      [16][128]byte
	ArgsCount uint32
	Pad0      uint32
}

// BPFFileEvent mirrors struct file_event in bpf/common.h.
type BPFFileEvent struct {
	Hdr       MonHdr
	Filepath  [256]byte
	Fd        uint32
	Flags     uint32
	ByteCount uint64
	Prot      uint32
	RiskFlags uint32
}

// BPFNetEvent mirrors struct net_event in bpf/common.h.
type BPFNetEvent struct {
	Hdr         MonHdr
	DstIp       uint32
	DstPort     uint16
	Protocol    uint8
	Pad0        uint8
	HttpPeek    [256]byte
	HttpPeekLen uint32
	RiskFlags   uint32
}

// BPFTLSEvent mirrors struct tls_event in bpf/common.h.
// Size: 56 + 1024 + 4 + 4 = 1088 bytes.
type BPFTLSEvent struct {
	Hdr        MonHdr
	Payload    [1024]byte
	PayloadLen uint32
	Pad0       uint32
}

// ══════════════════════════════════════════════════════════════════════════
//  ENRICHED EVENT — fully decoded, human-readable
// ══════════════════════════════════════════════════════════════════════════

// ProcessAncestor represents one node in the process ancestry chain.
// The chain in ProcessTree is ordered root → ... → direct parent.
type ProcessAncestor struct {
	Pid  uint32 `json:"pid"`
	Comm string `json:"comm,omitempty"`
}

// NetworkInfo holds parsed network connection details.
type NetworkInfo struct {
	DstIP      string `json:"dst_ip"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   string `json:"protocol"`
	HTTPMethod string `json:"http_method,omitempty"`
	URLPrefix  string `json:"url_prefix,omitempty"`
}

// MatchedRule captures the identifying metadata of a detection template that
// fired on this event. Stored in EnrichedEvent.MatchedRules so consumers can
// read rule names without resolving template IDs separately.
type MatchedRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// NucleiResult holds a finding produced by an active Nuclei scan that was
// triggered when our eBPF monitor detected a connection to a local AI service.
type NucleiResult struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	MatchedURL  string   `json:"matched_url,omitempty"`
	Service     string   `json:"service,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// EnrichedEvent is the fully decoded, correlated, and scored event
// that flows through the pipeline and is written to JSON output.
type EnrichedEvent struct {
	// ── Core identity ─────────────────────────────────────────────────
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Pid       uint32    `json:"pid"`
	Ppid      uint32    `json:"ppid"`
	Uid       uint32    `json:"uid"`
	CgroupID  uint64    `json:"cgroup_id"`
	Comm      string    `json:"comm"`

	// ── Process ancestry (populated by correlator) ────────────────────
	// ParentComm is the comm of the direct parent process.
	ParentComm string `json:"parent_comm,omitempty"`
	// ProcessTree is the PID ancestry chain from session root to the
	// direct parent: [root, ..., ppid]. The event's own Pid is NOT included.
	ProcessTree []ProcessAncestor `json:"process_tree,omitempty"`

	// ── Exec-specific ────────────────────────────────────────────────
	Binary  string   `json:"binary,omitempty"`
	Args    []string `json:"args,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`

	// ── File-specific ────────────────────────────────────────────────
	FilePath  string `json:"file_path,omitempty"`
	FileFlags uint32 `json:"file_flags,omitempty"`
	ByteCount uint64 `json:"byte_count,omitempty"`

	// ── Network-specific ─────────────────────────────────────────────
	Network *NetworkInfo `json:"network,omitempty"`

	// ── TLS plaintext-specific ────────────────────────────────────────
	// TLSPayload is the UTF-8 decoded plaintext payload peek.
	TLSPayload string `json:"tls_payload,omitempty"`
	// TLSPayloadLen is the total payload length (may exceed the peek window).
	TLSPayloadLen uint32 `json:"tls_payload_len,omitempty"`

	// ── Risk flags from eBPF (kernel-side classification) ────────────
	RiskFlags uint32 `json:"risk_flags,omitempty"`

	// ── Enrichment (set by correlator + detector) ─────────────────────
	AISessionID   string        `json:"ai_session_id"`
	ModelDetected string        `json:"model_detected,omitempty"`
	IsAIProcess   bool          `json:"is_ai_process,omitempty"`
	RiskScore     int           `json:"risk_score"`
	Tags          []string      `json:"tags"`
	MatchedRules  []MatchedRule `json:"matched_rules,omitempty"`

	// ── Nuclei active-scan finding (event_type == "nuclei_finding") ───
	// Populated only when a Nuclei scan triggered by this session fires.
	NucleiResult *NucleiResult `json:"nuclei_result,omitempty"`
}

// Decode turns raw ring-buffer bytes into an EnrichedEvent.
// It peeks at the event_type field (offset 32 in MonHdr) to determine
// which struct to decode into.
func Decode(raw []byte, cfg *aiprofile.Profile) (*EnrichedEvent, error) {
	if len(raw) < 33 {
		return nil, fmt.Errorf("raw event too short: %d bytes", len(raw))
	}

	// Peek at EventType without full decode
	eventType := raw[32]

	switch eventType {
	case EventExec:
		return decodeExec(raw, cfg)
	case EventFileOpen, EventFileRW, EventFileUnlink, EventFileMmap:
		return decodeFile(raw, eventType, cfg)
	case EventNetConnect, EventNetSend:
		return decodeNet(raw, eventType)
	case EventTLSSend, EventTLSRecv:
		return decodeTLS(raw, eventType)
	default:
		return nil, fmt.Errorf("unknown event type: %d", eventType)
	}
}

func decodeExec(raw []byte, cfg *aiprofile.Profile) (*EnrichedEvent, error) {
	var ev BPFExecEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("decoding exec event: %w", err)
	}

	comm := cStr(ev.Hdr.Comm[:])
	binary := cStr(ev.Filename[:])

	args := make([]string, 0, ev.ArgsCount)
	for i := uint32(0); i < ev.ArgsCount && i < 16; i++ {
		a := cStr(ev.Args[i][:])
		if a != "" {
			args = append(args, a)
		}
	}

	out := &EnrichedEvent{
		Timestamp: nsToTime(ev.Hdr.TimestampNs),
		EventType: "exec",
		Pid:       ev.Hdr.Pid,
		Ppid:      ev.Hdr.Ppid,
		Uid:       ev.Hdr.Uid,
		CgroupID:  ev.Hdr.CgroupId,
		Comm:      comm,
		Binary:    binary,
		Args:      args,
		Cmdline:   strings.Join(args, " "),
		Tags:      []string{},
	}
	if cfg.IsAIProcessComm(comm) {
		out.IsAIProcess = true
	}
	return out, nil
}

func decodeFile(raw []byte, eventType uint8, cfg *aiprofile.Profile) (*EnrichedEvent, error) {
	var ev BPFFileEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("decoding file event: %w", err)
	}

	filePath := cStr(ev.Filepath[:])
	typeStr := fileTypeStr(eventType)

	out := &EnrichedEvent{
		Timestamp: nsToTime(ev.Hdr.TimestampNs),
		EventType: typeStr,
		Pid:       ev.Hdr.Pid,
		Ppid:      ev.Hdr.Ppid,
		Uid:       ev.Hdr.Uid,
		CgroupID:  ev.Hdr.CgroupId,
		Comm:      cStr(ev.Hdr.Comm[:]),
		FilePath:  filePath,
		FileFlags: ev.Flags,
		ByteCount: ev.ByteCount,
		RiskFlags: ev.RiskFlags,
		Tags:      []string{},
	}
	out.ModelDetected = cfg.ModelBasenameIfMatch(filePath)
	return out, nil
}

func decodeNet(raw []byte, eventType uint8) (*EnrichedEvent, error) {
	var ev BPFNetEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("decoding net event: %w", err)
	}

	// Convert network-byte-order uint32 to dotted-decimal IP
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ev.DstIp)
	dstIP := net.IP(ipBytes).String()

	proto := protoStr(ev.Protocol)
	typeStr := "net_connect"
	if eventType == EventNetSend {
		typeStr = "net_send"
	}

	netInfo := &NetworkInfo{
		DstIP:    dstIP,
		DstPort:  ev.DstPort,
		Protocol: proto,
	}

	// Parse HTTP method and URL prefix from peek buffer
	if eventType == EventNetSend && ev.HttpPeekLen > 0 {
		peek := cStr(ev.HttpPeek[:ev.HttpPeekLen])
		parts := strings.SplitN(peek, " ", 3)
		if len(parts) >= 2 {
			netInfo.HTTPMethod = parts[0]
			netInfo.URLPrefix = parts[1]
		}
	}

	out := &EnrichedEvent{
		Timestamp: nsToTime(ev.Hdr.TimestampNs),
		EventType: typeStr,
		Pid:       ev.Hdr.Pid,
		Ppid:      ev.Hdr.Ppid,
		Uid:       ev.Hdr.Uid,
		CgroupID:  ev.Hdr.CgroupId,
		Comm:      cStr(ev.Hdr.Comm[:]),
		Network:   netInfo,
		RiskFlags: ev.RiskFlags,
		Tags:      []string{},
	}
	return out, nil
}

func decodeTLS(raw []byte, eventType uint8) (*EnrichedEvent, error) {
	var ev BPFTLSEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("decoding TLS event: %w", err)
	}

	typeStr := "tls_send"
	if eventType == EventTLSRecv {
		typeStr = "tls_recv"
	}

	// Determine valid payload slice: min(PayloadLen, 1024)
	payloadLen := ev.PayloadLen
	if payloadLen > 1024 {
		payloadLen = 1024
	}

	out := &EnrichedEvent{
		Timestamp:     nsToTime(ev.Hdr.TimestampNs),
		EventType:     typeStr,
		Pid:           ev.Hdr.Pid,
		Ppid:          ev.Hdr.Ppid,
		Uid:           ev.Hdr.Uid,
		CgroupID:      ev.Hdr.CgroupId,
		Comm:          cStr(ev.Hdr.Comm[:]),
		TLSPayload:    string(ev.Payload[:payloadLen]),
		TLSPayloadLen: ev.PayloadLen,
		Tags:          []string{},
	}
	return out, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────

// cStr converts a null-terminated C byte array to a Go string.
func cStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

// bootTime is the wall-clock time at system boot, computed once at package
// init by reading /proc/uptime. Zero value means the read failed and
// nsToTime will fall back to time.Now().
//
// Formula: bootTime = time.Now() − uptime
// Then:    wallTime = bootTime + Duration(kernelNs)
var bootTime = func() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	// /proc/uptime: "<uptime_seconds> <idle_seconds>"
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Time{}
	}
	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(uptimeSec * float64(time.Second))).UTC()
}()

// nsToTime converts a bpf_ktime_get_ns() nanosecond timestamp (CLOCK_MONOTONIC,
// nanoseconds since boot) to a wall-clock UTC time.
// Falls back to time.Now() if /proc/uptime was unreadable at startup.
func nsToTime(ns uint64) time.Time {
	if bootTime.IsZero() {
		return time.Now().UTC()
	}
	return bootTime.Add(time.Duration(ns)).UTC()
}

func fileTypeStr(t uint8) string {
	switch t {
	case EventFileOpen:
		return "file_open"
	case EventFileRW:
		return "file_rw"
	case EventFileUnlink:
		return "file_unlink"
	case EventFileMmap:
		return "file_mmap"
	default:
		return "file_unknown"
	}
}

func protoStr(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}
