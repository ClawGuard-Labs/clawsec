package tests

import (
	"testing"
	"time"

	"github.com/clawsec/internal/consumer"
	"github.com/clawsec/internal/detector"
)

func TestReadWriteLoop(t *testing.T) {
	tpl := findTemplate(t, "read_write_loop")
	lg := categoryLogger("session")

	aiEvent := &consumer.EnrichedEvent{
		Timestamp:   time.Now(),
		EventType:   "exec",
		Pid:         1000,
		Comm:        "python",
		IsAIProcess: true,
		Tags:        []string{},
	}

	otherRW := &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: "file_rw",
		Pid:       1000,
		Comm:      "python",
		FilePath:  "/data/output.csv",
		Tags:      []string{},
	}

	cases := []struct {
		name   string
		event  *consumer.EnrichedEvent
		events []*consumer.EnrichedEvent
		want   bool
	}{
		{
			name:   "positive: file_rw with another file_rw on different path in AI session",
			event:  newFileEvent("file_rw", "/data/input.csv", "python"),
			events: []*consumer.EnrichedEvent{aiEvent, otherRW},
			want:   true,
		},
		{
			name:   "negative: file_rw but no other file_rw in session",
			event:  newFileEvent("file_rw", "/data/input.csv", "python"),
			events: []*consumer.EnrichedEvent{aiEvent},
			want:   false,
		},
		{
			name:   "negative: file_rw with other file_rw but no AI in session",
			event:  newFileEvent("file_rw", "/data/input.csv", "python"),
			events: []*consumer.EnrichedEvent{otherRW},
			want:   false,
		},
		{
			name:   "negative: wrong event type",
			event:  newFileEvent("file_open", "/data/input.csv", "python"),
			events: []*consumer.EnrichedEvent{aiEvent, otherRW},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession(tc.events, nil)
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-60s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLongRunningLLM(t *testing.T) {
	tpl := findTemplate(t, "long_running_llm")
	lg := categoryLogger("session")

	cases := []struct {
		name      string
		event     *consumer.EnrichedEvent
		createdAt time.Time
		want      bool
	}{
		{
			name:      "positive: AI process in session older than 5 minutes",
			event:     newExecEvent("python", "/usr/bin/python3", "python3 serve.py", true),
			createdAt: time.Now().Add(-10 * time.Minute),
			want:      true,
		},
		{
			name:      "negative: AI process in fresh session (< 5 min)",
			event:     newExecEvent("python", "/usr/bin/python3", "python3 serve.py", true),
			createdAt: time.Now().Add(-1 * time.Minute),
			want:      false,
		},
		{
			name:      "negative: non-AI process in old session",
			event:     newExecEvent("cat", "/usr/bin/cat", "cat file.txt", false),
			createdAt: time.Now().Add(-10 * time.Minute),
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession(nil, nil)
			sess.CreatedAt = tc.createdAt
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-60s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCurlBashChain(t *testing.T) {
	tpl := findTemplate(t, "curl_bash_chain")
	lg := categoryLogger("session")

	curlExec := &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: "exec",
		Pid:       1001,
		Comm:      "curl",
		Binary:    "/usr/bin/curl",
		Tags:      []string{},
	}

	wgetExec := &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: "exec",
		Pid:       1001,
		Comm:      "wget",
		Binary:    "/usr/bin/wget",
		Tags:      []string{},
	}

	cases := []struct {
		name   string
		event  *consumer.EnrichedEvent
		events []*consumer.EnrichedEvent
		want   bool
	}{
		{
			name:   "positive: bash after curl in session",
			event:  newExecEvent("bash", "/bin/bash", "bash -c 'malicious'", false),
			events: []*consumer.EnrichedEvent{curlExec},
			want:   true,
		},
		{
			name:   "positive: sh after wget in session",
			event:  newExecEvent("sh", "/bin/sh", "sh payload.sh", false),
			events: []*consumer.EnrichedEvent{wgetExec},
			want:   true,
		},
		{
			name:   "negative: bash in clean session (no curl/wget)",
			event:  newExecEvent("bash", "/bin/bash", "bash", false),
			events: nil,
			want:   false,
		},
		{
			name:   "negative: non-shell after curl",
			event:  newExecEvent("ls", "/usr/bin/ls", "ls -la", false),
			events: []*consumer.EnrichedEvent{curlExec},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession(tc.events, nil)
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-60s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDownloadExec(t *testing.T) {
	tpl := findTemplate(t, "download_exec")
	lg := categoryLogger("session")

	cases := []struct {
		name         string
		event        *consumer.EnrichedEvent
		execAfterNet bool
		lastNetTime  time.Time
		want         bool
	}{
		{
			name:         "positive: exec shortly after net_connect",
			event:        newExecEvent("agent", "/tmp/agent", "./agent", false),
			execAfterNet: true,
			lastNetTime:  time.Now().Add(-5 * time.Second),
			want:         true,
		},
		{
			name:         "negative: exec_after_net false",
			event:        newExecEvent("agent", "/tmp/agent", "./agent", false),
			execAfterNet: false,
			lastNetTime:  time.Now().Add(-5 * time.Second),
			want:         false,
		},
		{
			name:         "negative: exec_after_net true but net too old (> 30s)",
			event:        newExecEvent("agent", "/tmp/agent", "./agent", false),
			execAfterNet: true,
			lastNetTime:  time.Now().Add(-60 * time.Second),
			want:         false,
		},
		{
			name:         "negative: wrong event type",
			event:        newFileEvent("file_open", "/tmp/agent", "agent"),
			execAfterNet: true,
			lastNetTime:  time.Now().Add(-5 * time.Second),
			want:         false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession(nil, nil)
			sess.ExecAfterNet = tc.execAfterNet
			sess.LastNetTime = tc.lastNetTime
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-60s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
