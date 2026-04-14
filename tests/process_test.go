package tests

import (
	"testing"
	"time"

	"github.com/onyx/internal/consumer"
	"github.com/onyx/internal/correlator"
	"github.com/onyx/internal/detector"
)

func TestAIProcess(t *testing.T) {
	tpl := findTemplate(t, "ai_process")
	lg := categoryLogger("process")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: exec of python (AI process)",
			event: newExecEvent("python", "/usr/bin/python3", "python3 train.py", true),
			want:  true,
		},
		{
			name:  "positive: exec of ollama (AI process)",
			event: newExecEvent("ollama", "/usr/local/bin/ollama", "ollama serve", true),
			want:  true,
		},
		{
			name:  "negative: exec of cat (not AI)",
			event: newExecEvent("cat", "/usr/bin/cat", "cat /etc/hosts", false),
			want:  false,
		},
		{
			name:  "negative: exec of bash (not AI)",
			event: newExecEvent("bash", "/bin/bash", "bash", false),
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Evaluate(tpl, tc.event, nil)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAISpawnedShell(t *testing.T) {
	tpl := findTemplate(t, "ai_spawned_shell")
	lg := categoryLogger("process")

	aiEvent := &consumer.EnrichedEvent{
		Timestamp:   time.Now(),
		EventType:   "exec",
		Pid:         1000,
		Comm:        "python",
		IsAIProcess: true,
		Tags:        []string{},
	}

	sessWithAI := newSession([]*consumer.EnrichedEvent{aiEvent}, nil)
	sessNoAI := newSession(nil, nil)

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		sess  *correlator.Session
		want  bool
	}{
		{
			name:  "positive: bash exec in AI session",
			event: newExecEvent("bash", "/bin/bash", "bash -c 'ls'", false),
			sess:  sessWithAI,
			want:  true,
		},
		{
			name:  "positive: sh exec in AI session",
			event: newExecEvent("sh", "/bin/sh", "sh -c 'whoami'", false),
			sess:  sessWithAI,
			want:  true,
		},
		{
			name:  "positive: zsh exec in AI session",
			event: newExecEvent("zsh", "/bin/zsh", "zsh", false),
			sess:  sessWithAI,
			want:  true,
		},
		{
			name:  "negative: bash exec without AI in session",
			event: newExecEvent("bash", "/bin/bash", "bash", false),
			sess:  sessNoAI,
			want:  false,
		},
		{
			name:  "negative: non-shell exec in AI session",
			event: newExecEvent("ls", "/usr/bin/ls", "ls -la", false),
			sess:  sessWithAI,
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Evaluate(tpl, tc.event, tc.sess)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
