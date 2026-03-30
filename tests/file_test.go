package tests

import (
	"testing"
	"time"

	"github.com/clawsec/internal/consumer"
	"github.com/clawsec/internal/detector"
)

func TestConfigAccess(t *testing.T) {
	tpl := findTemplate(t, "config_access")
	lg := categoryLogger("file")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_open on .yaml",
			event: newFileEvent("file_open", "/app/config.yaml", "python"),
			want:  true,
		},
		{
			name:  "positive: file_rw on .env",
			event: newFileEvent("file_rw", "/home/user/.env", "node"),
			want:  true,
		},
		{
			name:  "positive: file_open on .toml",
			event: newFileEvent("file_open", "/etc/app/settings.toml", "python3"),
			want:  true,
		},
		{
			name:  "negative: file_open on .bin (not a config extension)",
			event: newFileEvent("file_open", "/app/data.bin", "python"),
			want:  false,
		},
		{
			name:  "negative: wrong event type (exec)",
			event: newFileEvent("exec", "/app/config.yaml", "python"),
			want:  false,
		},
		{
			name:  "negative: file_open on extensionless file",
			event: newFileEvent("file_open", "/etc/shadow", "python"),
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

func TestFileDeleted(t *testing.T) {
	tpl := findTemplate(t, "file_deleted")
	lg := categoryLogger("file")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_unlink event",
			event: newFileEvent("file_unlink", "/tmp/secret.txt", "rm"),
			want:  true,
		},
		{
			name:  "negative: file_open event",
			event: newFileEvent("file_open", "/tmp/secret.txt", "cat"),
			want:  false,
		},
		{
			name:  "negative: file_rw event",
			event: newFileEvent("file_rw", "/tmp/secret.txt", "python"),
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

func TestSelfModify(t *testing.T) {
	tpl := findTemplate(t, "self_modify")
	lg := categoryLogger("file")

	execEv := &consumer.EnrichedEvent{
		Timestamp: time.Now(),
		EventType: "exec",
		Pid:       1000,
		Comm:      "agent",
		Binary:    "/usr/bin/agent",
		Tags:      []string{},
	}

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		sess  func() *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_rw on previously-exec'd binary",
			event: newFileEvent("file_rw", "/usr/bin/agent", "agent"),
			sess:  func() *consumer.EnrichedEvent { return execEv },
			want:  true,
		},
		{
			name:  "negative: file_rw on unrelated path",
			event: newFileEvent("file_rw", "/tmp/output.txt", "agent"),
			sess:  func() *consumer.EnrichedEvent { return execEv },
			want:  false,
		},
		{
			name:  "negative: file_rw but no exec in session",
			event: newFileEvent("file_rw", "/usr/bin/agent", "agent"),
			sess:  nil,
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var events []*consumer.EnrichedEvent
			if tc.sess != nil {
				events = []*consumer.EnrichedEvent{tc.sess()}
			}
			sess := newSession(events, nil)
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModelMmap(t *testing.T) {
	tpl := findTemplate(t, "model_mmap")
	lg := categoryLogger("file")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_mmap with large_mmap flag",
			event: newFileEventWithFlags("file_mmap", "/models/llama-7b.gguf", "python", consumer.RFlagLargeMmap),
			want:  true,
		},
		{
			name:  "negative: file_mmap without large_mmap flag",
			event: newFileEventWithFlags("file_mmap", "/models/small.bin", "python", 0),
			want:  false,
		},
		{
			name:  "negative: file_open with large_mmap flag (wrong event type)",
			event: newFileEventWithFlags("file_open", "/models/llama-7b.gguf", "python", consumer.RFlagLargeMmap),
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

func TestSSHKeyAccess(t *testing.T) {
	tpl := findTemplate(t, "ssh_key_access")
	lg := categoryLogger("file")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_open on id_rsa",
			event: newFileEvent("file_open", "/home/user/.ssh/id_rsa", "python"),
			want:  true,
		},
		{
			name:  "positive: file_rw on authorized_keys",
			event: newFileEvent("file_rw", "/home/user/.ssh/authorized_keys", "agent"),
			want:  true,
		},
		{
			name:  "positive: file_open on id_ed25519",
			event: newFileEvent("file_open", "/root/.ssh/id_ed25519", "python3"),
			want:  true,
		},
		{
			name:  "negative: file_open on unrelated path",
			event: newFileEvent("file_open", "/home/user/documents/report.txt", "cat"),
			want:  false,
		},
		{
			name:  "negative: wrong event type",
			event: newFileEvent("exec", "/home/user/.ssh/id_rsa", "python"),
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

func TestSensitiveRead(t *testing.T) {
	tpl := findTemplate(t, "sensitive_read")
	lg := categoryLogger("file")

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
		sess  *consumer.EnrichedEvent // nil = no AI in session
		want  bool
	}{
		{
			name:  "positive: sensitive flag + AI session",
			event: newFileEventWithFlags("file_open", "/etc/shadow", "python", consumer.RFlagSensitive),
			want:  true,
		},
		{
			name:  "negative: sensitive flag but no AI in session",
			event: newFileEventWithFlags("file_open", "/etc/shadow", "systemd", consumer.RFlagSensitive),
			want:  false,
		},
		{
			name:  "negative: no sensitive flag",
			event: newFileEventWithFlags("file_open", "/tmp/foo.txt", "python", 0),
			want:  false,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := sessNoAI
			if i == 0 {
				sess = sessWithAI
			}
			got := detector.Evaluate(tpl, tc.event, sess)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModelLoad(t *testing.T) {
	tpl := findTemplate(t, "model_load")
	lg := categoryLogger("file")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: file_open on .gguf model",
			event: newFileEvent("file_open", "/models/llama-7b.gguf", "ollama"),
			want:  true,
		},
		{
			name:  "positive: file_rw on .safetensors model",
			event: newFileEvent("file_rw", "/data/model.safetensors", "python"),
			want:  true,
		},
		{
			name:  "positive: file_open on .pt model",
			event: newFileEvent("file_open", "/checkpoints/epoch5.pt", "torchrun"),
			want:  true,
		},
		{
			name:  "negative: file_open on .pdf (not a model extension)",
			event: newFileEvent("file_open", "/data/report.pdf", "python"),
			want:  false,
		},
		{
			name:  "negative: wrong event type (file_mmap)",
			event: newFileEvent("file_mmap", "/models/llama-7b.gguf", "python"),
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
