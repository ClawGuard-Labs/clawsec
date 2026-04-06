// clawsec — host-level eBPF monitoring for AI agent processes.
//
// Architecture:
//
//   ┌─────────────────────────────────────────────────────────────────┐
//   │  Kernel (eBPF programs attached to stable syscall tracepoints)  │
//   │  execve │ openat │ read │ write │ unlinkat │ mmap │ connect …   │
//   └──────────────────────┬──────────────────────────────────────────┘
//                          │ ring buffer (8 MB)
//   ┌──────────────────────▼──────────────────────────────────────────┐
//   │  consumer  → decode raw bytes → EnrichedEvent                  │
//   │  correlator → assign session ID, parent comm, process tree      │
//   │  detector  → evaluate rules → tags + risk score                 │
//   │  output    → NDJSON to stdout/file + SSE HTTP stream            │
//   └─────────────────────────────────────────────────────────────────┘
//
//   TLS capture (optional, requires libssl.so in running processes):
//   ┌─────────────────────────────────────────────────────────────────┐
//   │  uprobe SSL_write   → plaintext before encryption               │
//   │  uretprobe SSL_read → plaintext after decryption                │
//   │  → same ring buffer → same pipeline                             │
//   └─────────────────────────────────────────────────────────────────┘
//
// Usage:
//   sudo ./bin/monitor [flags]
//
// Flags:
//   --bpf-obj     path to monitor.bpf.o  (auto-detected if not set)
//   --behavioral-templates  path to behavioral YAML dir (default: ./clawsec-templates/behavioral-templates)
//   --output      JSON output file        (default: stdout)
//   --sse         SSE listen address      (default: disabled)
//   --ui          graph dashboard address (default: disabled)
//   --log-level   debug|info|warn|error   (default: info)
//   --config      path to config.yaml (default: ./config.yaml or beside binary)
//   --no-tls      disable TLS uprobe capture (default: enabled if libssl found)
//   --version     print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/clawsec/internal/aiprofile"
	"github.com/clawsec/internal/chagg"
	"github.com/clawsec/internal/consumer"
	"github.com/clawsec/internal/correlator"
	"github.com/clawsec/internal/detector"
	"github.com/clawsec/internal/graph"
	"github.com/clawsec/internal/graphapi"
	"github.com/clawsec/internal/loader"
	"github.com/clawsec/internal/nucleiscanner"
	"github.com/clawsec/internal/output"
	"github.com/clawsec/internal/provenance"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version is injected at build time via -ldflags "-X main.Version=<tag>".
var Version = "dev"

// config holds all runtime configuration parsed from flags.
type config struct {
	bpfObjPath      string
	behavioralTemplatesDir string
	nucleiTemplates string
	noNuclei        bool
	outputFile      string
	sseAddr         string
	uiAddr          string
	logLevel        string
	noTLS           bool
	grouped         bool
	groupTimeout    time.Duration
	compact         bool
	compactLog      string
	compactIdle     time.Duration
	configPath      string
}

func main() {
	cfg := &config{}
	showVersion := false

	flag.StringVar(&cfg.bpfObjPath, "bpf-obj", "",
		"Path to monitor.bpf.o (auto-detected: ./bpf/, next to binary, /usr/lib/clawsec/)")
	flag.StringVar(&cfg.behavioralTemplatesDir, "behavioral-templates", "./clawsec-templates/behavioral-templates",
		"Directory containing behavioral YAML detection rules")
	flag.StringVar(&cfg.nucleiTemplates, "nuclei-templates", "./nuclei-templates",
		"Directory containing Nuclei YAML templates for active scanning")
	flag.BoolVar(&cfg.noNuclei, "no-nuclei", false,
		"Disable active Nuclei scanning of detected local AI services")
	flag.StringVar(&cfg.outputFile, "output", "",
		"JSON output file (default: stdout)")
	flag.StringVar(&cfg.sseAddr, "sse", "",
		"SSE listen address for live event streaming, e.g. :8080 (disabled if empty)")
	flag.StringVar(&cfg.uiAddr, "ui", "",
		"Graph dashboard listen address, e.g. :9090 (disabled if empty)")
	flag.StringVar(&cfg.logLevel, "log-level", "info",
		"Log verbosity: debug | info | warn | error")
	flag.BoolVar(&cfg.noTLS, "no-tls", false,
		"Disable TLS uprobe capture (useful if libssl symbol lookup is slow)")
	flag.BoolVar(&cfg.grouped, "grouped", false,
		"Buffer events by session and flush as one JSON block per (parent_comm, ppid) chain after idle")
	flag.DurationVar(&cfg.groupTimeout, "group-timeout", 500*time.Millisecond,
		"Idle time after which a session group is flushed (only with --grouped)")
	flag.BoolVar(&cfg.compact, "compact", false,
		"Enable chain aggregation (compact repeated edge patterns into counted chains)")
	flag.StringVar(&cfg.compactLog, "compact-log", "",
		"Path for compact chain log file (requires --compact)")
	flag.DurationVar(&cfg.compactIdle, "compact-idle", 30*time.Second,
		"Idle window before finalizing a process chain")
	flag.StringVar(&cfg.configPath, "config", "",
		"Path to config.yaml (AI ports, extensions, process names, categories). If empty, searches ./config.yaml then beside the binary")
	flag.BoolVar(&showVersion, "version", false,
		"Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("clawsec %s\n", Version)
		os.Exit(0)
	}

	// ── Logger ────────────────────────────────────────────────────────────
	logger := buildLogger(cfg.logLevel)
	defer logger.Sync() //nolint:errcheck

	// ── Privilege check ───────────────────────────────────────────────────
	if os.Getuid() != 0 {
		logger.Fatal("must run as root (or grant CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN)")
	}

	// ── Graceful shutdown context ─────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Run ───────────────────────────────────────────────────────────────
	if err := run(ctx, cfg, logger); err != nil {
		logger.Fatal("monitor exited with error", zap.Error(err))
	}
	logger.Info("shutdown complete")
}

// run is the real entry point — extracted so it can return an error cleanly.
func run(ctx context.Context, cfg *config, logger *zap.Logger) error {
	// Capture our own PID so we can drop self-generated eBPF events.
	// The monitor reads /proc, its own template files, and makes connections
	// during libssl scanning — all of which would create noisy false positives.
	selfPID := uint32(os.Getpid())

	cfgFile, err := aiprofile.ResolveConfigPath(cfg.configPath)
	if err != nil {
		return err
	}
	aiProf, err := aiprofile.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config.yaml %q: %w", cfgFile, err)
	}
	logger.Info("config.yaml loaded", zap.String("path", cfgFile))

	// ── 1. Resolve BPF object path ────────────────────────────────────────
	bpfPath, err := findBPFObject(cfg.bpfObjPath)
	if err != nil {
		return fmt.Errorf("finding BPF object: %w\n"+
			"  Build with: make build\n"+
			"  Or specify: --bpf-obj /path/to/monitor.bpf.o", err)
	}
	logger.Info("BPF object found", zap.String("path", bpfPath))

	// ── 2. Load eBPF programs and attach tracepoints ──────────────────────
	logger.Info("loading eBPF programs and attaching tracepoints…")
	objs, err := loader.Load(bpfPath)
	if err != nil {
		return fmt.Errorf("loading eBPF: %w\n"+
			"  Check: kernel >= 5.15, BTF enabled (/sys/kernel/btf/vmlinux exists)", err)
	}
	defer objs.Close()
	logger.Info("all tracepoints attached — monitoring active")

	// ── 3a. Attach LSM self-protection hooks (optional) ───────────────────
	// Non-fatal: if BPF LSM is not enabled in the kernel, a warning is logged
	// and the monitor continues without runtime file/process/map protection.
	if err := objs.AttachLSMProgs(logger); err != nil {
		logger.Warn("LSM hook attachment failed", zap.Error(err))
	}

	// ── 3b. Populate LSM protection maps ──────────────────────────────────
	// Build the list of paths the LSM inode hook will protect:
	//   - the monitor binary itself
	//   - the compiled BPF object
	//   - every YAML template file (behavioral + nuclei)
	//
	// We resolve the binary path via os.Executable() so it works whether the
	// user ran ./bin/monitor or /usr/local/bin/clawsec.
	protectedPaths := collectProtectedPaths(cfg, bpfPath, logger)
	if err := objs.PopulateProtectionMaps(selfPID, protectedPaths, logger); err != nil {
		// Non-fatal: log and continue.  LSM hooks will simply allow everything
		// if the maps are empty (same as if LSM weren't available).
		logger.Warn("LSM map population failed", zap.Error(err))
	}

	// ── 5. Attach TLS uprobes (optional) ──────────────────────────────────
	if !cfg.noTLS {
		logger.Info("scanning for libssl.so to attach TLS uprobes…")
		if err := objs.AttachSSLProbes(logger); err != nil {
			// Non-fatal: TLS capture is best-effort
			logger.Warn("TLS uprobe setup failed", zap.Error(err))
		}
	} else {
		logger.Info("TLS uprobe capture disabled via --no-tls flag")
	}

	// ── 6. Ring buffer consumer ───────────────────────────────────────────
	cons, err := consumer.New(objs.EventsMap, logger, aiProf)
	if err != nil {
		return fmt.Errorf("creating consumer: %w", err)
	}

	// ── 7. Correlation engine ─────────────────────────────────────────────
	corr := correlator.New(ctx, logger)

	// ── 8. Detection rules ────────────────────────────────────────────────
	det, err := detector.New(logger, cfg.behavioralTemplatesDir)
	if err != nil {
		return fmt.Errorf("loading detection templates: %w\n"+
			"  Clone clawsec-templates alongside this binary (./clawsec-templates/behavioral-templates)\n"+
			"  or pass: --behavioral-templates /path/to/behavioral-templates", err)
	}

	// ── 9. Output writer ──────────────────────────────────────────────────
	var w io.Writer = os.Stdout
	var rulesOut *output.Writer // flat NDJSON — rule-matched events only
	if cfg.outputFile != "" {
		logsPath, rulesPath := splitOutputPaths(cfg.outputFile)

		logsFile, err := os.OpenFile(logsPath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("opening logs file %q: %w", logsPath, err)
		}
		defer logsFile.Close()
		w = logsFile

		rulesFile, err := os.OpenFile(rulesPath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("opening rules file %q: %w", rulesPath, err)
		}
		defer rulesFile.Close()
		rulesOut = output.New(rulesFile, "", logger)

		logger.Info("JSON output",
			zap.String("all_events", logsPath),
			zap.String("rule_matches", rulesPath),
		)
	}

	var out output.EventWriter
	if cfg.grouped {
		gw := output.NewGroupedWriter(w, cfg.groupTimeout, cfg.sseAddr, logger)
		out = gw
		go gw.Start(ctx)
		logger.Info("grouped output enabled",
			zap.Duration("idle_flush", cfg.groupTimeout),
			zap.String("group_by", "ai_session_id (parent_comm/ppid in block)"))
	} else {
		out = output.New(w, cfg.sseAddr, logger)
	}

	if cfg.sseAddr != "" {
		logger.Info("SSE live stream",
			zap.String("url", "http://"+cfg.sseAddr+"/events"),
		)
	}

	// ── 10. Provenance tracker + graph ───────────────────────────────────
	tracker := provenance.New(aiProf)
	g := graph.New()

	var agg *chagg.Aggregator
	if cfg.compact {
		agg = chagg.New(cfg.compactIdle)
		go agg.Start(ctx)
		logger.Info("chain aggregation enabled",
			zap.Duration("idle_window", cfg.compactIdle))

		if cfg.compactLog != "" {
			cw := chagg.NewWriter(agg, cfg.compactLog)
			go cw.Start(ctx)
			logger.Info("compact chain log", zap.String("path", cfg.compactLog))
		}
	}

	builder := graph.NewBuilder(g, agg, cfg.compact, cfg.compactIdle)
	if cfg.compact {
		go builder.StartCompaction(ctx)
	}

	if cfg.uiAddr != "" {
		uiServer := graphapi.New(cfg.uiAddr, g, agg, logger, aiProf)
		go uiServer.Start(ctx)
	} else {
		logger.Info("graph dashboard disabled (enable with --ui :<port>)")
	}

	// ── 11. Nuclei active scanner (optional) ─────────────────────────────
	var nucleiScanner *nucleiscanner.Scanner
	if !cfg.noNuclei {
		ns, err := nucleiscanner.New(ctx, cfg.nucleiTemplates, out, logger, aiProf)
		if err != nil {
			// Non-fatal: log and continue without active scanning.
			logger.Warn("nuclei scanner unavailable — active scanning disabled",
				zap.Error(err),
				zap.String("nuclei_templates", cfg.nucleiTemplates),
			)
		} else {
			nucleiScanner = ns
			defer nucleiScanner.Close()
			// Forward Nuclei findings to the rules file as well.
			if rulesOut != nil {
				nucleiScanner.SetRulesWriter(rulesOut)
			}
			logger.Info("nuclei active scanner enabled",
				zap.String("nuclei_templates", cfg.nucleiTemplates),
				zap.String("trigger", "net_connect to localhost AI service ports + periodic discovery"),
			)
		}
	} else {
		logger.Info("nuclei active scanning disabled via --no-nuclei flag")
	}

	// ── 12. Start ring buffer consumer goroutine ──────────────────────────
	events := cons.Start(ctx)

	// ── 11. Main event processing loop ───────────────────────────────────
	logger.Info("event loop running — press Ctrl-C to stop",
		zap.String("bpf_obj", bpfPath),
		zap.String("version", Version),
	)

	// Periodic stats ticker
	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	for {
		select {

		case <-ctx.Done():
			decoded, dropped, decErr := cons.Stats()
			output.PrintSummary(logger, corr.SessionCount(), decoded, dropped)
			logger.Info("consumer final stats",
				zap.Uint64("decoded", decoded),
				zap.Uint64("dropped", dropped),
				zap.Uint64("decode_errors", decErr),
			)
			return nil

		case <-statsTicker.C:
			decoded, dropped, _ := cons.Stats()
			output.PrintSummary(logger, corr.SessionCount(), decoded, dropped)

		case ev, ok := <-events:
			if !ok {
				// Consumer channel closed — ring buffer reader was closed.
				return nil
			}

			// Drop events generated by the monitor itself to prevent
			// self-monitoring false positives (template reads, /proc scans,
			// libssl connect() calls, etc.).
			if ev.Pid == selfPID {
				continue
			}

			// ── Pipeline: correlate → detect → provenance → graph → emit ──
			ev = corr.Process(ev)
			sess := corr.GetSession(ev.AISessionID)
			ev = det.Analyze(ev, sess)

			// Provenance / taint tracking — runs after detection so that
			// rule tags are already populated when the graph is updated.
			taint := tracker.Track(ev)
			builder.Process(ev, taint)

			// Nuclei active scan: fires async when a local AI service
			// port is detected. Both detectors run on the same event.
			if nucleiScanner != nil {
				nucleiScanner.MaybeScan(ctx, ev)
			}

			out.Write(ctx, ev)

			// Mirror to the rules file when a template or Nuclei matched.
			if rulesOut != nil && (len(ev.Tags) > 0 || ev.NucleiResult != nil) {
				rulesOut.Write(ctx, ev)
			}
		}
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// splitOutputPaths derives paired filenames from the user-supplied --output path.
//
//	"events.json"  → "events_logs.json", "events_rules.json"
//	"out"          → "out_logs",         "out_rules"
func splitOutputPaths(path string) (logsPath, rulesPath string) {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return base + "_logs" + ext, base + "_rules" + ext
}

// findBPFObject resolves the path to monitor.bpf.o using a priority chain:
//  1. Explicit --bpf-obj flag value
//  2. Same directory as the running binary (deployment default)
//  3. bpf/monitor.bpf.o relative to CWD  (development / make run)
//  4. /usr/lib/clawsec/monitor.bpf.o  (installed via make install)
func findBPFObject(flagPath string) (string, error) {
	candidates := []string{}

	if flagPath != "" {
		candidates = append(candidates, flagPath)
	}

	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(exe), "monitor.bpf.o"))
	}

	candidates = append(candidates,
		"bpf/monitor.bpf.o",
		"/usr/lib/clawsec/monitor.bpf.o",
	)

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, err := filepath.Abs(p)
			if err != nil {
				return p, nil
			}
			return abs, nil
		}
	}

	return "", fmt.Errorf("monitor.bpf.o not found in any of: %v", candidates)
}

// collectProtectedPaths builds the list of filesystem paths the LSM inode hook
// should protect from writes/unlinks by external processes:
//
//   - the monitor binary itself (resolved via os.Executable)
//   - the compiled BPF object (bpfPath)
//   - every YAML template under cfg.behavioralTemplatesDir
//   - every YAML template under cfg.nucleiTemplates
//
// Non-existent directories are skipped silently; errors are logged as warnings.
func collectProtectedPaths(cfg *config, bpfPath string, logger *zap.Logger) []string {
	seen := make(map[string]struct{})
	var paths []string

	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil {
			logger.Warn("collectProtectedPaths: abs failed", zap.String("path", p), zap.Error(err))
			return
		}
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		paths = append(paths, abs)
	}

	// Monitor binary.
	if exe, err := os.Executable(); err == nil {
		add(exe)
	} else {
		logger.Warn("collectProtectedPaths: os.Executable failed", zap.Error(err))
	}

	// Compiled BPF object.
	add(bpfPath)

	// Walk template directories for YAML files.
	for _, dir := range []string{cfg.behavioralTemplatesDir, cfg.nucleiTemplates} {
		if dir == "" {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				add(path)
			}
			return nil
		})
		if err != nil {
			logger.Warn("collectProtectedPaths: walk failed",
				zap.String("dir", dir), zap.Error(err))
		}
	}

	logger.Debug("LSM protection paths collected", zap.Int("count", len(paths)))
	return paths
}

// buildLogger creates a human-readable console logger at the requested level.
// Internal log lines go to stderr; event JSON goes to stdout (or --output file).
//
// Format: "2006-01-02 15:04:05.000  LEVEL  message  {fields}"
func buildLogger(level string) *zap.Logger {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	encCfg := zapcore.EncoderConfig{
		TimeKey:        "T",
		LevelKey:       "L",
		NameKey:        "N",
		CallerKey:      "",  // omit caller — reduces noise in production
		MessageKey:     "M",
		StacktraceKey:  "S",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000"),
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encCfg),
		zapcore.AddSync(os.Stderr),
		zap.NewAtomicLevelAt(lvl),
	)

	return zap.New(core)
}
