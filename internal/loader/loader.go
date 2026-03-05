// Package loader handles loading the compiled eBPF object and attaching
// all tracepoint programs to their kernel hooks.
//
// It uses cilium/ebpf to:
//   - Load monitor.bpf.o from disk (path resolved by caller)
//   - Remove the MEMLOCK rlimit (required for kernel < 5.11; no-op on newer)
//   - Attach each program to its tracepoint via link.Tracepoint
//   - Return typed handles to maps and programs via Objects
//
// The caller is responsible for calling Objects.Close() on shutdown.
//
// Tracepoint attach model:
//   link.Tracepoint(group, event, program, nil)
//   group = "syscalls" for all sys_enter_*/sys_exit_* hooks
//   group = "sched"    for sched_process_exit
//
// All hooks use stable syscall tracepoints — no kprobes, no kernel-version
// specific function names. The same binary attaches cleanly on 5.15 and 6.x.
//
// SSL uprobe attach model (AttachSSLProbes):
//   Scans /proc/*/maps for libssl.so library paths, then for each unique
//   path calls link.OpenExecutable(path).Uprobe("SSL_write", ...) and
//   .Uretprobe("SSL_read", ...) to hook plaintext TLS traffic.
//   This is non-fatal: if no libssl.so is found, TLS capture is disabled.
package loader

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

// Objects holds all loaded eBPF maps and programs.
// Callers access maps by name to pass to consumers.
type Objects struct {
	coll  *ebpf.Collection
	links []link.Link

	// Exported map handles for direct consumer use
	EventsMap *ebpf.Map
}

// tracepointDef maps a (group, event) pair to the C function name
// used in SEC("tracepoint/<group>/<event>").
type tracepointDef struct {
	group   string
	event   string
	progKey string // C function name → key in coll.Programs
}

// allTracepoints lists every tracepoint we attach.
// These names are stable kernel ABI — identical on 5.15 and 6.x.
var allTracepoints = []tracepointDef{
	// ── Process execution ───────────────────────────────────────────────
	{"syscalls", "sys_enter_execve", "tp_execve"},
	{"syscalls", "sys_enter_execveat", "tp_execveat"},

	// ── File system activity ────────────────────────────────────────────
	{"syscalls", "sys_enter_openat", "tp_openat_enter"},
	{"syscalls", "sys_exit_openat", "tp_openat_exit"},
	{"syscalls", "sys_enter_read", "tp_read"},
	{"syscalls", "sys_enter_write", "tp_write"},
	{"syscalls", "sys_enter_unlinkat", "tp_unlinkat"},
	{"syscalls", "sys_enter_mmap", "tp_mmap"},

	// ── Network ─────────────────────────────────────────────────────────
	{"syscalls", "sys_enter_connect", "tp_connect"},
	{"syscalls", "sys_enter_sendmsg", "tp_sendmsg"},

	// ── Process exit cleanup ────────────────────────────────────────────
	{"sched", "sched_process_exit", "tp_proc_exit"},
}

// Load reads the compiled eBPF object from bpfObjPath, loads all programs
// and maps into the kernel, then attaches every tracepoint.
//
// On success it returns an *Objects that must be closed by the caller.
// On failure all partially-created resources are cleaned up.
func Load(bpfObjPath string) (*Objects, error) {
	// Remove MEMLOCK rlimit.
	// Required on kernels < 5.11 where BPF maps were charged against
	// the process's locked-memory limit. No-op (returns nil) on 5.11+
	// where BPF uses a dedicated memory accounting mechanism.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// Parse the ELF object — validates BTF and map/program specs.
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("loading collection spec from %q: %w", bpfObjPath, err)
	}

	// Load programs and maps into the kernel.
	// This is where the kernel verifier runs — if the eBPF code has
	// any issues (unbounded loops, missing null checks, etc.) the error
	// is returned here with the verifier log.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("creating eBPF collection (verifier error?): %w", err)
	}

	objs := &Objects{coll: coll}

	// Attach all tracepoints.
	// If any attachment fails, we clean up everything already attached.
	for _, tp := range allTracepoints {
		prog, ok := coll.Programs[tp.progKey]
		if !ok {
			objs.Close()
			return nil, fmt.Errorf("program %q not found in BPF object %q",
				tp.progKey, bpfObjPath)
		}

		l, err := link.Tracepoint(tp.group, tp.event, prog, nil)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("attaching tracepoint %s/%s (prog %q): %w",
				tp.group, tp.event, tp.progKey, err)
		}
		objs.links = append(objs.links, l)
	}

	// Expose the ring buffer map for the consumer
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		objs.Close()
		return nil, fmt.Errorf("map %q not found in BPF object", "events")
	}
	objs.EventsMap = eventsMap

	return objs, nil
}

// AttachSSLProbes scans /proc/*/maps for libssl.so instances and attaches
// SSL_write / SSL_read uprobes to each unique library path found.
//
// This function is non-fatal: if no libssl.so is present (e.g. on a host
// that only uses Go TLS or BoringSSL with different symbol names), it logs
// a warning and returns nil. TLS capture is simply disabled in that case.
//
// The attached links are added to o.links and closed by o.Close().
func (o *Objects) AttachSSLProbes(logger *zap.Logger) error {
	// Look up the three TLS uprobe programs in the loaded collection.
	sslWrite, okW := o.coll.Programs["uprobe_ssl_write"]
	sslReadEntry, okE := o.coll.Programs["uprobe_ssl_read_entry"]
	sslReadRet, okR := o.coll.Programs["uretprobe_ssl_read"]

	if !okW || !okE || !okR {
		logger.Warn("TLS uprobe programs not found in BPF object — TLS capture disabled",
			zap.Bool("ssl_write_found", okW),
			zap.Bool("ssl_read_entry_found", okE),
			zap.Bool("ssl_read_ret_found", okR),
		)
		return nil
	}

	libPaths, err := findSSLLibraries()
	if err != nil {
		logger.Warn("scanning /proc for libssl.so", zap.Error(err))
	}

	if len(libPaths) == 0 {
		logger.Info("no libssl.so found in running processes — TLS capture disabled")
		return nil
	}

	var attached int
	for libPath := range libPaths {
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			logger.Warn("opening SSL library for uprobe", zap.String("path", libPath), zap.Error(err))
			continue
		}

		writeLink, err := exe.Uprobe("SSL_write", sslWrite, nil)
		if err != nil {
			logger.Warn("attaching SSL_write uprobe", zap.String("lib", libPath), zap.Error(err))
			continue
		}

		readEntryLink, err := exe.Uprobe("SSL_read", sslReadEntry, nil)
		if err != nil {
			_ = writeLink.Close()
			logger.Warn("attaching SSL_read entry uprobe", zap.String("lib", libPath), zap.Error(err))
			continue
		}

		readRetLink, err := exe.Uretprobe("SSL_read", sslReadRet, nil)
		if err != nil {
			_ = writeLink.Close()
			_ = readEntryLink.Close()
			logger.Warn("attaching SSL_read return uprobe", zap.String("lib", libPath), zap.Error(err))
			continue
		}

		o.links = append(o.links, writeLink, readEntryLink, readRetLink)
		attached++
		logger.Info("TLS uprobes attached", zap.String("lib", libPath))
	}

	if attached == 0 {
		logger.Info("TLS capture: failed to attach to any libssl.so instance")
	} else {
		logger.Info("TLS capture active", zap.Int("libraries", attached))
	}

	return nil
}

// findSSLLibraries scans /proc/*/maps for unique libssl.so file paths.
// Returns a set of absolute paths to libssl.so library files currently
// mapped into at least one running process.
func findSSLLibraries() (map[string]struct{}, error) {
	paths := make(map[string]struct{})

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only process numeric entries (PIDs)
		if !isAllDigits(entry.Name()) {
			continue
		}

		data, err := os.ReadFile("/proc/" + entry.Name() + "/maps")
		if err != nil {
			continue // process may have exited
		}

		for _, line := range strings.Split(string(data), "\n") {
			// /proc/pid/maps line format:
			//   addr-addr perms offset dev inode /path/to/lib.so
			if !strings.Contains(line, "libssl") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			libPath := fields[5]
			if strings.HasPrefix(libPath, "/") && !strings.Contains(libPath, "(deleted)") {
				paths[libPath] = struct{}{}
			}
		}
	}

	return paths, nil
}

// isAllDigits returns true if s consists only of ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Close detaches all tracepoints and unloads programs and maps from the kernel.
// Safe to call on a nil receiver or after a partial Load failure.
func (o *Objects) Close() {
	if o == nil {
		return
	}
	// Detach tracepoints first — programs can be unloaded after links close.
	for _, l := range o.links {
		if l != nil {
			_ = l.Close()
		}
	}
	if o.coll != nil {
		o.coll.Close()
	}
}

// MapFD returns the file descriptor of a named map.
// Useful for userspace tools (bpftool, etc.) that need the raw fd.
func (o *Objects) MapFD(name string) (int, error) {
	m, ok := o.coll.Maps[name]
	if !ok {
		return -1, fmt.Errorf("map %q not found", name)
	}
	return m.FD(), nil
}
