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
	"path/filepath"
	"strings"
	"syscall"

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

	// LSM self-protection map handles.
	// Nil when the BPF object was built without Section 6 programs,
	// or when the maps could not be located after loading.
	protectedInodesMap *ebpf.Map
	monitorPIDMap      *ebpf.Map
	protectedMapIDsMap *ebpf.Map
}

// inodeKey mirrors struct inode_key in bpf/common.h.
// Field layout must match exactly — cilium/ebpf serialises it as-is.
//
//	Ino  uint64  — 8 bytes
//	Dev  uint32  — 4 bytes
//	Pad  uint32  — 4 bytes (explicit padding; matches C's __u32 _pad)
//
// Total: 16 bytes.
type inodeKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// tracepointDef maps a (group, event) pair to the C function name
// used in SEC("tracepoint/<group>/<event>").
type tracepointDef struct {
	group   string
	event   string
	progKey string // C function name → key in coll.Programs
}

// lsmDef maps a C function name to a human-readable description used in
// log messages.  LSM programs are attached via link.AttachTracing, not
// link.Tracepoint, so they have a separate definition list.
type lsmDef struct {
	progKey string // C function name → key in coll.Programs
	desc    string // human-readable hook name for logging
}

// allLSMProgs lists every LSM hook program defined in Section 6 of
// monitor.bpf.c.  Attachment is conditional on BPF LSM being available
// (isBPFLSMEnabled); missing entries are warned but not fatal.
var allLSMProgs = []lsmDef{
	{"lsm_protect_inode", "lsm/inode_permission"},
	{"lsm_protect_kill", "lsm/task_kill"},
	{"lsm_protect_bpf_map", "lsm/bpf_map"},
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

	// Expose LSM self-protection maps (present only when Section 6 is compiled
	// in).  Missing maps are not fatal — protection is simply disabled.
	objs.protectedInodesMap = coll.Maps["protected_inodes"]
	objs.monitorPIDMap = coll.Maps["monitor_pid"]
	objs.protectedMapIDsMap = coll.Maps["protected_map_ids"]

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

// ── LSM self-protection ───────────────────────────────────────────────────────

// isBPFLSMEnabled reports whether the running kernel has BPF LSM active.
// It reads /sys/kernel/security/lsm and looks for the "bpf" entry.
// Returns false on any read error (kernel may not expose the file).
func isBPFLSMEnabled() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, entry := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if strings.TrimSpace(entry) == "bpf" {
			return true
		}
	}
	return false
}

// AttachLSMProgs attaches the three LSM self-protection programs defined in
// Section 6 of monitor.bpf.c.
//
// This is non-fatal: if BPF LSM is not available on the running kernel, a
// warning is logged and the monitor continues without runtime file protection.
// The caller should invoke this after Load() and before PopulateProtectionMaps.
func (o *Objects) AttachLSMProgs(logger *zap.Logger) error {
	if !isBPFLSMEnabled() {
		logger.Warn("BPF LSM not active — self-protection hooks disabled",
			zap.String("hint", "add 'lsm=...,bpf' to kernel boot params and reboot"),
			zap.String("check", "/sys/kernel/security/lsm"),
		)
		return nil
	}

	var attached int
	for _, def := range allLSMProgs {
		prog, ok := o.coll.Programs[def.progKey]
		if !ok {
			logger.Warn("LSM program not found in BPF object — skipping",
				zap.String("prog", def.progKey),
				zap.String("hook", def.desc),
			)
			continue
		}

		// LSM programs (BPF_PROG_TYPE_LSM) use AttachLSM, not AttachTracing.
		// AttachTracing only accepts BPF_PROG_TYPE_TRACING programs.
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			logger.Warn("failed to attach LSM hook",
				zap.String("prog", def.progKey),
				zap.String("hook", def.desc),
				zap.Error(err),
			)
			continue
		}

		o.links = append(o.links, l)
		attached++
		logger.Info("LSM hook attached", zap.String("hook", def.desc))
	}

	if attached == 0 {
		logger.Warn("no LSM hooks attached — self-protection disabled")
	} else {
		logger.Info("LSM self-protection active", zap.Int("hooks", attached))
	}
	return nil
}

// PopulateProtectionMaps writes the monitor's PID and the inodes of all
// protected files into the kernel-side BPF maps used by the LSM hooks.
//
// Call order within the function matters:
//  1. monitor_pid is written first so is_monitor_pid() works before inodes
//     are locked down — avoiding a window where the monitor cannot touch its
//     own files.
//  2. protected_inodes is populated file-by-file.
//  3. protected_map_ids is populated last.
//
// protectedPaths should include the monitor binary, the BPF object, and
// all template YAML files + their parent directories.
//
// This is non-fatal: a partial population (e.g. a file not found) logs a
// warning but does not stop the monitor.
func (o *Objects) PopulateProtectionMaps(selfPID uint32, protectedPaths []string, logger *zap.Logger) error {
	if o.monitorPIDMap == nil || o.protectedInodesMap == nil || o.protectedMapIDsMap == nil {
		logger.Warn("LSM protection maps not found — self-protection disabled",
			zap.String("hint", "rebuild with Section 6 programs present in monitor.bpf.c"),
		)
		return nil
	}

	// ── 1. Write the monitor PID ─────────────────────────────────────────
	pidKey := uint32(0)
	if err := o.monitorPIDMap.Put(pidKey, selfPID); err != nil {
		return fmt.Errorf("writing monitor_pid map: %w", err)
	}
	logger.Info("LSM: monitor PID registered", zap.Uint32("pid", selfPID))

	// ── 2. Populate protected_inodes ─────────────────────────────────────
	//
	// Deduplicate paths before stat-ing so we write each inode exactly once
	// (multiple template files may share the same parent directory inode
	// if we also protect parent dirs, and the binary dir may be the same
	// as the BPF object dir).
	seenInodes := make(map[inodeKey]struct{})
	dummy := uint32(1)

	// Protect individual file inodes AND their parent directory inodes.
	// Protecting the directory prevents adding/removing files without
	// the user explicitly stopping the monitor.
	allPaths := make([]string, 0, len(protectedPaths)*2)
	for _, p := range protectedPaths {
		allPaths = append(allPaths, p)
		if dir := filepath.Dir(p); dir != "" && dir != "." {
			allPaths = append(allPaths, dir)
		}
	}

	var inodesRegistered int
	for _, p := range allPaths {
		key, err := fileInodeKey(p)
		if err != nil {
			logger.Warn("LSM: cannot stat protected path — skipping",
				zap.String("path", p), zap.Error(err))
			continue
		}
		if _, seen := seenInodes[key]; seen {
			continue
		}
		seenInodes[key] = struct{}{}

		if err := o.protectedInodesMap.Put(key, dummy); err != nil {
			logger.Warn("LSM: failed to register inode",
				zap.String("path", p),
				zap.Uint64("ino", key.Ino),
				zap.Error(err),
			)
			continue
		}
		inodesRegistered++
		logger.Debug("LSM: inode protected",
			zap.String("path", p),
			zap.Uint64("ino", key.Ino),
			zap.Uint32("dev", key.Dev),
		)
	}
	logger.Info("LSM: inode protection active", zap.Int("inodes", inodesRegistered))

	// ── 3. Populate protected_map_ids ────────────────────────────────────
	//
	// Protect every map in the collection, including the three new
	// LSM guard maps themselves.
	var mapsRegistered int
	for name, m := range o.coll.Maps {
		info, err := m.Info()
		if err != nil {
			logger.Warn("LSM: cannot get map info — skipping",
				zap.String("map", name), zap.Error(err))
			continue
		}
		id, ok := info.ID()
		if !ok {
			logger.Warn("LSM: map ID not available — skipping",
				zap.String("map", name))
			continue
		}
		mapID := uint32(id)
		if err := o.protectedMapIDsMap.Put(mapID, dummy); err != nil {
			logger.Warn("LSM: failed to register map ID",
				zap.String("map", name), zap.Uint32("id", mapID), zap.Error(err))
			continue
		}
		mapsRegistered++
		logger.Debug("LSM: map protected", zap.String("name", name), zap.Uint32("id", mapID))
	}
	logger.Info("LSM: BPF map protection active", zap.Int("maps", mapsRegistered))

	return nil
}

// fileInodeKey stats path and returns the inodeKey for it.
// Works for both regular files and directories.
func fileInodeKey(path string) (inodeKey, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return inodeKey{}, fmt.Errorf("stat %q: %w", path, err)
	}
	return inodeKey{
		Ino: st.Ino,
		Dev: uint32(st.Dev),
	}, nil
}
