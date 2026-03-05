/* monitor.bpf.c — eBPF kernel-side monitoring program
 *
 * Single compilation unit: all programs share the same maps.
 *
 * Design principles:
 *   - CO-RE only: BPF_CORE_READ for all kernel struct access.
 *     libbpf resolves field offsets at load time via BTF.
 *     Works on kernel 5.15 (Ubuntu 22.04) and 6.x (Ubuntu 24.04)
 *     without recompilation.
 *
 *   - Tracepoints only: no kprobes, no fentry/fexit.
 *     Syscall tracepoints are stable ABI — format is guaranteed
 *     not to change between kernel versions. Hook names are identical
 *     on 5.15 and 6.x.
 *
 *   - Verifier safety:
 *     · All loops are bounded (#pragma unroll or explicit limit)
 *     · Large structs live in per-CPU maps, NOT on the stack
 *     · Every map lookup is null-checked before dereference
 *     · bpf_probe_read_user sizes are masked to prove bounds
 *
 *   - Low overhead:
 *     · read/write events only emitted for fds in fd_track
 *       (interesting files only — prevents millions of events/sec)
 *     · per-(pid, event_type) rate limiter caps bursts
 *     · early-exit on irrelevant threads (pid != tid)
 *
 * Build:
 *   clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64        \
 *         -I./bpf -I/usr/include/bpf                        \
 *         -c bpf/monitor.bpf.c -o bpf/monitor.bpf.o
 */

#include "common.h"

/* ════════════════════════════════════════════════════════════════════════════
   MAP DEFINITIONS
   All maps are defined in this single translation unit so every
   SEC("tracepoint/...") program can reference them directly.
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * events — primary ring buffer: eBPF → Go daemon.
 *
 * Ring buffer (BPF_MAP_TYPE_RINGBUF) is preferred over perf buffer because:
 *   - No per-CPU memory waste
 *   - Preserves ordering across CPUs
 *   - Lower overhead (single shared buffer vs N CPU buffers)
 *   - Available since kernel 5.8 — well within our 5.15 minimum
 *
 * 8 MB gives ~4000 exec_events or ~16000 net_events before wrap.
 * Go consumer must drain faster than this fills — trivial in practice.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);   /* 8 MB                                  */
} events SEC(".maps");

/*
 * proc_tree — process ancestry: pid → event_header snapshot.
 *
 * Written at execve time, read when we need parent info for any event.
 * Allows Go correlator to reconstruct full process trees without
 * repeated /proc/<pid>/status reads (which race with process exit).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                 /* pid                               */
    __type(value, struct mon_hdr);
} proc_tree SEC(".maps");

/*
 * fd_track — interesting open file descriptors: (pid, fd) → fd_val.
 *
 * Key mechanism for controlling read/write event volume.
 * Only fds of "interesting" files are stored here.
 * read/write probes skip emission unless the fd is in this map.
 *
 * "Interesting" currently means: sensitive path prefix (/etc, /proc, /sys).
 * Go userspace enriches this — it can push additional path patterns
 * (model file extensions, config dirs) via a separate config map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, struct fd_val);
} fd_track SEC(".maps");

/*
 * open_scratch — per-thread staging: pid_tgid → fd_val.
 *
 * Written at sys_enter_openat with the path and flags.
 * Read at sys_exit_openat where the returned fd is available.
 * Deleted immediately after use to keep the map small.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);             /* pid_tgid (unique per thread)           */
    __type(value, struct fd_val);
} open_scratch SEC(".maps");

/*
 * rate_limiter — sliding-window event throttle.
 * Prevents any single process from flooding the ring buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct rate_key);
    __type(value, struct rate_val);
} rate_limiter SEC(".maps");

/*
 * ssl_read_args — bridges the SSL_read entry and return probes.
 *
 * SSL_read(SSL *ssl, void *buf, int num): the output buffer pointer (arg2)
 * is available at entry but the decrypted data is written there only after
 * the function returns. We stash buf at entry (keyed by pid_tgid so it is
 * per-thread), then read the decrypted bytes in the uretprobe.
 *
 * Map is cleared on every uretprobe invocation or when SSL_read returns ≤0.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);             /* pid_tgid                               */
    __type(value, __u64);           /* userspace buf pointer                  */
} ssl_read_args SEC(".maps");

/*
 * Per-CPU scratch buffers for file and net events (~300 bytes each).
 *
 * WHY we do NOT have an exec_heap:
 *   exec_event is ~2 KB (args[MAX_ARGS][MAX_ARG_LEN]).
 *   clang 18+ with BPF target cannot inline __builtin_memset or
 *   __builtin_memcpy for structs this large — it tries to emit a
 *   runtime memset/memcpy call, which the BPF backend rejects with:
 *   "A call to built-in function 'memset' is not supported."
 *
 *   Fix: for exec events, bpf_ringbuf_reserve directly and write each
 *   field in-place. No scratch buffer, no memcpy. See __do_exec().
 *
 * file_event (~336 B) and net_event (~332 B) are small enough that
 * clang can inline __builtin_memset, so they use per-CPU scratch safely.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_event);
} file_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_event);
} net_heap SEC(".maps");


/* ════════════════════════════════════════════════════════════════════════════
   HELPER FUNCTIONS
   Declared static __always_inline — inlined by the compiler into each
   probe. The verifier sees the full code inline and can verify it.
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * fill_header — populate common fields that every event carries.
 *
 * BPF_CORE_READ(task, real_parent, tgid):
 *   This is CO-RE syntax for task->real_parent->tgid.
 *   At program load, libbpf looks up the field offset in the running
 *   kernel's BTF and patches the bytecode. On kernel 5.15 the offset
 *   for real_parent might be 0x3A0; on 6.x it might be 0x3B8.
 *   We never see this difference — libbpf handles it transparently.
 */
static __always_inline void fill_header(struct mon_hdr *h, __u8 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    h->timestamp_ns = bpf_ktime_get_ns();
    h->pid          = (__u32)(pid_tgid >> 32);
    h->uid          = (__u32)uid_gid;
    h->gid          = (__u32)(uid_gid >> 32);
    h->cgroup_id    = bpf_get_current_cgroup_id();
    h->event_type   = type;

    bpf_get_current_comm(h->comm, TASK_COMM_LEN);

    /* CO-RE: resolve real_parent->tgid offset from running kernel BTF */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    h->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

/*
 * rate_limit — sliding-window throttle per (pid, event_type).
 *
 * Returns 0 if the event should be emitted, -1 if it should be dropped.
 *
 * __sync_fetch_and_add: atomic increment required because the same
 * map value can be accessed from different CPUs concurrently.
 * Without atomics, count would silently under-count.
 */
static __always_inline int rate_limit(__u32 pid, __u8 type)
{
    struct rate_key k = { .pid = pid, .event_type = type };
    __u64 now = bpf_ktime_get_ns();

    struct rate_val *v = bpf_map_lookup_elem(&rate_limiter, &k);
    if (!v) {
        struct rate_val nv = { .window_ns = now, .count = 1 };
        bpf_map_update_elem(&rate_limiter, &k, &nv, BPF_NOEXIST);
        return 0;
    }

    /* Reset window if 1 second has elapsed */
    if (now - v->window_ns > RATE_WINDOW_NS) {
        v->window_ns = now;
        v->count = 0;
    }

    if (v->count >= RATE_MAX)
        return -1;  /* drop: rate limit exceeded */

    __sync_fetch_and_add(&v->count, 1);
    return 0;
}

/*
 * classify_path_buf — check a path that is already in BPF-accessible memory.
 *
 * Sensitive prefix detection done here in the kernel for two reasons:
 *   1. Lets us decide immediately whether to add fd to fd_track
 *   2. Sets risk_flags in the event without a userspace round-trip
 *
 * Model file extension detection (.pt, .gguf, .safetensors, .bin, .onnx)
 * is intentionally left for Go userspace — extension matching requires
 * iterating to the end of the string, which is expensive and verifier-
 * hostile in eBPF.
 */
static __always_inline __u32 classify_path_buf(const char *p)
{
    __u32 flags = 0;

    /* /etc/ — system configuration */
    if (p[0]=='/' && p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/')
        flags |= RFLAG_SENSITIVE;

    /* /proc/ — kernel process information */
    if (p[0]=='/' && p[1]=='p' && p[2]=='r' && p[3]=='o' &&
        p[4]=='c' && p[5]=='/')
        flags |= RFLAG_SENSITIVE;

    /* /sys/ — kernel sysfs */
    if (p[0]=='/' && p[1]=='s' && p[2]=='y' && p[3]=='s' && p[4]=='/')
        flags |= RFLAG_SENSITIVE;

    /* /root/.ssh/ or /home/.../.ssh/ — SSH keys */
    if (p[4]=='.' && p[5]=='s' && p[6]=='s' && p[7]=='h' && p[8]=='/')
        flags |= RFLAG_SENSITIVE;

    return flags;
}

/*
 * is_http_payload — check first bytes of a send buffer for HTTP methods.
 *
 * Called AFTER reading the payload into BPF-accessible memory.
 * Avoids emitting net_events for every sendmsg() — only HTTP traffic.
 *
 * Covers: GET POST PUT DELETE HEAD PATCH OPTIONS
 */
static __always_inline int is_http_payload(const char *buf, __u32 len)
{
    if (len < 4) return 0;
    if (buf[0]=='G' && buf[1]=='E' && buf[2]=='T' && buf[3]==' ') return 1;
    if (buf[0]=='P' && buf[1]=='O' && buf[2]=='S' && buf[3]=='T') return 1;
    if (buf[0]=='P' && buf[1]=='U' && buf[2]=='T' && buf[3]==' ') return 1;
    if (buf[0]=='D' && buf[1]=='E' && buf[2]=='L' && buf[3]=='E') return 1;
    if (buf[0]=='H' && buf[1]=='E' && buf[2]=='A' && buf[3]=='D') return 1;
    if (buf[0]=='P' && buf[1]=='A' && buf[2]=='T' && buf[3]=='C') return 1;
    if (buf[0]=='O' && buf[1]=='P' && buf[2]=='T' && buf[3]=='I') return 1;
    return 0;
}


/* ════════════════════════════════════════════════════════════════════════════
   SECTION 1 — PROCESS EXECUTION MONITORING
   Hooks: sys_enter_execve, sys_enter_execveat
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * __do_exec — shared logic for execve and execveat.
 *
 * DESIGN: Write directly to ring buffer — no scratch buffer, no memcpy.
 *
 * WHY: exec_event is ~2 KB (args[MAX_ARGS][MAX_ARG_LEN]).
 *   clang 18+ with BPF target cannot inline __builtin_memset /
 *   __builtin_memcpy for structs this large, emitting a runtime call
 *   the BPF backend rejects. The fix: bpf_ringbuf_reserve first, then
 *   write each field directly into ring buffer memory.
 *
 * Header is written via a stack-local struct mon_hdr (56 bytes — well
 * within the 512-byte stack limit and small enough for inline memset).
 * This stack copy also lets us update proc_tree without passing a
 * ring-buffer pointer to bpf_map_update_elem.
 *
 * Unused arg slots are null-terminated so Go knows they are empty.
 *
 * argv is char** in userspace. To read it:
 *   Step 1: bpf_probe_read_user(&argp, 8, &argv[i])  → reads the pointer
 *   Step 2: bpf_probe_read_user_str(dst, MAX, argp)  → reads the string
 *
 * #pragma unroll: fully unrolls the loop at compile time so the verifier
 * sees bounded straight-line code. MAX_ARGS=16 iterations is fine.
 */
static __always_inline int __do_exec(
    const char *filename_ptr,
    const char *const *argv_ptr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;

    /* Only capture on the main thread — exec() only fires on main thread */
    if (pid != tid)
        return 0;

    if (rate_limit(pid, EVENT_EXEC) < 0)
        return 0;

    /*
     * Build the common header on the stack (56 bytes — safe).
     * The struct = {} zero-initializer is 56 bytes; clang inlines it.
     */
    struct mon_hdr hdr = {};
    fill_header(&hdr, EVENT_EXEC);

    /* Update process ancestry map before ring buffer work */
    bpf_map_update_elem(&proc_tree, &pid, &hdr, BPF_ANY);

    /*
     * Reserve ring buffer space and write directly.
     * No __builtin_memset / __builtin_memcpy on the large struct —
     * every byte is explicitly written below.
     */
    struct exec_event *rb = bpf_ringbuf_reserve(&events,
                                                 sizeof(struct exec_event), 0);
    if (!rb)
        return 0;

    /* Copy 56-byte header via struct assignment (inlined by clang) */
    rb->hdr = hdr;

    /* Read binary path directly into ring buffer memory */
    bpf_probe_read_user_str(rb->filename, MAX_PATH_LEN, filename_ptr);

    /*
     * Read each argv element into ring buffer memory.
     * On read failure or null ptr: null-terminate the slot so Go
     * knows the argument is absent (Go reads until '\0').
     */
    __u32 count = 0;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg = NULL;

        /* Read the pointer at argv[i] */
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv_ptr[i]) < 0) {
            /* Read failure — pointer itself unreadable, stop. */
            rb->args[i][0] = '\0';
            break;
        }

        if (!arg) {
            /*
             * NULL pointer = argv terminator. All remaining slots are
             * meaningless. Without this break the loop continues into
             * the envp[] array (which follows argv[] in process memory),
             * producing garbage args like "p\ufffdi\ufffd\ufffd\\".
             */
            rb->args[i][0] = '\0';
            break;
        }

        long ret = bpf_probe_read_user_str(rb->args[i], MAX_ARG_LEN, arg);
        if (ret > 0)
            count++;
        else
            rb->args[i][0] = '\0';
    }
    rb->args_count = count;
    rb->_pad = 0;

    bpf_ringbuf_submit(rb, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    /*
     * execve(const char *filename, char *const argv[], char *const envp[])
     * ctx->args[0] = filename  (userspace pointer)
     * ctx->args[1] = argv      (userspace pointer to pointer array)
     * ctx->args[2] = envp      (not captured — too large, done in Go)
     */
    return __do_exec(
        (const char *)ctx->args[0],
        (const char *const *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
    /*
     * execveat(int dirfd, const char *pathname,
     *          char *const argv[], char *const envp[], int flags)
     * ctx->args[0] = dirfd
     * ctx->args[1] = pathname  (userspace pointer)
     * ctx->args[2] = argv      (userspace pointer to pointer array)
     */
    return __do_exec(
        (const char *)ctx->args[1],
        (const char *const *)ctx->args[2]);
}


/* ════════════════════════════════════════════════════════════════════════════
   SECTION 2 — FILE SYSTEM ACTIVITY MONITORING
   Hooks: sys_enter_openat, sys_exit_openat,
          sys_enter_read, sys_enter_write,
          sys_enter_unlinkat, sys_enter_mmap
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * tp_openat_enter — capture path and flags before the syscall executes.
 *
 * We cannot get the returned fd here — it's the return value, available
 * only at sys_exit_openat. So we:
 *   1. Read and classify the path
 *   2. Emit the FILE_OPEN event immediately (fd field = 0xFFFFFFFF)
 *   3. Store path+flags in open_scratch[pid_tgid]
 *      → sys_exit_openat will retrieve this and populate fd_track
 *
 * openat(int dfd, const char __user *filename, int flags, umode_t mode)
 * args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (rate_limit(pid, EVENT_FILE_OPEN) < 0)
        return 0;

    /* Read path from userspace into a scratch fd_val */
    struct fd_val scratch = {};
    bpf_probe_read_user_str(scratch.path, MAX_PATH_LEN,
                            (const char *)ctx->args[1]);
    scratch.flags      = (__u32)ctx->args[2];
    scratch.risk_flags = classify_path_buf(scratch.path);

    /* Save for exit probe */
    bpf_map_update_elem(&open_scratch, &pid_tgid, &scratch, BPF_ANY);

    /* Emit FILE_OPEN event — fd unknown at this point */
    __u32 zero = 0;
    struct file_event *ev = bpf_map_lookup_elem(&file_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    fill_header(&ev->hdr, EVENT_FILE_OPEN);
    __builtin_memcpy(ev->filepath, scratch.path, MAX_PATH_LEN);
    ev->flags      = scratch.flags;
    ev->risk_flags = scratch.risk_flags;
    ev->fd         = 0xFFFFFFFF;    /* sentinel: fd not yet known             */

    struct file_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}

/*
 * tp_openat_exit — get the returned fd and decide whether to track it.
 *
 * We only add to fd_track if the path was classified as interesting
 * (risk_flags != 0). This is the gate that controls read/write volume.
 *
 * The open_scratch entry is always deleted — it's single-use.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    long  fd  = ctx->ret;

    if (fd < 0)
        goto cleanup;   /* syscall failed — nothing to track */

    struct fd_val *scratch = bpf_map_lookup_elem(&open_scratch, &pid_tgid);
    if (!scratch)
        goto cleanup;

    /*
     * Add to fd_track if this file is interesting.
     * Go userspace can extend this by writing to a "watch_paths" config map
     * that we could check here (Part 3 extension).
     */
    if (scratch->risk_flags) {
        struct fd_key fk = { .pid = pid, .fd = (__u32)fd };
        bpf_map_update_elem(&fd_track, &fk, scratch, BPF_ANY);
    }

cleanup:
    bpf_map_delete_elem(&open_scratch, &pid_tgid);
    return 0;
}

/*
 * __do_rw — shared logic for read and write events.
 *
 * Two-stage filter (both must pass to emit an event):
 *   Stage 1: Is this fd in fd_track? (O(1) hash lookup)
 *            No  → return 0 immediately (the common case)
 *            Yes → this is an interesting file, continue
 *   Stage 2: Rate limit check
 *
 * This design means read() on /dev/urandom or a socket emits nothing.
 * Only read() on /etc/passwd (if opened and tracked) would emit.
 */
static __always_inline int __do_rw(__u8 type,
                                    struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 fd  = (__u32)ctx->args[0];

    /* Stage 1: only proceed for tracked fds */
    struct fd_key fk = { .pid = pid, .fd = fd };
    struct fd_val *fv = bpf_map_lookup_elem(&fd_track, &fk);
    if (!fv)
        return 0;

    /* Stage 2: rate limit */
    if (rate_limit(pid, type) < 0)
        return 0;

    __u32 zero = 0;
    struct file_event *ev = bpf_map_lookup_elem(&file_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    fill_header(&ev->hdr, type);
    __builtin_memcpy(ev->filepath, fv->path, MAX_PATH_LEN);
    ev->fd         = fd;
    ev->flags      = fv->flags;
    ev->byte_count = (__u64)ctx->args[2]; /* requested byte count             */
    ev->risk_flags = fv->risk_flags;

    struct file_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
    return __do_rw(EVENT_FILE_RW, ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
    return __do_rw(EVENT_FILE_RW, ctx);
}

/*
 * tp_unlinkat — file deletion.
 *
 * Always emitted regardless of fd_track — a deleted file is always
 * notable for AI agent monitoring (evidence removal, model cleanup).
 *
 * unlinkat(int dfd, const char __user *pathname, int flag)
 * args[0]=dfd, args[1]=pathname, args[2]=flag
 */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (rate_limit(pid, EVENT_FILE_UNLINK) < 0)
        return 0;

    __u32 zero = 0;
    struct file_event *ev = bpf_map_lookup_elem(&file_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    fill_header(&ev->hdr, EVENT_FILE_UNLINK);
    bpf_probe_read_user_str(ev->filepath, MAX_PATH_LEN,
                            (const char *)ctx->args[1]);
    ev->flags      = (__u32)ctx->args[2];
    ev->risk_flags = classify_path_buf(ev->filepath);

    struct file_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}

/*
 * tp_mmap — large file-backed memory mapping (model load detection).
 *
 * Filter criteria (ALL must be true to emit):
 *   1. NOT anonymous (MAP_ANONYMOUS not set) — must be file-backed
 *   2. Size >= MODEL_MMAP_THRESHOLD (100 MB) — models are large
 *   3. PROT_READ set — we're loading data, not just allocating
 *
 * This catches: torch loading .pt/.bin, llama.cpp loading .gguf,
 *               transformers loading .safetensors, ONNX loading .onnx
 *
 * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
 * args: addr=0, len=1, prot=2, flags=3, fd=4, offset=5
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 mmap_len   = (__u64)ctx->args[1];
    __u32 prot       = (__u32)ctx->args[2];
    __u32 mmap_flags = (__u32)ctx->args[3];
    __u32 fd         = (__u32)ctx->args[4];

    /* Filter 1: must be file-backed (not anonymous) */
    if (mmap_flags & MAP_ANONYMOUS)
        return 0;

    /* Filter 2: must be large enough to be a model file */
    if (mmap_len < MODEL_MMAP_THRESHOLD)
        return 0;

    /* Filter 3: must be readable */
    if (!(prot & PROT_READ))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (rate_limit(pid, EVENT_FILE_MMAP) < 0)
        return 0;

    __u32 zero = 0;
    struct file_event *ev = bpf_map_lookup_elem(&file_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    fill_header(&ev->hdr, EVENT_FILE_MMAP);
    ev->fd         = fd;
    ev->prot       = prot;
    ev->byte_count = mmap_len;
    ev->risk_flags = RFLAG_LARGE_MMAP;

    /* Enrich with path if we were tracking this fd */
    struct fd_key fk = { .pid = pid, .fd = fd };
    struct fd_val *fv = bpf_map_lookup_elem(&fd_track, &fk);
    if (fv) {
        __builtin_memcpy(ev->filepath, fv->path, MAX_PATH_LEN);
        ev->risk_flags |= fv->risk_flags;
    }

    struct file_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}


/* ════════════════════════════════════════════════════════════════════════════
   SECTION 3 — NETWORK MONITORING
   Hooks: sys_enter_connect, sys_enter_sendmsg
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * tp_connect — outbound TCP/UDP connection attempt.
 *
 * Reads the sockaddr struct from USERSPACE using bpf_probe_read_user.
 * The sockaddr pointer is a userspace address passed as a syscall argument
 * — we cannot dereference it directly in the kernel, we must copy it.
 *
 * Filters:
 *   - IPv4 only (sa.sin_family == AF_INET). IPv6 extension: check AF_INET6
 *     and cast to sockaddr_in6_t.
 *   - Skip loopback (127.x.x.x) — not relevant for AI agent exfil detection
 *
 * connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
 * args[0]=sockfd, args[1]=sockaddr*, args[2]=addrlen
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (rate_limit(pid, EVENT_NET_CONNECT) < 0)
        return 0;

    /* Copy sockaddr from userspace */
    struct sockaddr_in_t sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) < 0)
        return 0;

    /* Only handle IPv4 for now */
    if (sa.sin_family != AF_INET)
        return 0;

    /* Skip loopback */
    __u32 ip_host = bpf_ntohl(sa.sin_addr);
    if ((ip_host >> 24) == 127)
        return 0;

    __u32 zero = 0;
    struct net_event *ev = bpf_map_lookup_elem(&net_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    fill_header(&ev->hdr, EVENT_NET_CONNECT);

    ev->dst_ip   = sa.sin_addr;              /* keep in network byte order     */
    ev->dst_port = bpf_ntohs(sa.sin_port);   /* convert port to host order    */
    ev->protocol = 6;                         /* TCP (connect is always TCP)   */

    struct net_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}

/*
 * tp_sendmsg — HTTP request detection via payload inspection.
 *
 * How we read HTTP headers WITHOUT kprobes on tcp_sendmsg:
 *
 *   At sys_enter_sendmsg, the data is still in USERSPACE buffers.
 *   The msghdr struct and its iovec chain are userspace pointers.
 *   We read them with bpf_probe_read_user, making this approach:
 *     - Kernel-version independent (no tcp_sendmsg function name)
 *     - CO-RE safe (no kernel struct access)
 *     - Works for both TCP and UDP sends
 *
 * Read chain:
 *   ctx->args[1] → struct user_msghdr_t (userspace)
 *                → msg_iov[0]           (userspace iovec)
 *                → iov_base             (userspace data buffer)
 *                → first N bytes        → HTTP method check
 *
 * VERIFIER NOTE on size masking:
 *   bpf_probe_read_user(buf, size, src) requires the verifier to prove
 *   size <= sizeof(buf). A variable 'peek_len' doesn't satisfy this.
 *   Solution: peek_len & (MAX_HTTP_PEEK - 1)
 *   Since MAX_HTTP_PEEK is a power of 2 (256), this bitwise AND
 *   provably clamps the value to [0, MAX_HTTP_PEEK-1]. Verifier accepts.
 *
 * sendmsg(int sockfd, const struct msghdr *msg, int flags)
 * args[0]=sockfd, args[1]=msghdr*, args[2]=flags
 */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (rate_limit(pid, EVENT_NET_SEND) < 0)
        return 0;

    /* Step 1: read msghdr from userspace */
    struct user_msghdr_t msg = {};
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->args[1]) < 0)
        return 0;

    if (!msg.msg_iov || msg.msg_iovlen == 0)
        return 0;

    /* Step 2: read first iovec from userspace */
    struct iovec_t iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov) < 0)
        return 0;

    if (!iov.iov_base || iov.iov_len == 0)
        return 0;

    /* Step 3: get per-CPU buffer */
    __u32 zero = 0;
    struct net_event *ev = bpf_map_lookup_elem(&net_heap, &zero);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));

    /* Step 4: read first bytes of payload into ev->http_peek */
    __u32 peek_len = (__u32)iov.iov_len;
    if (peek_len > MAX_HTTP_PEEK)
        peek_len = MAX_HTTP_PEEK;

    /*
     * Mask to satisfy verifier: proves peek_len < MAX_HTTP_PEEK.
     * MAX_HTTP_PEEK must be a power of 2 for this to be correct.
     */
    if (bpf_probe_read_user(ev->http_peek,
                            peek_len & (MAX_HTTP_PEEK - 1),
                            iov.iov_base) < 0)
        return 0;

    /* Step 5: only emit if this looks like HTTP */
    if (!is_http_payload(ev->http_peek, peek_len))
        return 0;

    fill_header(&ev->hdr, EVENT_NET_SEND);
    ev->http_peek_len = peek_len;
    ev->risk_flags    = RFLAG_HTTP;

    struct net_event *rb = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb)
        return 0;
    __builtin_memcpy(rb, ev, sizeof(*ev));
    bpf_ringbuf_submit(rb, 0);

    return 0;
}


/* ════════════════════════════════════════════════════════════════════════════
   SECTION 4 — CLEANUP ON PROCESS EXIT
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * tp_proc_exit — remove proc_tree entry when a process dies.
 *
 * fd_track entries for this pid become stale after exit. We do NOT
 * iterate and clean them here because:
 *   1. eBPF cannot iterate a hash map and delete during iteration
 *   2. The overhead of a full scan on every exit is too high
 *   3. Stale entries are bounded (max 65536) and naturally stop
 *      being queried (no more read/write from a dead process)
 *
 * Go userspace performs periodic fd_track sweeps using the proc_tree
 * absence as a signal that the pid is gone.
 */
SEC("tracepoint/sched/sched_process_exit")
int tp_proc_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;

    /* Only act on main thread exit (process exit, not just thread exit) */
    if (pid != tid)
        return 0;

    bpf_map_delete_elem(&proc_tree, &pid);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
   SECTION 5 — TLS PLAINTEXT CAPTURE (uprobes on libssl.so)

   These programs attach to SSL_write and SSL_read in OpenSSL/BoringSSL.
   They intercept plaintext BEFORE encryption (SSL_write) and AFTER
   decryption (SSL_read), giving full HTTPS visibility without keys.

   Uprobe ABI — System V AMD64 calling convention:
     SSL_write(SSL *ssl, const void *buf, int num)
       PT_REGS_PARM1 = ssl  (ignored)
       PT_REGS_PARM2 = buf  (plaintext data)
       PT_REGS_PARM3 = num  (byte count)

     SSL_read(SSL *ssl, void *buf, int num)
       PT_REGS_PARM2 = buf  (output buffer — written AFTER return)
       PT_REGS_RC           (actual bytes read — only valid at return)

   Attach: NOT via tracepoint. Go loader calls
     link.OpenExecutable(libssl_path).Uprobe("SSL_write", prog, nil)
   for every unique libssl.so found in /proc/<pid>/maps.
   ════════════════════════════════════════════════════════════════════════════ */

/*
 * __emit_tls — shared ring buffer write for both TLS send and recv.
 *
 * Writes directly to ring buffer (no scratch buffer) because tls_event
 * is 1088 bytes — too large for reliable inline memset on the stack.
 * Same pattern as __do_exec.
 *
 * Size masking: peek & (MAX_TLS_PEEK - 1) proves to the verifier that
 * peek < MAX_TLS_PEEK, satisfying bounds-check on rb->payload[0..peek-1].
 * MAX_TLS_PEEK must be a power of 2 (1024). A peek of 0 reads nothing.
 */
static __always_inline int __emit_tls(__u8 event_type,
                                       __u64 buf_ptr,
                                       __u32 n)
{
    if (buf_ptr == 0 || n == 0)
        return 0;

    struct tls_event *rb = bpf_ringbuf_reserve(&events,
                                                sizeof(struct tls_event), 0);
    if (!rb)
        return 0;

    /* Build header on stack (56 bytes — safe) */
    struct mon_hdr hdr = {};
    fill_header(&hdr, event_type);
    rb->hdr = hdr;

    rb->payload_len = n;
    rb->_pad = 0;

    /* Clamp and mask for verifier bounds proof */
    __u32 peek = n < MAX_TLS_PEEK ? n : MAX_TLS_PEEK;
    peek = peek & (MAX_TLS_PEEK - 1);

    if (peek > 0) {
        if (bpf_probe_read_user(rb->payload, peek, (void *)buf_ptr) < 0) {
            bpf_ringbuf_discard(rb, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit(rb, 0);
    return 0;
}

/*
 * uprobe_ssl_write — fires at entry of SSL_write in libssl.so.
 *
 * SSL_write(SSL *ssl, const void *buf, int num)
 *   buf (PT_REGS_PARM2) = plaintext to encrypt
 *   num (PT_REGS_PARM3) = byte count
 *
 * We read the plaintext BEFORE OpenSSL encrypts it.
 */
SEC("uprobe")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    __u64 buf_ptr = PT_REGS_PARM2(ctx);
    __u32 n       = (__u32)(long)PT_REGS_PARM3(ctx);
    return __emit_tls(EVENT_TLS_SEND, buf_ptr, n);
}

/*
 * uprobe_ssl_read_entry — fires at entry of SSL_read in libssl.so.
 *
 * SSL_read(SSL *ssl, void *buf, int num)
 *   buf (PT_REGS_PARM2) = output buffer — data is written AFTER return
 *
 * We stash the buf pointer in ssl_read_args so the return probe can use it.
 */
SEC("uprobe")
int uprobe_ssl_read_entry(struct pt_regs *ctx)
{
    __u64 buf_ptr = PT_REGS_PARM2(ctx);
    if (buf_ptr == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/*
 * uretprobe_ssl_read — fires when SSL_read returns.
 *
 * PT_REGS_RC = number of bytes actually read (≤0 means error/EOF/retry).
 * Retrieves the stashed buf pointer and reads the now-decrypted data.
 */
SEC("uretprobe")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 *buf_ptr_p = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!buf_ptr_p)
        return 0;

    __u64 buf_ptr = *buf_ptr_p;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    long ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    return __emit_tls(EVENT_TLS_RECV, buf_ptr, (__u32)ret);
}

/* Required: declares this program is GPL-licensed,
 * enabling use of GPL-only BPF helpers. */
char LICENSE[] SEC("license") = "GPL";
