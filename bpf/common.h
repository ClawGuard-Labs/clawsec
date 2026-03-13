/* common.h — shared types, constants, and map key definitions
 *
 * Written by eBPF programs, read by Go daemon via ring buffer.
 * Keep field alignment explicit — Go binary.Read is strict on padding.
 *
 * Compatibility: Linux 5.15 (Ubuntu 22.04) and 6.x (Ubuntu 24.04)
 * Approach: CO-RE + tracepoints only (no kprobes, no hardcoded offsets)
 */
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Limits ──────────────────────────────────────────────────────────────── */
#define MAX_ARGS            16
#define MAX_ARG_LEN         128
#define MAX_PATH_LEN        256
#define TASK_COMM_LEN       16
#define MAX_HTTP_PEEK       256
#define MAX_TLS_PEEK        1024    /* larger to capture full HTTP/2 headers  */

/* ── Event Types (event_header.event_type) ───────────────────────────────── */
#define EVENT_EXEC          1   /* execve / execveat                         */
#define EVENT_FILE_OPEN     2   /* openat enter                              */
#define EVENT_FILE_RW       3   /* read / write on tracked fd                */
#define EVENT_FILE_UNLINK   4   /* unlinkat                                  */
#define EVENT_FILE_MMAP     5   /* mmap with large file-backed mapping       */
#define EVENT_NET_CONNECT   6   /* connect() syscall                         */
#define EVENT_NET_SEND      7   /* sendmsg() with HTTP payload detected      */
#define EVENT_TLS_SEND      8   /* SSL_write plaintext peek (pre-encryption) */
#define EVENT_TLS_RECV      9   /* SSL_read plaintext peek (post-decryption) */

/* ── Risk Flags (set in kernel, further enriched in Go userspace) ────────── */
#define RFLAG_SENSITIVE     (1 << 0)  /* /etc/ /proc/ /sys/ /.ssh/ prefix    */
#define RFLAG_LARGE_MMAP    (1 << 1)  /* mmap > 100 MB → likely model load   */
#define RFLAG_HTTP          (1 << 2)  /* HTTP method detected in send buffer  */

/* ── Rate Limiting ───────────────────────────────────────────────────────── */
#define RATE_MAX            100              /* max events per pid per window  */
#define RATE_WINDOW_NS      1000000000ULL   /* 1-second sliding window        */

/* ── Model mmap threshold ────────────────────────────────────────────────── */
#define MODEL_MMAP_THRESHOLD  (100ULL * 1024 * 1024)   /* 100 MB             */

/* ── Error codes (not exposed as macros in vmlinux.h) ────────────────────── */
#ifndef EPERM
#define EPERM               1
#endif

/* ── Address family constants (not always in vmlinux.h for eBPF) ─────────── */
#define AF_INET             2
#define AF_INET6            10

/* ── mmap protection flags ───────────────────────────────────────────────── */
#define PROT_READ           0x1
#define MAP_ANONYMOUS       0x20

/* ═══════════════════════════════════════════════════════════════════════════
   Event Structs
   All structs sent over the ring buffer must be fixed-size.
   Explicit padding ensures Go binary.Read decodes correctly.
   ═══════════════════════════════════════════════════════════════════════════ */

/*
 * mon_hdr — common prefix for every event.
 * Named with mon_ prefix to avoid collision with kernel's event_header
 * type that is present in vmlinux.h on some kernel versions.
 * Go side reads this first to determine which struct follows.
 */
struct mon_hdr {
    __u64 timestamp_ns;          /* bpf_ktime_get_ns()                       */
    __u32 pid;                   /* process id (tgid in kernel terms)         */
    __u32 ppid;                  /* parent process id                         */
    __u32 uid;                   /* real user id                              */
    __u32 gid;                   /* real group id                             */
    __u64 cgroup_id;             /* bpf_get_current_cgroup_id()               */
    __u8  event_type;            /* EVENT_* constant above                    */
    __u8  _pad[7];               /* align struct to 8 bytes                  */
    char  comm[TASK_COMM_LEN];   /* process name, null-terminated             */
};

/*
 * exec_event — emitted on execve / execveat.
 * Captures the full command line reconstructed from argv[].
 */
struct exec_event {
    struct mon_hdr hdr;
    char  filename[MAX_PATH_LEN];           /* argv[0] / execve pathname      */
    char  args[MAX_ARGS][MAX_ARG_LEN];      /* argv[1..N]                     */
    __u32 args_count;                       /* number of args captured        */
    __u32 _pad;
};

/*
 * file_event — emitted on open / read / write / unlink / mmap.
 * For read/write: only fired when the fd is in fd_track map
 * (i.e., the file was previously opened and classified as interesting).
 */
struct file_event {
    struct mon_hdr hdr;
    char  filepath[MAX_PATH_LEN];   /* absolute path (best-effort)            */
    __u32 fd;                       /* file descriptor                        */
    __u32 flags;                    /* open(2) flags (O_RDONLY etc.)          */
    __u64 byte_count;               /* bytes requested (read/write) or mmap sz*/
    __u32 prot;                     /* mmap prot flags                        */
    __u32 risk_flags;               /* RFLAG_* bitmask                        */
};

/*
 * net_event — emitted on connect() and HTTP sendmsg().
 * http_peek holds the first MAX_HTTP_PEEK bytes of the send buffer
 * when an HTTP method is detected (EVENT_NET_SEND).
 */
struct net_event {
    struct mon_hdr hdr;
    __u32 dst_ip;                   /* destination IPv4, network byte order   */
    __u16 dst_port;                 /* destination port, host byte order      */
    __u8  protocol;                 /* IPPROTO_TCP=6, IPPROTO_UDP=17          */
    __u8  _pad;
    char  http_peek[MAX_HTTP_PEEK]; /* first bytes of HTTP request            */
    __u32 http_peek_len;            /* valid bytes in http_peek               */
    __u32 risk_flags;               /* RFLAG_* bitmask                        */
};

/*
 * tls_event — plaintext TLS payload peek.
 * Emitted by SSL_write uprobe (before encryption) and SSL_read uretprobe
 * (after decryption). Captures the plaintext that OpenSSL is about to
 * encrypt / has just decrypted, giving visibility into HTTPS traffic
 * without decryption keys or MITM proxying.
 */
struct tls_event {
    struct mon_hdr hdr;
    char  payload[MAX_TLS_PEEK];    /* plaintext peek (first N bytes)        */
    __u32 payload_len;              /* total payload length (may exceed peek)*/
    __u32 _pad;
};

/* ═══════════════════════════════════════════════════════════════════════════
   Map Key / Value Types
   ═══════════════════════════════════════════════════════════════════════════ */

/*
 * fd_key — composite key for fd_track map.
 * Uniquely identifies an open file descriptor within a process.
 */
struct fd_key {
    __u32 pid;
    __u32 fd;
};

/*
 * fd_val — stored per tracked fd.
 * Only interesting fds are tracked (sensitive paths, model files).
 */
struct fd_val {
    char  path[MAX_PATH_LEN];
    __u32 flags;
    __u32 risk_flags;
};

/*
 * rate_key — composite key for rate_limiter map.
 */
struct rate_key {
    __u32 pid;
    __u8  event_type;
    __u8  _pad[3];
};

/*
 * rate_val — sliding-window counter per (pid, event_type).
 */
struct rate_val {
    __u64 window_ns;    /* start of current 1-second window                  */
    __u32 count;        /* events fired in this window                        */
    __u32 _pad;
};

/*
 * Userspace msghdr ABI — stable across all kernel versions.
 * Defined here so we don't rely on kernel headers for a userspace struct.
 */
struct user_msghdr_t {
    void           *msg_name;
    int             msg_namelen;
    int             _pad1;
    struct iovec   *msg_iov;
    unsigned long   msg_iovlen;
    void           *msg_control;
    unsigned long   msg_controllen;
    unsigned int    msg_flags;
    unsigned int    _pad2;
};

/*
 * iovec_t — userspace iovec, stable ABI.
 */
struct iovec_t {
    void          *iov_base;
    unsigned long  iov_len;
};

/*
 * sockaddr_in_t — IPv4 socket address, stable userspace ABI.
 */
struct sockaddr_in_t {
    __u16 sin_family;   /* AF_INET                                            */
    __u16 sin_port;     /* port in network byte order                         */
    __u32 sin_addr;     /* IPv4 in network byte order                         */
    __u8  sin_zero[8];  /* padding                                            */
};

/* ═══════════════════════════════════════════════════════════════════════════
   LSM Self-Protection Types and Constants
   Used by SEC("lsm/...") programs in Section 6 of monitor.bpf.c.
   ═══════════════════════════════════════════════════════════════════════════ */

/*
 * inode_key — composite BPF map key that uniquely identifies a file inode.
 *
 * Using both inode number and device number prevents false matches when two
 * different filesystems happen to have the same inode number (common on
 * tmpfs vs ext4). Must be 16 bytes to keep BPF map key alignment clean.
 *
 * Go mirror: loader.inodeKey  (same field order, same sizes).
 */
struct inode_key {
    __u64 ino;    /* inode number — bpf_core_read(inode, i_ino)               */
    __u32 dev;    /* block device  — bpf_core_read(inode, i_sb, s_dev)        */
    __u32 _pad;   /* explicit 4-byte pad for 8-byte struct alignment           */
};

/*
 * Linux VFS permission mask bits (from include/linux/fs.h).
 * Defined with ifndef guards — vmlinux.h does not export preprocessor macros,
 * only type definitions. Values are stable across all kernel versions we
 * support (5.15 and 6.x).
 */
#ifndef MAY_WRITE
#define MAY_WRITE   0x00000002u
#endif
#ifndef MAY_APPEND
#define MAY_APPEND  0x00000008u
#endif

/*
 * FMODE_CAN_WRITE — fmode_t bit that indicates a BPF map fd was opened
 * for writing.  Set by the kernel in map_get_fd_by_id() when the caller
 * does NOT pass BPF_F_RDONLY. Value is stable across 5.x / 6.x kernels.
 *
 * Note: this is different from FMODE_WRITE (0x2). FMODE_CAN_WRITE (0x40000)
 * is what security_bpf_map() receives for write-capable map fds.
 */
#define FMODE_CAN_WRITE_BIT  0x00040000ULL
