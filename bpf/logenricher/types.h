// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <shared/obi_ctx.h>

enum {
    // include/linux/tty_driver.h
    k_tty_driver_type_pty = 0x0004,
    k_tty_driver_subtype_pty_master = 0x0001,

    // include/uapi/asm-generic/termbits.h
    k_echo = 0x00008,

    // log handling
    k_log_event_max_size = 1 << 15,    // 32K
    k_log_event_max_log_len = 1 << 13, // 8K

    // iovec
    k_iov_max_segs = 8,
    k_iov_seg_max_len = 1 << 13, // 8K

    // terminal file
    k_pts_file_path_len_max = 64,
    k_pts_file_path_len_max_mask = k_pts_file_path_len_max - 1,
};

static const char k_newline = '\n';

// Userspace publishes this exact process-lifetime identity before arming a
// host TGID. Keep this ABI fixed-width: bpf2go mirrors it in Go and the BPF
// program validates every field before touching the application's log buffer.
typedef struct log_enricher_generation {
    u64 process_instance_id;
    u64 process_start_ticks;
    u64 executable_device;
    u64 executable_inode;
    u64 lifecycle_epoch;
} log_enricher_generation_t;

_Static_assert(sizeof(log_enricher_generation_t) == 40,
               "log enricher generation ABI size mismatch");
_Static_assert(__builtin_offsetof(log_enricher_generation_t, process_instance_id) == 0,
               "log enricher generation process-instance offset mismatch");
_Static_assert(__builtin_offsetof(log_enricher_generation_t, process_start_ticks) == 8,
               "log enricher generation process-start offset mismatch");
_Static_assert(__builtin_offsetof(log_enricher_generation_t, executable_device) == 16,
               "log enricher generation executable-device offset mismatch");
_Static_assert(__builtin_offsetof(log_enricher_generation_t, executable_inode) == 24,
               "log enricher generation executable-inode offset mismatch");
_Static_assert(__builtin_offsetof(log_enricher_generation_t, lifecycle_epoch) == 32,
               "log enricher generation lifecycle-epoch offset mismatch");

typedef struct log_event {
    u32 tgid;
    u32 len;
    u64 process_instance_id;
    u64 lifecycle_epoch;
    u64 target_device;
    u64 target_inode;
    u32 fd;
    u32 reserved;
    obi_ctx_info_t ctx;
    u8 file_path[k_pts_file_path_len_max];
    u8 log[];
} log_event_t;

const log_event_t *log_event__unused __attribute__((unused));

enum tty_driver_type___new {
    TTY_DRIVER_TYPE_SYSTEM,
    TTY_DRIVER_TYPE_CONSOLE,
    TTY_DRIVER_TYPE_SERIAL,
    TTY_DRIVER_TYPE_PTY,
    TTY_DRIVER_TYPE_SCC,
    TTY_DRIVER_TYPE_SYSCONS,
};

enum tty_driver_subtype___new {
    SYSTEM_TYPE_TTY = 1,
    SYSTEM_TYPE_CONSOLE,
    SYSTEM_TYPE_SYSCONS,
    SYSTEM_TYPE_SYSPTMX,

    PTY_TYPE_MASTER = 1,
    PTY_TYPE_SLAVE,

    SERIAL_TYPE_NORMAL = 1,
};

struct tty_termios {
    u32 c_lflag;
    // ...unused fields
};

struct tty_dev {
    u16 minor;
    u16 major;
    struct tty_termios termios;
};

static __always_inline void tty_dev_fill(struct tty_dev *dev, struct tty_struct *tty) {
    BPF_CORE_READ_INTO(&dev->major, tty, driver, major);
    BPF_CORE_READ_INTO(&dev->minor, tty, driver, minor_start);
    dev->minor += BPF_CORE_READ(tty, index);
    dev->termios.c_lflag = BPF_CORE_READ(tty, termios.c_lflag);
}

static __always_inline bool tty_driver_is_pty(struct tty_struct *tty) {
    int typ;
    if (bpf_core_enum_value_exists(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY)) {
        typ = bpf_core_enum_value(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY);
    } else {
        typ = k_tty_driver_type_pty;
    }

    if (bpf_core_field_exists(((struct tty_driver *)0)->type)) {
        return BPF_CORE_READ(tty, driver, type) == typ;
    }

    return false;
}

static __always_inline bool tty_driver_is_master(struct tty_struct *tty) {
    int typ;
    if (bpf_core_enum_value_exists(enum tty_driver_subtype___new, PTY_TYPE_MASTER)) {
        typ = bpf_core_enum_value(enum tty_driver_subtype___new, PTY_TYPE_MASTER);
    } else {
        typ = k_tty_driver_subtype_pty_master;
    }

    if (bpf_core_field_exists(((struct tty_driver *)0)->subtype)) {
        return BPF_CORE_READ(tty, driver, subtype) == typ;
    }

    return false;
}
