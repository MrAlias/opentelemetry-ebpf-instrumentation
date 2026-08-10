// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/compiler.h>

#include <common/iov_iter.h>
#include <common/scratch_mem.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

#include <logenricher/path_resolver.h>
#include <logenricher/types.h>

#include <logenricher/maps/log_enricher_generations.h>
#include <logenricher/maps/log_enricher_lifecycle_epochs.h>
#include <logenricher/maps/log_enricher_pids.h>
#include <logenricher/maps/log_events.h>
#include <logenricher/maps/pid_fd.h>
#include <logenricher/maps/zeros.h>

#include <shared/obi_ctx.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SCRATCH_MEM_SIZED(log_event, k_log_event_max_size);

// Linux exposes /proc/<pid>/stat starttime in USER_HZ ticks. USER_HZ is 100
// on both supported BPF targets, and nsec_to_clock_t() therefore performs
// this exact division for task_struct's nanosecond start timestamp.
static const u64 k_nsec_per_process_start_tick = 10000000ULL;

static __always_inline u64 log_enricher_encode_stat_device(u32 dev) {
    const u32 major = dev >> 20;
    const u32 minor = dev & ((1U << 20) - 1);

    // Match new_encode_dev(), which is the st_dev representation returned to userspace.
    return (u64)((minor & 0xffU) | (major << 8) | ((minor & ~0xffU) << 12));
}

// Kernels predating task_struct::start_boottime called the /proc starttime
// source real_start_time. The CO-RE flavor suffix maps this declaration back
// to task_struct without requiring the build kernel to contain the old field.
struct task_struct___real_start_time {
    u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline bool process_start_ticks(const struct task_struct *leader, u64 *ticks) {
    u64 start_ns = 0;

    if (bpf_core_field_exists(((struct task_struct *)0)->start_boottime)) {
        start_ns = BPF_CORE_READ(leader, start_boottime);
    } else if (bpf_core_field_exists(
                   ((struct task_struct___real_start_time *)0)->real_start_time)) {
        start_ns =
            BPF_CORE_READ((const struct task_struct___real_start_time *)leader, real_start_time);
    } else {
        // start_time is intentionally not a fallback: unlike start_boottime
        // (and its old real_start_time name), it does not provably match the
        // starttime value exported by /proc/<pid>/stat across suspend.
        return false;
    }

    *ticks = start_ns / k_nsec_per_process_start_tick;
    return *ticks != 0;
}

static __always_inline bool
log_enricher_generation_matches_task(const log_enricher_generation_t *generation,
                                     const struct task_struct *task) {
    if (!generation || !generation->process_instance_id || !generation->process_start_ticks ||
        !generation->executable_device || !generation->executable_inode ||
        !generation->lifecycle_epoch) {
        return false;
    }

    const u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const u64 *lifecycle_epoch = bpf_map_lookup_elem(&log_enricher_lifecycle_epochs, &tgid);
    if (!lifecycle_epoch) {
        return false;
    }
    const u64 current_lifecycle_epoch = *lifecycle_epoch;
    if (!current_lifecycle_epoch || current_lifecycle_epoch != generation->lifecycle_epoch) {
        return false;
    }

    const struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) {
        return false;
    }

    u64 current_start_ticks = 0;
    if (!process_start_ticks(leader, &current_start_ticks) ||
        current_start_ticks != generation->process_start_ticks) {
        return false;
    }

    const struct mm_struct *mm = BPF_CORE_READ(leader, mm);
    if (!mm) {
        return false;
    }
    const struct file *executable = BPF_CORE_READ(mm, exe_file);
    if (!executable) {
        return false;
    }
    const struct inode *inode = BPF_CORE_READ(executable, f_inode);
    if (!inode) {
        return false;
    }
    const struct super_block *superblock = BPF_CORE_READ(inode, i_sb);
    if (!superblock) {
        return false;
    }

    const u32 raw_device = (u32)BPF_CORE_READ(superblock, s_dev);
    const u64 current_device = log_enricher_encode_stat_device(raw_device);
    const u64 current_inode = (u64)BPF_CORE_READ(inode, i_ino);
    return current_device == generation->executable_device &&
           current_inode == generation->executable_inode;
}

static __always_inline int log_enricher_retire_current_process(void) {
    const u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 *lifecycle_epoch = bpf_map_lookup_elem(&log_enricher_lifecycle_epochs, &tgid);
    if (!lifecycle_epoch) {
        return 0;
    }

    // Epoch zero is never valid. Skip it on the practically unreachable wrap
    // so no stale generation can become eligible through an ABA transition.
    const u64 previous_epoch = __sync_fetch_and_add(lifecycle_epoch, 1);
    if (previous_epoch == ~0ULL) {
        __sync_fetch_and_add(lifecycle_epoch, 1);
    }
    bpf_map_delete_elem(&log_enricher_generations, &tgid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int obi_log_enricher_process_exec(void *ctx) {
    (void)ctx;

    return log_enricher_retire_current_process();
}

SEC("tracepoint/sched/sched_process_exit")
int obi_log_enricher_process_exit(void *ctx) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) != 0) {
        return 0;
    }

    return log_enricher_retire_current_process();
}

static __always_inline bool pid_tracked(const struct task_struct *task) {
    u32 ns_pid = 0;
    u32 ns_ppid = 0;
    u32 ns_id = 0;

    ns_pid_ppid(task, (int *)&ns_pid, (int *)&ns_ppid, &ns_id);

    u64 key = ((u64)ns_id << 32) | ns_pid;

    u8 *tracked = bpf_map_lookup_elem(&log_enricher_pids, &key);
    if (tracked != NULL) {
        return true;
    }

    key = ((u64)ns_id << 32) | ns_ppid;

    tracked = bpf_map_lookup_elem(&log_enricher_pids, &key);
    return tracked != NULL;
}

static __always_inline u32 consume_ubuf(log_event_t *e,
                                        struct iov_iter *from,
                                        void *ubuf,
                                        const char *fill) {
    const size_t count = BPF_CORE_READ(from, count);
    u32 to_copy = (u32)count;

    bpf_clamp_umax(to_copy, k_log_event_max_log_len);
    if (to_copy == 0) {
        return 0;
    }

    bpf_probe_read_user(e->log, to_copy, ubuf);
    bpf_clamp_umin(to_copy, 1);
    bpf_probe_write_user(ubuf, fill, to_copy);
    bpf_probe_write_user((char *)ubuf + to_copy - 1, &k_newline, 1);

    return to_copy;
}

static __always_inline u32 consume_iovec(log_event_t *e,
                                         const struct iovec *iov,
                                         unsigned long nr_segs,
                                         const char *fill) {
    u32 tot = 0;
    void *last_end = NULL;

    bpf_clamp_umax(nr_segs, k_iov_max_segs);

    for (unsigned long i = 0; i < k_iov_max_segs && i < nr_segs; i++) {
        struct iovec vec;
        if (bpf_probe_read_kernel(&vec, sizeof(vec), &iov[i]) != 0) {
            break;
        }
        if (!vec.iov_base || !vec.iov_len) {
            continue;
        }

        u32 to_copy = (u32)vec.iov_len;
        bpf_clamp_umax(to_copy, k_iov_seg_max_len);
        bpf_clamp_umax(tot, k_log_event_max_log_len);
        if (tot + to_copy > k_log_event_max_log_len) {
            break;
        }

        bpf_probe_read_user(&e->log[tot], to_copy, vec.iov_base);
        bpf_clamp_umin(to_copy, 1);
        bpf_probe_write_user(vec.iov_base, fill, to_copy);
        last_end = (char *)vec.iov_base + to_copy - 1;
        tot += to_copy;
    }

    if (last_end) {
        bpf_probe_write_user(last_end, &k_newline, 1);
    }
    return tot;
}

static __always_inline int
__write(struct kiocb *iocb, struct iov_iter *from, const int fd, const struct task_struct *task) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 tgid = pid_tgid >> 32;
    const log_enricher_generation_t *generation =
        bpf_map_lookup_elem(&log_enricher_generations, &tgid);
    if (!log_enricher_generation_matches_task(generation, task)) {
        return 0;
    }
    const u64 process_instance_id = generation->process_instance_id;
    const u64 lifecycle_epoch = generation->lifecycle_epoch;

    const struct file *target = BPF_CORE_READ(iocb, ki_filp);
    if (!target) {
        return 0;
    }
    const struct inode *target_inode = BPF_CORE_READ(target, f_inode);
    if (!target_inode) {
        return 0;
    }
    const struct super_block *target_superblock = BPF_CORE_READ(target_inode, i_sb);
    if (!target_superblock) {
        return 0;
    }
    const u64 target_device =
        log_enricher_encode_stat_device((u32)BPF_CORE_READ(target_superblock, s_dev));
    const u64 target_inode_number = (u64)BPF_CORE_READ(target_inode, i_ino);
    if (!target_device || !target_inode_number) {
        return 0;
    }

    iovec_iter_ctx ictx;
    get_iovec_ctx(&ictx, (struct iov_iter___dummy *)from);

    log_event_t *e = (log_event_t *)log_event_mem();
    if (!e) {
        bpf_dbg_printk("logenricher: failed to reserve event space");
        return 0;
    }
    char *fill = bpf_map_lookup_elem(&zeros, &(u32){0});
    if (!fill) {
        bpf_dbg_printk("logenricher: failed to get zero buffer");
        return 0;
    }

    obi_ctx_info_t *obi_ctx = obi_ctx__get(pid_tgid);
    e->tgid = tgid;
    e->process_instance_id = process_instance_id;
    e->lifecycle_epoch = lifecycle_epoch;
    e->target_device = target_device;
    e->target_inode = target_inode_number;
    e->reserved = 0;
    e->ctx = obi_ctx ? *obi_ctx : (obi_ctx_info_t){0};
    e->fd = fd;

    u32 tot = 0;

    if (bpf_core_enum_value_exists(enum iter_type___dummy, ITER_UBUF) &&
        ictx.iter_type == bpf_core_enum_value(enum iter_type___dummy, ITER_UBUF) && ictx.ubuf) {
        tot = consume_ubuf(e, from, ictx.ubuf, fill);
    } else if (ictx.iter_type == bpf_core_enum_value(enum iter_type, ITER_IOVEC) && ictx.iov) {
        tot = consume_iovec(e, ictx.iov, ictx.nr_segs, fill);
    } else {
        bpf_dbg_printk("logenricher: unsupported iter_type %d", ictx.iter_type);
        return 0;
    }

    e->len = tot;
    if (e->len == 0) {
        return 0;
    }

    if (fd == 0) {
        // We are in the TTY path so we can resolve the filepath
        // from the file struct.
        // NOTE: we could theoretically use the FD similarly to how
        // we do in the pipe case, this approach has less moving parts.
        struct path path = BPF_CORE_READ(iocb, ki_filp, f_path);
        resolve_path((char *)e->file_path, &path, task);
    } else {
        // This is a pipe write, there's no file path to resolve in the
        // file struct, we will write to the process FD directly.
        e->file_path[0] = '\0';
    }

    u64 out_size = sizeof(log_event_t) + e->len;
    bpf_clamp_umax(out_size, k_log_event_max_size);
    const long err = bpf_ringbuf_output(&log_events, e, out_size, log_events_flags());
    if (err < 0) {
        bpf_dbg_printk("logenricher: failed to write log event to ringbuf: %d", err);
    }

    return 0;
}

SEC("kprobe/tty_write")
int BPF_KPROBE(obi_kprobe_tty_write, struct kiocb *iocb, struct iov_iter *from) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    struct tty_file_private *tfp =
        (struct tty_file_private *)BPF_CORE_READ(iocb, ki_filp, private_data);
    struct tty_struct *tty = BPF_CORE_READ(tfp, tty);
    const bool is_master = tty_driver_is_pty(tty) && tty_driver_is_master(tty);

    struct tty_dev master = {};
    struct tty_dev slave = {};
    if (is_master) {
        struct tty_struct *lnk = BPF_CORE_READ(tty, link);
        tty_dev_fill(&master, tty);
        tty_dev_fill(&slave, lnk);
    } else {
        tty_dev_fill(&slave, tty);
    }

    if (slave.major == 0 && slave.minor == 0) {
        return 0;
    }

    if ((is_master && !(master.termios.c_lflag & k_echo)) && !(slave.termios.c_lflag & k_echo)) {
        return 0;
    }

    return __write(iocb, from, 0, task);
}

SEC("kprobe/pipe_write")
int BPF_KPROBE(obi_kprobe_pipe_write, struct kiocb *iocb, struct iov_iter *from) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    int *fdp = bpf_map_lookup_elem(&pid_fd, &(u64){bpf_get_current_pid_tgid()});
    if (!fdp) {
        return 0;
    }

    return __write(iocb, from, *fdp, task);
}

static __always_inline int __record_fd(unsigned int fd) {
    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    if (bpf_map_update_elem(&pid_fd, &(u64){bpf_get_current_pid_tgid()}, (int *)&fd, BPF_ANY)) {
        bpf_dbg_printk("logenricher: failed to update pid_fd map");
    }

    return 0;
}

SEC("kprobe/ksys_write")
int BPF_KPROBE(obi_kprobe_ksys_write, unsigned int fd) {
    (void)ctx;
    return __record_fd(fd);
}

// writev() bypasses ksys_write, so pipe_write can't find the fd.
// Hook do_writev to capture the fd for writev() calls too.
SEC("kprobe/do_writev")
int BPF_KPROBE(obi_kprobe_do_writev, unsigned long fd) {
    (void)ctx;
    return __record_fd((unsigned int)fd);
}
