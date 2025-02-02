//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/version.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
    u32 pid;          // Process ID
    u32 uid;          // User ID
    u8 comm[16];      // Command name
    u32 mode;         // New file permissions (mode)
    char filename[256]; // File path
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_chmod")
int file_permissions_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct event *data;

    // Allocate ring buffer space for event data
    data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!data) {
        bpf_printk("Error - ringbuffer is full\n");
        return 0;
    }

    // Fill event data
    data->pid = bpf_get_current_pid_tgid();
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Retrieve the first argument (permission mode)
    data->mode = (u32)ctx->args[1]; // args[1] is the mode in chmod(path, mode)

    // Retrieve the second argument (file path)
    const char *file_path = (const char *)ctx->args[0]; // args[0] is the path in chmod(path, mode)
    if (bpf_probe_read_user_str(&data->filename, sizeof(data->filename), file_path) < 0) {
        bpf_printk("Error - failed to read file path\n");
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(data, 0);

    return 0;
}

// Pending to add
SEC("tracepoint/syscalls/sys_enter_fchmod")
int file_permissions_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct event *data;

    // Allocate ring buffer space for event data
    data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!data) {
        bpf_printk("Error - ringbuffer is full\n");
        return 0;
    }

    // Fill event data
    data->pid = bpf_get_current_pid_tgid();
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Retrieve the mode (second argument)
    data->mode = (u32)ctx->args[1];

    // For fchmod, the file is referenced by a file descriptor, so we can't easily get the path
    bpf_probe_read_kernel_str(&data->filename, sizeof(data->filename), "fd-based");

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(data, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int file_permissions_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct event *data;

    // Allocate ring buffer space for event data
    data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!data) {
        bpf_printk("Error - ringbuffer is full\n");
        return 0;
    }

    // Fill event data
    data->pid = bpf_get_current_pid_tgid();
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Retrieve the mode (third argument)
    data->mode = (u32)ctx->args[2];

    // Retrieve the file path (second argument)
    const char *file_path = (const char *)ctx->args[1];
    if (bpf_probe_read_user_str(&data->filename, sizeof(data->filename), file_path) < 0) {
        bpf_printk("Error - failed to read file path\n");
        bpf_ringbuf_discard(data, 0);
        return 0;
    }

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(data, 0);

    return 0;
}
