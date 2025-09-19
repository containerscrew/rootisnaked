#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

#define WINDOW_NS (5ULL * 60ULL * 1000000000ULL) // 5 minutes

struct dedup_entry {
  __u64 last_seen_ns;
};

struct dedup_key {
  __u32 tgid;
  __u64 start_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct dedup_key);
  __type(value, struct dedup_entry);
  __uint(max_entries, 8192);
} active_processes SEC(".maps");

/* Portable read of kernel_cap_t into u64 without assuming .cap[] exists */
static __always_inline __u64 read_caps(const struct cred* c) {
  __u64 out = 0;

  /* Fast path: kernels where cap_effective has a .val member (u64) */
  if (bpf_core_field_exists(struct cred, cap_effective.val)) {
    BPF_CORE_READ_INTO(&out, c, cap_effective.val);
    return out;
  }

  /* Fallback: copy the first 8 bytes of cap_effective as raw bytes */
  struct {
    __u32 lo;
    __u32 hi;
  } tmp = {};
  int sz = bpf_core_field_size(struct cred, cap_effective);
  if (sz <= 0) return 0;
  int copy = sz < 8 ? sz : 8;
  bpf_core_read(&tmp, copy, &c->cap_effective);

  out = ((__u64)tmp.hi << 32) | tmp.lo;
  return out;
}

/* Returns 1 if we should emit (and updates the timestamp),
 * returns 0 if we must skip (within the 5-min window).
 */
static __always_inline int should_emit(const struct dedup_key* key,
  __u64 now_ns) {
  struct dedup_entry* entry = bpf_map_lookup_elem(&active_processes, key);
  if (entry) {
    __u64 dt = now_ns - entry->last_seen_ns;
    if (dt < WINDOW_NS) return 0;
    entry->last_seen_ns = now_ns; // best-effort update; minor races acceptable
    return 1;
  }
  else {
    struct dedup_entry newval = { .last_seen_ns = now_ns };
    bpf_map_update_elem(&active_processes, key, &newval, BPF_ANY);
    return 1;
  }
}

SEC("fentry/commit_creds")
int BPF_PROG(commit_creds, const struct cred* new_cred) {
  const struct task_struct* task;
  const struct cred* old_cred;
  struct commit_creds_event* data;
  __u64 now = bpf_ktime_get_ns();

  if (!new_cred) return 0;

  task = (const struct task_struct*)bpf_get_current_task();
  if (!task) return 0;

  if (bpf_core_read(&old_cred, sizeof(old_cred), &task->cred)) return 0;

  __u32 tgid = BPF_CORE_READ(task, tgid);
  __u64 start_time = BPF_CORE_READ(task, start_time);
  struct dedup_key key = { .tgid = tgid, .start_time = start_time };

  /* Read UIDs */
  kuid_t old_euid = BPF_CORE_READ(old_cred, euid);
  kuid_t new_euid = BPF_CORE_READ(new_cred, euid);

  /* Read capabilities */
  __u64 old_caps = read_caps(old_cred);
  __u64 new_caps = read_caps(new_cred);

  /* Trigger only on:
   *  - EUID transition: non-root -> root
   *  - Capabilities change, but only if already root
   */
  if ((new_euid.val == 0 && old_euid.val != 0) ||
    ((new_caps != old_caps) && new_euid.val == 0)) {

    /* Rate-limit real hits BEFORE reserving the ring buffer */
    if (!should_emit(&key, now)) return 0;

    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
      bpf_printk("Error - ringbuffer is full\n");
      return 0;
    }

    data->event_type = EVENT_COMMIT_CREDS;
    data->tgid = tgid;
    data->old_uid = old_euid.val;
    data->new_uid = new_euid.val;
    data->old_caps = old_caps;
    data->new_caps = new_caps;
    // __builtin_memcpy(data->event_type, "commit creds", sizeof("commit creds"));

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}

// ebpf code to file permissions
SEC("tracepoint/syscalls/sys_enter_chmod")
int file_permissions_chmod(struct trace_event_raw_sys_enter* ctx) {
  struct file_perm_event* data;

  // Allocate ring buffer space for event data
  data = bpf_ringbuf_reserve(&events, sizeof(struct file_perm_event), 0);
  if (!data) {
    bpf_printk("Error - ringbuffer is full\n");
    return 0;
  }

  // Fill event data
  data->event_type = EVENT_FILE_PERM;
  data->pid = bpf_get_current_pid_tgid();
  data->uid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  // Retrieve the first argument (permission mode)
  data->mode = (u32)ctx->args[1]; // args[1] is the mode in chmod(path, mode)

  // Retrieve the second argument (file path)
  const char* file_path = (const char*)ctx->args[0]; // args[0] is the path in chmod(path, mode)
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
int file_permissions_fchmod(struct trace_event_raw_sys_enter* ctx) {
  struct file_perm_event* data;

  // Allocate ring buffer space for event data
  data = bpf_ringbuf_reserve(&events, sizeof(struct file_perm_event), 0);
  if (!data) {
    bpf_printk("Error - ringbuffer is full\n");
    return 0;
  }

  // Fill event data
  data->event_type = EVENT_FILE_PERM;
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
int file_permissions_fchmodat(struct trace_event_raw_sys_enter* ctx) {
  struct file_perm_event* data;

  // Allocate ring buffer space for event data
  data = bpf_ringbuf_reserve(&events, sizeof(struct file_perm_event), 0);
  if (!data) {
    bpf_printk("Error - ringbuffer is full\n");
    return 0;
  }

  // Fill event data
  data->event_type = EVENT_FILE_PERM;
  data->pid = bpf_get_current_pid_tgid();
  data->uid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  // Retrieve the mode (third argument)
  data->mode = (u32)ctx->args[2];

  // Retrieve the file path (second argument)
  const char* file_path = (const char*)ctx->args[1];
  if (bpf_probe_read_user_str(&data->filename, sizeof(data->filename), file_path) < 0) {
    bpf_printk("Error - failed to read file path\n");
    bpf_ringbuf_discard(data, 0);
    return 0;
  }

  // Submit the event to the ring buffer
  bpf_ringbuf_submit(data, 0);

  return 0;
}