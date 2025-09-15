#include "vmlinux.h"
#include "event.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

#define WINDOW_NS (5ULL * 60ULL * 1000000000ULL) // 5 minutes

struct dedup_entry {
  __u64 last_seen_ns;
};

struct dedup_key {
  __u32 tgid;
  __u64 start_time; // task->start_time (monotonic)
};

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
  } else {
    struct dedup_entry newval = {.last_seen_ns = now_ns};
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
  struct dedup_key key = {.tgid = tgid, .start_time = start_time};

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

    data->tgid = tgid;
    data->old_uid = old_euid.val;
    data->new_uid = new_euid.val;
    data->old_caps = old_caps;
    data->new_caps = new_caps;
    __builtin_memcpy(data->event_type, "commit creds", sizeof("commit creds"));

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}

// ebpf code to file permissions