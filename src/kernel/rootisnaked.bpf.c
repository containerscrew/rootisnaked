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
  __uint(max_entries, 1 << 24); // 16MB ring buffer size
} events SEC(".maps");

/* Portable read of kernel_cap_t into u64 without assuming .cap[] exists */
static __always_inline u64 read_caps(const struct cred* c) {
  u64 out = 0;

  /* Fast path: kernels where cap_effective has a .val member (u64) */
  if (bpf_core_field_exists(struct cred, cap_effective.val)) {
    BPF_CORE_READ_INTO(&out, c, cap_effective.val);
    return out;
  }

  /* Fallback: copy the first 8 bytes of cap_effective as raw bytes */
  struct {
    u32 lo;
    u32 hi;
  } tmp = {};
  int sz = bpf_core_field_size(struct cred, cap_effective);
  if (sz <= 0) return 0;
  int copy = sz < 8 ? sz : 8;
  bpf_core_read(&tmp, copy, &c->cap_effective);

  out = ((u64)tmp.hi << 32) | tmp.lo;
  return out;
}

SEC("fentry/commit_creds")
int BPF_PROG(commit_creds, const struct cred* new_cred) {
  const struct task_struct* task;
  const struct cred* old_cred;
  struct event* data;

  if (!new_cred) return 0;

  task = (const struct task_struct*)bpf_get_current_task();
  if (!task) return 0;

  if (bpf_core_read(&old_cred, sizeof(old_cred), &task->cred)) return 0;

  /* Read UIDs */
  kuid_t old_euid = BPF_CORE_READ(old_cred, euid);
  kuid_t new_euid = BPF_CORE_READ(new_cred, euid);

  /* Read capabilities */
  u64 old_caps = read_caps(old_cred);
  u64 new_caps = read_caps(new_cred);

  /* Trigger only on:
   *  - EUID transition: non-root -> root
   *  - Capabilities change, but only if already root
   */
  if ((new_euid.val == 0 && old_euid.val != 0) ||
      ((new_caps != old_caps) && new_euid.val == 0)) {
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
      bpf_printk("Error - ringbuffer is full\n");
      return 0;
    }

    data->tgid = BPF_CORE_READ(task, tgid);
    data->old_uid = old_euid.val; // store EUIDs for relevance
    data->new_uid = new_euid.val;
    data->old_caps = old_caps;
    data->new_caps = new_caps;

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}
