// include/event.h
#pragma once

#ifdef __BPF__ // compiling with -target bpf
// No std headers here; vmlinux.h must be included BEFORE this header in .bpf.c
// and it defines __u32/__u64 already.
typedef __u32 u32c;
typedef __u64 u64c;
#else
// user space
#include <stdint.h>
typedef uint32_t u32c;
typedef uint64_t u64c;
#endif

struct event {
  u32c tgid;
  u32c old_uid;
  u32c new_uid;
  u64c old_caps;
  u64c new_caps;
  char event_type[16];
};

// struct dedup_entry {
//   __u64 last_seen_ns; // monotonic clock from bpf_ktime_get_ns()
// };
