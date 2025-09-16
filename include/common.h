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

struct commit_creds_event {
  u32c tgid;
  u32c old_uid;
  u32c new_uid;
  u64c old_caps;
  u64c new_caps;
  char event_type[16];
};

struct file_perm_event {
  u32c pid;           // Process ID
  u32c uid;           // User ID
  char comm[16];      // Command name
  u32c mode;          // New file permissions (mode)
  char filename[256]; // File path
};

/* include/app_ctx.h */
#ifndef APP_CTX_H
#define APP_CTX_H

struct app_ctx {
  const char* token;
  const char* chat_id;
  /* …otros campos que usas en otras partes del programa… */
};

#endif /* APP_CTX_H */