#include "common.h"
#include "utils.h"
#include "logger.h"
#include "handle_events.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <pwd.h>
#include <stdbool.h>

// Some global flags, by the moment harcoded in the code
// TODO: read from config file or env vars
int DEBUG_ENABLED = 0;
static volatile bool exiting = false;
const char* alertmanager_url = "http://localhost:9093/api/v2/alerts";

void init_debug_flag(void) {
  const char* debug = getenv("DEBUG");
  DEBUG_ENABLED = (debug && strcmp(debug, "true") == 0) ? 1 : 0;
}

static void sig_handler(int sig) {
  log_warning("Dettaching rootisnaked eBPF program, bye! Signal=%d\n", sig);
  exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static struct bpf_program* find_program(struct bpf_object* obj,
                                        const char* name) {
  struct bpf_program* prog = bpf_object__find_program_by_name(obj, name);
  if (!prog) {
    fprintf(stderr, "Failed to find eBPF program '%s'\n", name);
  }
  return prog;
}

int main(void) {
  struct bpf_object* obj;
  int err = 0;
  struct bpf_program *commit_creds_program, *file_permission_chmod_program,
      *file_permission_fchmod_program, *file_permission_fchmodat_program;
  struct bpf_link *commit_creds_link, *file_permission_chmod_link,
      *file_permission_fchmod_link, *file_permission_fchmodat_link;
  int mapfd;
  struct ring_buffer* ring_buffer = NULL;
  const char* bpf_file = "build/rootisnaked.bpf.o";
  init_debug_flag();

  if (access(bpf_file, R_OK) != 0) {
    bpf_file = "/usr/local/share/rootisnaked/rootisnaked.bpf.o";
    if (access(bpf_file, R_OK) != 0) {
      fprintf(stderr, "Could not find BPF object file in either location.\n");
      return 1;
    }
  }

  if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
    fprintf(stderr, "curl_global_init failed\n");
    return 1;
  }

  struct app_ctx app = {
      .url = alertmanager_url,
  };

  // Ensure the program is run as root
  if (geteuid() != 0) {
    log_error(
        "You must run this program as root. Consider using sudo: $ sudo "
        "rootisnaked");
    curl_global_cleanup();
    return 1;
  }

  log_info("Starting rootisnaked");
  if (DEBUG_ENABLED) {
    libbpf_set_print(libbpf_print_fn);
  }

  obj = bpf_object__open_file(bpf_file, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", bpf_file);
    err = -1;
    goto cleanup;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error loading BPF object into the kernel\n");
    err = -2;
    goto cleanup;
  }

  commit_creds_program = find_program(obj, "commit_creds");
  if (!commit_creds_program) {
    log_error("Could not find commit_creds program");
    err = -3;
    goto cleanup;
  }

  commit_creds_link = bpf_program__attach(commit_creds_program);
  if (libbpf_get_error(commit_creds_link)) {
    err = libbpf_get_error(commit_creds_link);
    commit_creds_link = NULL;
    fprintf(stderr, "Failed to attach program (fentry): %s\n", strerror(-err));
    goto cleanup;
  }

  // sys_enter_chmod, sys_enter_fchmod, sys_enter_fchmodat
  // TODO
  file_permission_chmod_program =
      bpf_object__find_program_by_name(obj, "file_permissions_chmod");
  if (!file_permission_chmod_program) {
    fprintf(stderr, "Failed to find eBPF program 'file_permissions_chmod'\n");
    err = -ENOENT;
    goto cleanup;
  }

  // Attach the eBPF program to the tracepoint
  file_permission_chmod_link = bpf_program__attach_tracepoint(
      file_permission_chmod_program, "syscalls", "sys_enter_chmod");
  if (libbpf_get_error(file_permission_chmod_link)) {
    fprintf(stderr, "Failed to attach BPF program to tracepoint\n");
    err = -4;
    goto cleanup;
  }

  file_permission_fchmod_program =
      bpf_object__find_program_by_name(obj, "file_permissions_fchmod");
  if (!file_permission_fchmod_program) {
    fprintf(stderr, "Failed to find eBPF program 'file_permissions_fchmod'\n");
    err = -ENOENT;
    goto cleanup;
  }

  // Attach the eBPF program to the tracepoint
  file_permission_fchmod_link = bpf_program__attach_tracepoint(
      file_permission_fchmod_program, "syscalls", "sys_enter_fchmod");
  if (libbpf_get_error(file_permission_fchmod_link)) {
    fprintf(stderr, "Failed to attach BPF program to tracepoint\n");
    err = -4;
    goto cleanup;
  }

  file_permission_fchmodat_program =
      bpf_object__find_program_by_name(obj, "file_permissions_fchmodat");
  if (!file_permission_fchmodat_program) {
    fprintf(stderr,
            "Failed to find eBPF program 'file_permissions_fchmodat'\n");
    err = -ENOENT;
    goto cleanup;
  }

  // Attach the eBPF program to the tracepoint
  file_permission_fchmodat_link = bpf_program__attach_tracepoint(
      file_permission_fchmodat_program, "syscalls", "sys_enter_fchmodat");
  if (libbpf_get_error(file_permission_fchmodat_link)) {
    fprintf(stderr, "Failed to attach BPF program to tracepoint\n");
    err = -4;
    goto cleanup;
  }

  mapfd = bpf_object__find_map_fd_by_name(obj, "events");
  if (mapfd < 0) {
    fprintf(stderr, "Failed to find map 'commit_creds_events': %s\n",
            strerror(-mapfd));
    err = mapfd;
    goto cleanup;
  }

  ring_buffer = ring_buffer__new(mapfd, handle_event, &app, NULL);
  if (!ring_buffer) {
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  log_info(
      "eBPF program loaded and attached. Waiting for commit_creds_events...");

  while (!exiting) {
    ring_buffer__poll(ring_buffer, 1000);
  }

cleanup:
  if (ring_buffer) ring_buffer__free(ring_buffer);
  if (commit_creds_link) bpf_link__destroy(commit_creds_link);
  if (file_permission_chmod_link) bpf_link__destroy(file_permission_chmod_link);
  if (obj) bpf_object__close(obj);
  curl_global_cleanup();
  return err;
}