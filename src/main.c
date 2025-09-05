#include "event.h"
#include "utils.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
  log_warning("Dettaching rootisnaked eBPF program, bye! Signal=%d\n", sig);
  exiting = true;
}

static int _libbpf_print_fn(enum libbpf_print_level level, const char* format,
                            va_list args) {
  return vfprintf(stderr, format, args);
}

static int handle_event(void* ctx, void* data, size_t size) {
  if (!data) {
    fprintf(stderr, "Error: Data pointer is NULL\n");
    return -1;
  }

  if (size < sizeof(struct event)) {
    fprintf(stderr, "Error: Invalid data size (expected %zu, got %zu)\n",
            sizeof(struct event), size);
    return -1;
  }

  struct event* e = (struct event*)data;

  char* old_caps_str = caps_to_string(e->old_caps);
  char* new_caps_str = caps_to_string(e->new_caps);

  log_info("event: tgid=%u, old_uid=%u, new_uid=%u, old_caps=%s, new_caps=%s\n",
           e->tgid, e->old_uid, e->new_uid, old_caps_str, new_caps_str);

  free(old_caps_str);
  free(new_caps_str);
  return 0;
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
  int err;
  struct bpf_program* prog;
  struct bpf_link* link;
  int mapfd;
  struct ring_buffer* ring_buffer;
  const char* bpf_file = "build/rootisnaked.bpf.o";

  // Ensure the program is run as root
  if (geteuid() != 0) {
    log_error(
        "You must run this program as root. Consider using sudo: $ sudo "
        "rootisnaked");
    return 1;
  }

  log_info("Starting rootisnaked");
  // libbpf_set_print(libbpf_print_fn);

  obj = bpf_object__open_file(bpf_file, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", bpf_file);
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error loading BPF object into the kernel\n");
    bpf_object__close(obj);
    return 1;
  }

  prog = find_program(obj, "commit_creds");
  if (!prog) {
    bpf_object__close(obj);
    return 1;
  }

  mapfd = bpf_object__find_map_fd_by_name(obj, "events");
  if (mapfd < 0) {
    fprintf(stderr, "Failed to find map 'events': %s\n", strerror(-mapfd));
    err = mapfd;
    goto cleanup;
  }

  link = bpf_program__attach(prog);
  if (libbpf_get_error(link)) {
    err = libbpf_get_error(link);
    link = NULL;
    fprintf(stderr, "Failed to attach program (fentry): %s\n", strerror(-err));
    goto cleanup;
  }

  ring_buffer = ring_buffer__new(mapfd, handle_event, NULL, NULL);
  if (!ring_buffer) {
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  while (!exiting) {
    ring_buffer__poll(ring_buffer, 1000);
  }

cleanup:
  if (link) {
    bpf_link__destroy(link);
  }
  bpf_object__close(obj);
  return err;
}