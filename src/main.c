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
#include <curl/curl.h>
#include "notify-telegram.h"
#include "logger.h"

static volatile bool exiting = false;

// Run this:
// export TELEGRAM_TOKEN="xxxxx";
// export DEBUG=true; export CHAT_ID="xxxxx" ; sudo -E ./bin/rootisnaked

struct app_ctx {
  const char* token;
  const char* chat_id;
};

static void sig_handler(int sig) {
  log_warning("Dettaching rootisnaked eBPF program, bye! Signal=%d\n", sig);
  exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
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

  struct app_ctx* app = (struct app_ctx*)ctx;
  const char* token = app ? app->token : NULL;
  const char* chat_id = app ? app->chat_id : NULL;

  if (!token || !*token || !chat_id || !*chat_id) {
    fprintf(stderr,
            "Warning: TELEGRAM_TOKEN or CHAT_ID missing; skipping send.\n");
  } else {
    int rc = telegram_send_message(token, chat_id,
                                   "Alert: UID 0 privileges granted!");
    if (rc != 0) {
      fprintf(stderr, "Message failed (rc=%d)\n", rc);
    }
  }

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
  int err = 0;
  struct bpf_program* prog;
  struct bpf_link* link = NULL;
  int mapfd;
  struct ring_buffer* ring_buffer = NULL;
  const char* bpf_file = "build/rootisnaked.bpf.o";
  if (access(bpf_file, R_OK) != 0) {
    bpf_file = "/usr/local/share/rootisnaked/rootisnaked.bpf.o";
    if (access(bpf_file, R_OK) != 0) {
      fprintf(stderr, "Could not find BPF object file in either location.\n");
      return 1;
    }
  }
  const char* telegram_token = getenv("TELEGRAM_TOKEN");
  const char* chat_id = getenv("CHAT_ID");
  const char* debug = getenv("DEBUG") ? getenv("DEBUG") : "false";

  // Init libcurl lo antes posible
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
    fprintf(stderr, "curl_global_init failed\n");
    return 1;
  }

  struct app_ctx app = {
      .token = telegram_token,
      .chat_id = chat_id,
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
  if (debug && strcmp(debug, "true") == 0) {
    libbpf_set_print(libbpf_print_fn);
  }

  obj = bpf_object__open_file(bpf_file, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", bpf_file);
    curl_global_cleanup();
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error loading BPF object into the kernel\n");
    bpf_object__close(obj);
    curl_global_cleanup();
    return 1;
  }

  prog = find_program(obj, "commit_creds");
  if (!prog) {
    bpf_object__close(obj);
    curl_global_cleanup();
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

  ring_buffer = ring_buffer__new(mapfd, handle_event, &app, NULL);
  if (!ring_buffer) {
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  log_info("eBPF program loaded and attached. Waiting for events...");

  while (!exiting) {
    ring_buffer__poll(ring_buffer, 1000);
  }

cleanup:
  if (ring_buffer) {
    ring_buffer__free(ring_buffer);
  }
  if (link) {
    bpf_link__destroy(link);
  }
  bpf_object__close(obj);
  curl_global_cleanup();
  return err;
}
