#include "common.h"
#include "utils.h"
#include "logger.h"
#include "notify_telegram.h"
#include "handle_events.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <stdbool.h>

int handle_commit_creds_event(void* ctx, void* data, size_t size) {
  if (!data) {
    fprintf(stderr, "Error: Data pointer is NULL\n");
    return -1;
  }

  if (size < sizeof(struct commit_creds_event)) {
    fprintf(stderr, "Error: Invalid data size (expected %zu, got %zu)\n",
            sizeof(struct commit_creds_event), size);
    return -1;
  }

  struct commit_creds_event* e = (struct commit_creds_event*)data;

  char* old_caps_str = caps_to_string(e->old_caps);
  char* new_caps_str = caps_to_string(e->new_caps);

  struct app_ctx* app = (struct app_ctx*)ctx;
  const char* token = app ? app->token : NULL;
  const char* chat_id = app ? app->chat_id : NULL;

  // User name
  struct passwd* user_info;
  user_info = getpwuid(e->old_uid);

  // If debug mode is off, send Telegram message (production ready)
  if (!DEBUG_ENABLED) {
    char msg[256];
    // char host[256];
    // GetHostname(host, sizeof(host));
    snprintf(msg, sizeof(msg),
             "event: %s\n"
             "Pid: %u\n"
             "User: %s\n"
             "Old UID: %u, New UID: %u\n"
             "Cmdline: %s\n"
             "Executable: %s\n"
             "Host: %s\n",
             e->event_type, e->tgid, user_info ? user_info->pw_name : "unknown",
             e->old_uid, e->new_uid, GetCommandLine(e->tgid),
             GetExecutablePath(e->tgid), "localhost");

    int rc = telegram_send_message(token, chat_id, msg);
    if (rc != 0) {
      fprintf(stderr, "Message failed (rc=%d)\n", rc);
    }
  }

  // TODO: log caps changes too when debug mode is active
  log_info(
      "event=%s, user=%s, tgid=%u, old_uid=%u, new_uid=%u, "
      "cmdline=%s, "
      "executable_path:%s",
      e->event_type, user_info ? user_info->pw_name : "unknown", e->tgid,
      e->old_uid, e->new_uid, GetCommandLine(e->tgid),
      GetExecutablePath(e->tgid));

  free(old_caps_str);
  free(new_caps_str);
  return 0;
}