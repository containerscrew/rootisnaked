#include "common.h"
#include "utils.h"
#include "logger.h"
#include "alerting.h"
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
#include <time.h>

static void get_current_time_rfc3339(char* buf, size_t bufsize) {
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

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

  // User name
  struct passwd* user_info;
  user_info = getpwuid(e->old_uid);

  // If debug mode is off, send Telegram message (production ready)
  if (!DEBUG_ENABLED) {
    // Time in RFC3339 format (UTC)
    char start_time_rfc3339[32];
    get_current_time_rfc3339(start_time_rfc3339, sizeof(start_time_rfc3339));

    char json[2048];
    snprintf(json, sizeof(json),
             "[{\"labels\":{"
             "\"alertname\":\"PrivilegeEscalation\","
             "\"severity\":\"critical\","
             "\"instance\":\"localhost\","
             "\"event\":\"%s\","
             "\"pid\":\"%u\","
             "\"user\":\"%s\","
             "\"old_uid\":\"%u\","
             "\"new_uid\":\"%u\","
             "\"cmdline\":\"%s\","
             "\"executable\":\"%s\""
             "},"
             "\"annotations\":{"
             "\"title\":\"Privilege Escalation Attempt Detected\","
             "\"description\":\"A possible privilege escalation attempt was "
             "detected on host %s\""
             "},"
             "\"startsAt\":\"%s\""
             "}]",
             e->event_type, e->tgid, user_info ? user_info->pw_name : "unknown",
             e->old_uid, e->new_uid, GetCommandLine(e->tgid),
             GetExecutablePath(e->tgid), "localhost", start_time_rfc3339);

    int rc = send_alert(app->url, json);
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