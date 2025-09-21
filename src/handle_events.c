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

#define HOSTNAME_LEN 128

// Whitelist executable path
const char* whitelist[] = {
    "/usr/bin/unix_chkpwd",
    "/usr/bin/sudo",
    "/usr/bin/pkexec",
    "/usr/sbin/crond",
};

static int is_whitelisted(const char* exe) {
  for (size_t i = 0; i < sizeof(whitelist) / sizeof(whitelist[0]); ++i) {
    if (strcmp(exe, whitelist[i]) == 0) return 1;
  }
  return 0;
}

static void get_current_time_rfc3339(char* buf, size_t bufsize) {
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static inline const char* event_type_to_string(enum event_type type) {
  switch (type) {
  case EVENT_COMMIT_CREDS:
    return "commit_creds";
  case EVENT_FILE_PERM:
    return "file_perm";
  default:
    return "unknown";
  }
}

int handle_commit_creds_event(void* ctx, void* data, size_t size) {
  if (!data) {
    fprintf(stderr, "Error: Data pointer is NULL\n");
    return -1;
  }

  // Rapid check for size

  if (size == sizeof(struct file_perm_event)) {
    log_warning(
        "Seems like a file_perm_event was received! Not implemented yet! :)\n");
    return 0;
  }

  if (size < sizeof(struct commit_creds_event)) {
    log_warning("Error: Invalid data size (expected %zu, got %zu)\n",
                sizeof(struct commit_creds_event), size);
    return -1;
  }

  struct commit_creds_event* e = (struct commit_creds_event*)data;

  char* old_caps_str = caps_to_string(e->old_caps);
  char* new_caps_str = caps_to_string(e->new_caps);
  char* executable_path = GetExecutablePath(e->tgid);
  if (!executable_path) executable_path = strdup("unknown");
  char* cmdline = GetCommandLine(e->tgid);
  if (!cmdline) cmdline = strdup("unknown");

  // Hostname
  char hostname[HOSTNAME_LEN];
  GetHostname(hostname, HOSTNAME_LEN);

  struct app_ctx* app = (struct app_ctx*)ctx;

  // User name
  struct passwd* user_info;
  user_info = getpwuid(e->old_uid);

  // If debug is not enabled, send alert to alertmanager (production ready)
  if (!DEBUG_ENABLED) {
    // Time in RFC3339 format (UTC)
    char start_time_rfc3339[32];
    get_current_time_rfc3339(start_time_rfc3339, sizeof(start_time_rfc3339));

    char json[2048];
    snprintf(json, sizeof(json),
             "[{\"labels\":{"
             "\"alertname\":\"PrivilegeEscalation\","
             "\"severity\":\"critical\","
             "\"instance\":\"%s\","
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
             hostname, event_type_to_string(e->event_type), e->tgid,
             user_info ? user_info->pw_name : "unknown", e->old_uid, e->new_uid,
             cmdline, executable_path, hostname, start_time_rfc3339);

    // If executable is in whitelist, ignore the alert
    if (!is_whitelisted(executable_path)) {
      int rc = send_alert(app->url, json);
      if (rc != 0) {
        fprintf(stderr, "Message failed (rc=%d)\n", rc);
      }
    }
  }

  // TODO: log caps changes too when debug mode is active
  log_info(
      "event=%s, user=%s, tgid=%u, old_uid=%u, new_uid=%u, "
      "cmdline=%s, "
      "executable_path=%s, "
      "hostname=%s  ",
      event_type_to_string(e->event_type),
      user_info ? user_info->pw_name : "unknown", e->tgid, e->old_uid,
      e->new_uid, cmdline, executable_path, hostname);

  free(old_caps_str);
  free(new_caps_str);
  return 0;
}