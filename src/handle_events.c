#include "common.h"
#include "utils.h"
#include "alerting.h"
#include "log.h"
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

// Whitelist for file_perm events
// const char* file_perm_whitelist[] = {"/etc/", NULL};

// Whitelist executable path
const char* commit_creds_whitelist[] = {"/usr/bin/unix_chkpwd", "/usr/bin/sudo",
                                        "/usr/bin/pkexec", "/usr/sbin/crond",
                                        NULL};

static int is_whitelisted(const char* exe, const char* whitelist[]) {
  for (size_t i = 0; whitelist[i] != NULL; ++i) {
    if (strcmp(exe, whitelist[i]) == 0) {
      return 1;
    }
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

static int handle_commit_creds_event(void* ctx, void* data, size_t size) {
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

  // If alerts are not enabled, send alert to alertmanager (production ready)
  if (!ALERTS_ENABLED) {
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
    if (!is_whitelisted(executable_path, commit_creds_whitelist)) {
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

static int handle_file_perm_event(void* ctx, void* data, size_t size) {
  struct file_perm_event* e = (struct file_perm_event*)data;

  // Fetch hostname
  char hostname[HOSTNAME_LEN];
  GetHostname(hostname, HOSTNAME_LEN);

  // struct app_ctx* app = (struct app_ctx*)ctx;

  // Get username for UID
  struct passwd* user_info = getpwuid(e->uid);

  // If alerts are not enabled, send alert to alertmanager (production ready)
  if (!ALERTS_ENABLED) {
    // Time in RFC3339 format (UTC)
    char start_time_rfc3339[32];
    get_current_time_rfc3339(start_time_rfc3339, sizeof(start_time_rfc3339));

    char json[2048];
    snprintf(json, sizeof(json),
             "[{\"labels\":{"
             "\"alertname\":\"FilePermissionChange\","
             "\"severity\":\"critical\","
             "\"instance\":\"%s\","
             "\"event\":\"%s\","
             "\"pid\":\"%u\","
             "\"user\":\"%s\","
             "\"uid\":\"%u\","
             "\"comm\":\"%s\","
             "\"mode\":\"%o\","
             "\"filename\":\"%s\""
             "},"
             "\"annotations\":{"
             "\"title\":\"Sensitive File Permission Change Detected\","
             "\"description\":\"A file permission change was detected on host "
             "%s: %s (mode: %o) by user %s (%u) [comm: %s]\""
             "},"
             "\"startsAt\":\"%s\""
             "}]",
             hostname,
             event_type_to_string(e->event_type), // event
             e->pid, user_info ? user_info->pw_name : "unknown", e->uid,
             e->comm, e->mode, e->filename, hostname, e->filename, e->mode,
             user_info ? user_info->pw_name : "unknown", e->uid, e->comm,
             start_time_rfc3339);

    // TODO: Implement file_perm alert
    log_info(
        "event=%s, pid=%u, user=%s, uid=%u, comm=%s, mode=%o, filename=%s, "
        "hostname=%s",
        event_type_to_string(e->event_type), e->pid,
        user_info ? user_info->pw_name : "unknown", e->uid, e->comm, e->mode,
        e->filename, hostname);
  }
  return 0;
}

int handle_event(void* ctx, void* data, size_t size) {
  if (!data) {
    log_warn("Error: Data pointer is NULL\n");
    return -1;
  }

  switch (size) {
  case sizeof(struct commit_creds_event):
    return handle_commit_creds_event(ctx, data, size);

  case sizeof(struct file_perm_event):
    return handle_file_perm_event(ctx, data, size);

  default:
    log_info("Received event with unexpected size: %zu bytes\n", size);
    return -1;
  }
}
