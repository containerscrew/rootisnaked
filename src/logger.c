#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "colors.h"

LogLevel global_log_level = LOG_LEVEL_INFO;

void set_log_level(LogLevel level) { global_log_level = level; }

LogLevel parse_log_level(const char* level_str) {
  if (strcmp(level_str, "info") == 0) {
    return LOG_LEVEL_INFO;
  } else if (strcmp(level_str, "warning") == 0) {
    return LOG_LEVEL_WARNING;
  } else if (strcmp(level_str, "error") == 0) {
    return LOG_LEVEL_ERROR;
  } else {
    fprintf(stderr, "Error: Unknown log level '%s'\n", level_str);
    exit(1);
  }
}

static void log_message(char* level, const char* message) {
  time_t now;
  time(&now);
  struct tm* timeinfo = localtime(&now);

  // Custom datetime format
  char time_str[64]; // Buffer to hold the formatted time
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

  switch (*level) {
  case 'i':
    printf(GREEN "%s [INFO]: %s\n" RESET, time_str, message);
    break;
  case 'w':
    printf(YELLOW "%s [WARNING]: %s\n" RESET, time_str, message);
    break;
  case 'e':
    printf(RED "%s [ERROR]: %s\n" RESET, time_str, message);
    break;
  default:
    printf("%s [UNKNOWN]: Unknown log level. See usage below%s\n\n", time_str,
           level);
    exit(1);
  }
}

// Helper function to handle formatted logging
// Helper function to handle formatted logging (sin truncados)
static void log_formatted_message(char* level, const char* message,
                                  va_list args) {
  va_list ap1, ap2;
  va_copy(ap1, args);
  va_copy(ap2, args);

  int needed = vsnprintf(NULL, 0, message, ap1);
  va_end(ap1);
  if (needed < 0) {
    // si falla el cálculo, imprime algo básico
    log_message(level, "log formatting error");
    return;
  }

  size_t sz = (size_t)needed + 1;
  char* formatted_message = (char*)malloc(sz);
  if (!formatted_message) {
    log_message(level, "log oom");
    va_end(ap2);
    return;
  }

  vsnprintf(formatted_message, sz, message, ap2);
  va_end(ap2);

  log_message(level, formatted_message);
  free(formatted_message);
}

void log_info(const char* message, ...) {
  if (global_log_level <= LOG_LEVEL_INFO) {
    va_list args;
    va_start(args, message);
    log_formatted_message("i", message, args);
    va_end(args);
  }
}

void log_warning(const char* message, ...) {
  if (global_log_level <= LOG_LEVEL_WARNING) {
    va_list args;
    va_start(args, message);
    log_formatted_message("w", message, args);
    va_end(args);
  }
}

void log_error(const char* message, ...) {
  if (global_log_level <= LOG_LEVEL_ERROR) {
    va_list args;
    va_start(args, message);
    log_formatted_message("e", message, args);
    va_end(args);
  }
}