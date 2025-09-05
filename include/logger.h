#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
  LOG_LEVEL_INFO,     // 0
  LOG_LEVEL_WARNING,  // 1
  LOG_LEVEL_ERROR     // 2
} LogLevel;

extern LogLevel global_log_level;

void set_log_level(LogLevel level);
LogLevel parse_log_level(const char *level_str);
void log_info(const char *message, ...);
void log_warning(const char *message, ...);
void log_error(const char *message, ...);

#endif /* LOGGER_H */
