#include "utils.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct cap_entry {
  uint64_t bit;
  const char *name;
};

static const struct cap_entry cap_table[] = {
    {1ULL << 0, "CAP_CHOWN"},
    {1ULL << 1, "CAP_DAC_OVERRIDE"},
    {1ULL << 2, "CAP_DAC_READ_SEARCH"},
    {1ULL << 3, "CAP_FOWNER"},
    {1ULL << 4, "CAP_FSETID"},
    {1ULL << 5, "CAP_KILL"},
    {1ULL << 6, "CAP_SETGID"},
    {1ULL << 7, "CAP_SETUID"},
    {1ULL << 8, "CAP_SETPCAP"},
    {1ULL << 9, "CAP_LINUX_IMMUTABLE"},
    {1ULL << 10, "CAP_NET_BIND_SERVICE"},
    {1ULL << 11, "CAP_NET_BROADCAST"},
    {1ULL << 12, "CAP_NET_ADMIN"},
    {1ULL << 13, "CAP_NET_RAW"},
    {1ULL << 14, "CAP_SYS_CHROOT"},
    {1ULL << 15, "CAP_SYS_PTRACE"},
    {1ULL << 16, "CAP_SYS_MODULE"},
    {1ULL << 17, "CAP_SYS_RAWIO"},
    {1ULL << 18, "CAP_SYS_PACCT"},
    {1ULL << 19, "CAP_SYS_ADMIN"},
    {1ULL << 20, "CAP_SYS_BOOT"},
    {1ULL << 21, "CAP_SYS_NICE"},
    {1ULL << 22, "CAP_SYS_RESOURCE"},
    {1ULL << 23, "CAP_SYS_TIME"},
    {1ULL << 24, "CAP_SYS_TTY_CONFIG"},
    {1ULL << 25, "CAP_MKNOD"},
    {1ULL << 26, "CAP_LEASE"},
    {1ULL << 27, "CAP_AUDIT_WRITE"},
    {1ULL << 28, "CAP_AUDIT_CONTROL"},
    {1ULL << 29, "CAP_SETFCAP"},
    {1ULL << 30, "CAP_MAC_OVERRIDE"},
    {1ULL << 31, "CAP_MAC_ADMIN"},
    {1ULL << 32, "CAP_SYSLOG"},
    {1ULL << 33, "CAP_WAKE_ALARM"},
    {1ULL << 34, "CAP_BLOCK_SUSPEND"},
    {1ULL << 35, "CAP_AUDIT_READ"},
};
#define CAP_TABLE_SIZE (sizeof(cap_table) / sizeof(cap_table[0]))

const char **decode_capabilities(uint64_t mask) {
  const char **arr = malloc((CAP_TABLE_SIZE + 1) * sizeof(char *));
  if (!arr) return NULL;
  int count = 0;
  for (size_t i = 0; i < CAP_TABLE_SIZE; i++)
    if (mask & cap_table[i].bit) arr[count++] = cap_table[i].name;
  arr[count] = NULL;
  return arr;
}

char *caps_to_string(uint64_t mask) {
  const char **caps = decode_capabilities(mask);
  if (!caps) return strdup("<error>");
  if (!caps[0]) {
    free(caps);
    return strdup("<none>");
  }

  // Paso 1: calcular tamaño
  size_t needed = 1;                                            // '\0'
  for (int i = 0; caps[i]; i++) needed += strlen(caps[i]) + 1;  // +1 por coma
  // Paso 2: construir
  char *out = malloc(needed);
  if (!out) {
    free(caps);
    return strdup("<oom>");
  }
  out[0] = '\0';
  for (int i = 0; caps[i]; i++) {
    if (i) strcat(out, ",");
    strcat(out, caps[i]);
  }
  free(caps);
  return out;
}
