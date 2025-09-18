#include <stdint.h>
#include <stddef.h>
#ifndef UTILS_H
#define UTILS_H

const char** decode_capabilities(uint64_t mask);
char* caps_to_string(uint64_t mask);
char* GetExecutablePath(__pid_t pid);
char* GetCommandLine(__pid_t pid);
void GetHostname(char* buf, size_t sz);
int load_env_file(const char* filename);

#endif /* UTILS_H */