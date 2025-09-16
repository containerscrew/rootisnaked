#pragma once
#include <stdint.h>

const char** decode_capabilities(uint64_t mask);
char* caps_to_string(uint64_t mask);
char* GetExecutablePath(__pid_t pid);
char* GetCommandLine(__pid_t pid);
