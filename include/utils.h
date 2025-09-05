#pragma once
#include <stdint.h>

const char **decode_capabilities(uint64_t mask);

/* Devuelve una cadena con las caps separadas por comas. Debes free(). */
char *caps_to_string(uint64_t mask);
