
#include <stddef.h>
#ifndef HANDLE_EVENTS_H
#define HANDLE_EVENTS_H

extern int DEBUG_ENABLED;

int handle_commit_creds_event(void* ctx, void* data, size_t size);

#endif /* HANDLE_EVENTS_H */