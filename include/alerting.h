#ifndef ALERTING_H
#define ALERTING_H

#include <stdbool.h>

extern bool DEBUG_ENABLED;
extern bool ALERTS_ENABLED;

/* Send a POST alert to alertmanager. Returns 0 on success. */
int send_alert(const char* url, const char* text);

#endif /* ALERTING_H */
