#ifndef TELEGRAM_ALERTS_H
#define TELEGRAM_ALERTS_H

/* Public API: send a Telegram message. Returns 0 on success. */
int telegram_send_message(const char* token, const char* chat_id,
                          const char* text);

#endif /* TELEGRAM_ALERTS_H */
