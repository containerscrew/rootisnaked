#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static size_t sink(void* ptr, size_t size, size_t nmemb, void* userdata) {
  (void)userdata;
  return size * nmemb;
}

// Returns 0 on success, non-zero on error.
int telegram_send_message(const char* token, const char* chat_id,
                          const char* text) {
  if (!token || !*token || !chat_id || !*chat_id || !text) {
    fprintf(stderr, "telegram_send_message: invalid args\n");
    return 1;
  }

  CURL* curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "telegram_send_message: curl_easy_init failed\n");
    return 1;
  }

  // Build URL using token WITHOUT url-encoding the token.
  char url[512];
  snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage",
           token);

  // Encode ONLY the text value for application/x-www-form-urlencoded
  char* esc_text = curl_easy_escape(curl, text, 0);
  if (!esc_text) {
    fprintf(stderr, "telegram_send_message: curl_easy_escape failed (text)\n");
    curl_easy_cleanup(curl);
    return 1;
  }

  // If your chat_id can include special chars (rare), escape it too:
  // char *esc_chat = curl_easy_escape(curl, chat_id, 0);
  // ...and use esc_chat below instead of chat_id, then curl_free(esc_chat).

  // Keep it simple: no Markdown mode to avoid escaping headaches.
  char postfields[2048];
  snprintf(postfields, sizeof(postfields), "chat_id=%s&text=%s", chat_id,
           esc_text);

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "rootisnaked/1.0");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink); // discard body

  // TLS verification (recommended ON)
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

  CURLcode res = curl_easy_perform(curl);

  long http_code = 0;
  if (res == CURLE_OK)
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_free(esc_text);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    fprintf(stderr, "telegram_send_message: curl error: %s\n",
            curl_easy_strerror(res));
    return 2;
  }

  if (http_code != 200) {
    fprintf(stderr, "telegram_send_message: http_code=%ld, %s\n", http_code,
            curl_easy_strerror(res));
    return 3;
  }
  return 0;
}
