#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static size_t sink(void* ptr, size_t size, size_t nmemb, void* userdata) {
  (void)userdata;
  return size * nmemb;
}

// Returns 0 on success, non-zero on error.
int send_alert(const char* url, const char* json_payload) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "alertmanager_send_alert: curl_easy_init failed\n");
    return 1;
  }

  struct curl_slist* headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "rootisnaked/1.0");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  // Desactiva SSL si usas HTTP puro:
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  CURLcode res = curl_easy_perform(curl);

  long http_code = 0;
  if (res == CURLE_OK)
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  if (res != CURLE_OK) {
    fprintf(stderr, "alertmanager_send_alert: curl error: %s\n",
            curl_easy_strerror(res));
    return 2;
  }

  if (http_code != 200) {
    fprintf(stderr, "alertmanager_send_alert: http_code=%ld, %s\n", http_code,
            curl_easy_strerror(res));
    return 3;
  }
  return 0;
}