#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "../include/subdigger.h"

typedef struct {
    char *data;
    size_t size;
} curl_response_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    curl_response_t *response = (curl_response_t *)userp;

    char *ptr = realloc(response->data, response->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;

    return realsize;
}

char **cert_query_crtsh(const char *domain, size_t *count) {
    if (!domain || !count) {
        return NULL;
    }

    *count = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        sd_error("Failed to initialize curl");
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%.%s&output=json", domain);

    curl_response_t response = {NULL, 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (res != CURLE_OK) {
        sd_warn("Certificate transparency query failed: %s (HTTP %ld)", curl_easy_strerror(res), http_code);
        curl_easy_cleanup(curl);
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    if (http_code != 200) {
        sd_warn("Certificate transparency query returned HTTP %ld", http_code);
        curl_easy_cleanup(curl);
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    curl_easy_cleanup(curl);

    if (!response.data || response.size == 0) {
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);

    if (!json) {
        sd_warn("Failed to parse CT logs JSON");
        return NULL;
    }

    if (!json_object_is_type(json, json_type_array)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(json);
    char **results = malloc(array_len * 10 * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    size_t capacity = array_len * 10;

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(json, i);
        struct json_object *common_name_obj, *name_value_obj;

        if (json_object_object_get_ex(item, "common_name", &common_name_obj)) {
            const char *common_name = json_object_get_string(common_name_obj);
            if (common_name && validate_domain(common_name)) {
                if (*count >= capacity) {
                    capacity *= 2;
                    char **new_results = realloc(results, capacity * sizeof(char *));
                    if (!new_results) {
                        break;
                    }
                    results = new_results;
                }
                results[*count] = strdup(common_name);
                (*count)++;
            }
        }

        if (json_object_object_get_ex(item, "name_value", &name_value_obj)) {
            const char *name_value = json_object_get_string(name_value_obj);

            if (name_value) {
                char *names_copy = strdup(name_value);
                char *saveptr;
                char *token = strtok_r(names_copy, "\n", &saveptr);

                while (token) {
                    token = trim(token);

                    if (strlen(token) > 0 && validate_domain(token)) {
                        if (*count >= capacity) {
                            capacity *= 2;
                            char **new_results = realloc(results, capacity * sizeof(char *));
                            if (!new_results) {
                                free(names_copy);
                                break;
                            }
                            results = new_results;
                        }
                        results[*count] = strdup(token);
                        (*count)++;
                    }

                    token = strtok_r(NULL, "\n", &saveptr);
                }

                free(names_copy);
            }
        }
    }

    json_object_put(json);

    sd_info("Found %zu subdomains from certificate transparency", *count);
    return results;
}

void cert_free_results(char **results, size_t count) {
    if (!results) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(results[i]);
    }

    free(results);
}
