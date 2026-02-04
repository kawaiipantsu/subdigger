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

char **api_shodan_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    *count = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.shodan.io/dns/domain/%s?key=%s", domain, api_key);

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
        sd_warn("Shodan API query failed: %s (HTTP %ld)", curl_easy_strerror(res), http_code);
        curl_easy_cleanup(curl);
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    if (http_code != 200) {
        sd_warn("Shodan API returned HTTP %ld (rate limit or invalid key?)", http_code);
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
        return NULL;
    }

    struct json_object *subdomains_obj;
    if (!json_object_object_get_ex(json, "subdomains", &subdomains_obj)) {
        json_object_put(json);
        return NULL;
    }

    if (!json_object_is_type(subdomains_obj, json_type_array)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(subdomains_obj);
    char **results = malloc(array_len * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(subdomains_obj, i);
        const char *subdomain_prefix = json_object_get_string(item);

        char full_subdomain[MAX_DOMAIN_LEN];
        snprintf(full_subdomain, sizeof(full_subdomain), "%s.%s", subdomain_prefix, domain);

        if (validate_domain(full_subdomain)) {
            results[*count] = strdup(full_subdomain);
            (*count)++;
        }
    }

    json_object_put(json);
    sd_info("Found %zu subdomains from Shodan", *count);
    return results;
}

char **api_virustotal_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    *count = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain);

    curl_response_t response = {NULL, 0};

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        sd_warn("VirusTotal API query failed: %s (HTTP %ld)", curl_easy_strerror(res), http_code);
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    if (http_code != 200) {
        sd_warn("VirusTotal API returned HTTP %ld (rate limit or invalid key?)", http_code);
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    if (!response.data || response.size == 0) {
        if (response.data) {
            free(response.data);
        }
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);

    if (!json) {
        return NULL;
    }

    struct json_object *data_obj;
    if (!json_object_object_get_ex(json, "data", &data_obj)) {
        json_object_put(json);
        return NULL;
    }

    if (!json_object_is_type(data_obj, json_type_array)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(data_obj);
    char **results = malloc(array_len * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(data_obj, i);
        struct json_object *id_obj;

        if (json_object_object_get_ex(item, "id", &id_obj)) {
            const char *subdomain = json_object_get_string(id_obj);

            if (validate_domain(subdomain)) {
                results[*count] = strdup(subdomain);
                (*count)++;
            }
        }
    }

    json_object_put(json);
    sd_info("Found %zu subdomains from VirusTotal", *count);
    return results;
}

void api_free_results(char **results, size_t count) {
    if (!results) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(results[i]);
    }

    free(results);
}
