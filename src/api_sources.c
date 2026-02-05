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

// Helper function for generic API queries
static char **generic_api_query(const char *url, struct curl_slist *headers,
                                const char *service_name, const char *domain,
                                const char *json_path, bool is_array_of_strings,
                                size_t *count) {
    (void)domain; // Reserved for future use in error messages

    if (!url || !count) {
        return NULL;
    }

    *count = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    curl_response_t response = {NULL, 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SubDigger/1.4.0");

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        sd_warn("%s API query failed: %s (HTTP %ld)", service_name, curl_easy_strerror(res), http_code);
        if (response.data) free(response.data);
        return NULL;
    }

    if (http_code != 200) {
        sd_warn("%s API returned HTTP %ld (rate limit or invalid key?)", service_name, http_code);
        if (response.data) free(response.data);
        return NULL;
    }

    if (!response.data || response.size == 0) {
        if (response.data) free(response.data);
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);

    if (!json) {
        return NULL;
    }

    // Navigate JSON path
    struct json_object *target_obj = json;
    if (json_path && strlen(json_path) > 0) {
        if (!json_object_object_get_ex(json, json_path, &target_obj)) {
            json_object_put(json);
            return NULL;
        }
    }

    if (!json_object_is_type(target_obj, json_type_array)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(target_obj);
    if (array_len == 0) {
        json_object_put(json);
        return NULL;
    }

    char **results = malloc(array_len * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(target_obj, i);
        const char *subdomain = NULL;

        if (is_array_of_strings) {
            subdomain = json_object_get_string(item);
        } else {
            struct json_object *id_obj;
            if (json_object_object_get_ex(item, "id", &id_obj)) {
                subdomain = json_object_get_string(id_obj);
            } else if (json_object_object_get_ex(item, "domain", &id_obj)) {
                subdomain = json_object_get_string(id_obj);
            } else if (json_object_object_get_ex(item, "subdomain", &id_obj)) {
                subdomain = json_object_get_string(id_obj);
            }
        }

        if (subdomain && validate_domain(subdomain)) {
            results[*count] = strdup(subdomain);
            (*count)++;
        }
    }

    json_object_put(json);
    if (*count > 0) {
        sd_info("Found %zu subdomains from %s", *count, service_name);
    }
    return results;
}

// BeVigil API
char **api_bevigil_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://osint.bevigil.com/api/%s/subdomains/", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "X-Access-Token: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "BeVigil", domain, "subdomains", true, count);
    curl_slist_free_all(headers);
    return results;
}

// BinaryEdge API
char **api_binaryedge_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.binaryedge.io/v2/query/domains/subdomain/%s", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "X-Key: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "BinaryEdge", domain, "events", true, count);
    curl_slist_free_all(headers);
    return results;
}

// BufferOver API (free, no key needed)
char **api_bufferover_query(const char *domain, size_t *count) {
    if (!domain || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://dns.bufferover.run/dns?q=.%s", domain);

    return generic_api_query(url, NULL, "BufferOver", domain, "FDNS_A", true, count);
}

// C99 API
char **api_c99_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json", api_key, domain);

    return generic_api_query(url, NULL, "C99", domain, "subdomains", false, count);
}

// Censys API
char **api_censys_query(const char *domain, const char *api_id, const char *api_secret, size_t *count) {
    if (!domain || !api_id || !api_secret || !count) {
        return NULL;
    }

    *count = 0;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char url[512];
    snprintf(url, sizeof(url), "https://search.censys.io/api/v2/certificates/search?q=names:%s", domain);

    char auth[512];
    snprintf(auth, sizeof(auth), "%s:%s", api_id, api_secret);

    curl_response_t response = {NULL, 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SubDigger/1.4.0");

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response.data) {
        if (response.data) free(response.data);
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);
    if (!json) return NULL;

    struct json_object *results_obj;
    if (!json_object_object_get_ex(json, "results", &results_obj)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(results_obj);
    char **results = malloc(array_len * 10 * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(results_obj, i);
        struct json_object *names_obj;
        if (json_object_object_get_ex(item, "names", &names_obj)) {
            size_t names_len = json_object_array_length(names_obj);
            for (size_t j = 0; j < names_len; j++) {
                struct json_object *name_obj = json_object_array_get_idx(names_obj, j);
                const char *name = json_object_get_string(name_obj);
                if (name && validate_domain(name) && strstr(name, domain)) {
                    results[*count] = strdup(name);
                    (*count)++;
                }
            }
        }
    }

    json_object_put(json);
    if (*count > 0) {
        sd_info("Found %zu subdomains from Censys", *count);
    }
    return results;
}

// CertSpotter API
char **api_certspotter_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !count) {
        return NULL;
    }

    char url[512];
    if (api_key && strlen(api_key) > 0) {
        snprintf(url, sizeof(url), "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain);
    } else {
        // Free tier endpoint
        snprintf(url, sizeof(url), "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain);
    }

    struct curl_slist *headers = NULL;
    if (api_key && strlen(api_key) > 0) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
        headers = curl_slist_append(headers, auth_header);
    }

    char **results = generic_api_query(url, headers, "CertSpotter", domain, "", false, count);
    if (headers) curl_slist_free_all(headers);
    return results;
}

// Chaos (ProjectDiscovery) API
char **api_chaos_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://dns.projectdiscovery.io/dns/%s/subdomains", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "Chaos", domain, "subdomains", true, count);
    curl_slist_free_all(headers);
    return results;
}

// FullHunt API
char **api_fullhunt_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://fullhunt.io/api/v1/domain/%s/subdomains", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "X-API-KEY: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "FullHunt", domain, "hosts", true, count);
    curl_slist_free_all(headers);
    return results;
}

// GitHub Code Search API
char **api_github_query(const char *domain, const char *api_token, size_t *count) {
    if (!domain || !api_token || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.github.com/search/code?q=%%22%s%%22", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: token %s", api_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");

    char **results = generic_api_query(url, headers, "GitHub", domain, "items", false, count);
    curl_slist_free_all(headers);
    return results;
}

// Hunter API
char **api_hunter_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.hunter.how/search?api-key=%s&query=domain%%3D%%22%s%%22&page=1&page_size=100",
             api_key, domain);

    return generic_api_query(url, NULL, "Hunter", domain, "data.list", false, count);
}

// IntelX API
char **api_intelx_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://2.intelx.io/phonebook/search?k=%s", api_key);

    *count = 0;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char post_data[256];
    snprintf(post_data, sizeof(post_data), "{\"term\":\"%s\",\"maxresults\":10000,\"media\":0,\"target\":1}", domain);

    curl_response_t response = {NULL, 0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response.data) {
        if (response.data) free(response.data);
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);
    if (!json) return NULL;

    struct json_object *selectors_obj;
    if (!json_object_object_get_ex(json, "selectors", &selectors_obj)) {
        json_object_put(json);
        return NULL;
    }

    size_t array_len = json_object_array_length(selectors_obj);
    char **results = malloc(array_len * sizeof(char *));
    if (!results) {
        json_object_put(json);
        return NULL;
    }

    for (size_t i = 0; i < array_len; i++) {
        struct json_object *item = json_object_array_get_idx(selectors_obj, i);
        struct json_object *selectorvalue_obj;
        if (json_object_object_get_ex(item, "selectorvalue", &selectorvalue_obj)) {
            const char *subdomain = json_object_get_string(selectorvalue_obj);
            if (subdomain && validate_domain(subdomain)) {
                results[*count] = strdup(subdomain);
                (*count)++;
            }
        }
    }

    json_object_put(json);
    if (*count > 0) {
        sd_info("Found %zu subdomains from IntelX", *count);
    }
    return results;
}

// LeakIX API
char **api_leakix_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://leakix.net/api/subdomains/%s", domain);

    struct curl_slist *headers = NULL;
    if (api_key && strlen(api_key) > 0) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "api-key: %s", api_key);
        headers = curl_slist_append(headers, auth_header);
    }

    char **results = generic_api_query(url, headers, "LeakIX", domain, "", true, count);
    if (headers) curl_slist_free_all(headers);
    return results;
}

// Netlas API
char **api_netlas_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://app.netlas.io/api/domains/?q=domain:*.%s&source_type=include&start=0&fields=domain", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "X-API-Key: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "Netlas", domain, "items", false, count);
    curl_slist_free_all(headers);
    return results;
}

// PassiveTotal API
char **api_passivetotal_query(const char *domain, const char *api_user, const char *api_key, size_t *count) {
    if (!domain || !api_user || !api_key || !count) {
        return NULL;
    }

    *count = 0;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char url[512];
    snprintf(url, sizeof(url), "https://api.passivetotal.org/v2/enrichment/subdomains?query=%s", domain);

    char auth[512];
    snprintf(auth, sizeof(auth), "%s:%s", api_user, api_key);

    curl_response_t response = {NULL, 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response.data) {
        if (response.data) free(response.data);
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);
    if (!json) return NULL;

    struct json_object *subdomains_obj;
    if (!json_object_object_get_ex(json, "subdomains", &subdomains_obj)) {
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
    if (*count > 0) {
        sd_info("Found %zu subdomains from PassiveTotal", *count);
    }
    return results;
}

// SecurityTrails API
char **api_securitytrails_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.securitytrails.com/v1/domain/%s/subdomains", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "APIKEY: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    *count = 0;
    CURL *curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(headers);
        return NULL;
    }

    curl_response_t response = {NULL, 0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !response.data) {
        if (response.data) free(response.data);
        return NULL;
    }

    struct json_object *json = json_tokener_parse(response.data);
    free(response.data);
    if (!json) return NULL;

    struct json_object *subdomains_obj;
    if (!json_object_object_get_ex(json, "subdomains", &subdomains_obj)) {
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
    if (*count > 0) {
        sd_info("Found %zu subdomains from SecurityTrails", *count);
    }
    return results;
}

// Shodan API (existing)
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
    if (*count > 0) {
        sd_info("Found %zu subdomains from Shodan", *count);
    }
    return results;
}

// VirusTotal API (existing)
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
    if (*count > 0) {
        sd_info("Found %zu subdomains from VirusTotal", *count);
    }
    return results;
}

// WhoisXMLAPI
char **api_whoisxmlapi_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s", api_key, domain);

    return generic_api_query(url, NULL, "WhoisXMLAPI", domain, "result.records", false, count);
}

// ZoomEye API
char **api_zoomeye_query(const char *domain, const char *api_key, size_t *count) {
    if (!domain || !api_key || !count) {
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "https://api.zoomeye.org/domain/search?q=+%s&type=1&page=1", domain);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "API-KEY: %s", api_key);
    headers = curl_slist_append(headers, auth_header);

    char **results = generic_api_query(url, headers, "ZoomEye", domain, "list", false, count);
    curl_slist_free_all(headers);
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
