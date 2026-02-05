#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <time.h>
#include "../include/subdigger.h"

#define IANA_ROOT_DB_URL "https://www.iana.org/domains/root/db"
#define TLD_DATABASE_FILE "tld-database.csv"
#define TLD_DATABASE_MAX_AGE_DAYS 30

typedef struct {
    char *data;
    size_t size;
} fetch_buffer_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    fetch_buffer_t *mem = (fetch_buffer_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

const char *tld_database_get_path(void) {
    static char path[1024];
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        snprintf(path, sizeof(path), "%s/.subdigger/%s", pw->pw_dir, TLD_DATABASE_FILE);
        return path;
    }
    return NULL;
}

static bool tld_database_needs_update(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return true; // File doesn't exist
    }

    time_t now = time(NULL);
    double seconds = difftime(now, st.st_mtime);
    double days = seconds / (60 * 60 * 24);

    return days > TLD_DATABASE_MAX_AGE_DAYS;
}

static char *extract_text_between(const char *html, const char *start, const char *end) {
    const char *s = strstr(html, start);
    if (!s) return NULL;

    s += strlen(start);
    const char *e = strstr(s, end);
    if (!e) return NULL;

    size_t len = e - s;
    char *result = malloc(len + 1);
    if (!result) return NULL;

    memcpy(result, s, len);
    result[len] = '\0';

    // Trim whitespace
    char *trimmed = trim(result);
    char *final = strdup(trimmed);
    free(result);

    return final;
}

static void html_decode(char *str) {
    if (!str) return;

    char *src = str;
    char *dst = str;

    while (*src) {
        if (*src == '&') {
            if (strncmp(src, "&amp;", 5) == 0) {
                *dst++ = '&';
                src += 5;
            } else if (strncmp(src, "&lt;", 4) == 0) {
                *dst++ = '<';
                src += 4;
            } else if (strncmp(src, "&gt;", 4) == 0) {
                *dst++ = '>';
                src += 4;
            } else if (strncmp(src, "&quot;", 6) == 0) {
                *dst++ = '"';
                src += 6;
            } else if (strncmp(src, "&#39;", 5) == 0) {
                *dst++ = '\'';
                src += 5;
            } else {
                *dst++ = *src++;
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

int tld_database_fetch_and_parse(const char *output_path) {
    if (!output_path) {
        return -1;
    }

    sd_info("Fetching IANA root database from %s", IANA_ROOT_DB_URL);

    CURL *curl = curl_easy_init();
    if (!curl) {
        sd_error("Failed to initialize curl");
        return -1;
    }

    fetch_buffer_t buffer = {0};

    curl_easy_setopt(curl, CURLOPT_URL, IANA_ROOT_DB_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buffer);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SubDigger/1.3.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        sd_error("Failed to fetch IANA database: %s", curl_easy_strerror(res));
        free(buffer.data);
        return -1;
    }

    if (!buffer.data || buffer.size == 0) {
        sd_error("Empty response from IANA");
        free(buffer.data);
        return -1;
    }

    // Parse HTML and extract TLD data
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        sd_error("Failed to open output file: %s", output_path);
        free(buffer.data);
        return -1;
    }

    fprintf(fp, "DOMAIN,TYPE,TLD_MANAGER\n");

    // Parse table rows - IANA structure: <span class="domain tld"><a href="...">domain</a></span>
    // Type: <td>country-code</td> or <td>generic</td> or <td>sponsored</td> etc
    // Manager: <td>Manager Name</td>

    char *pos = buffer.data;
    int count = 0;

    while ((pos = strstr(pos, "<span class=\"domain tld\">"))) {
        pos += strlen("<span class=\"domain tld\">");

        // Extract domain from the href path like: /domains/root/db/com.html
        char *href_start = strstr(pos - strlen("<span class=\"domain tld\">"), "<a href=\"/domains/root/db/");
        if (!href_start) {
            continue;
        }

        href_start += strlen("<a href=\"/domains/root/db/");
        char *href_end = strstr(href_start, ".html\">");
        if (!href_end) {
            continue;
        }

        size_t domain_len = href_end - href_start;
        if (domain_len == 0 || domain_len >= 64) {
            continue;
        }

        char *domain = malloc(domain_len + 1);
        if (!domain) {
            continue;
        }

        memcpy(domain, href_start, domain_len);
        domain[domain_len] = '\0';

        // Move past the domain
        char *row_start = pos;
        char *row_end = strstr(row_start, "</tr>");
        if (!row_end) {
            free(domain);
            continue;
        }

        // Extract type - next <td> after domain span
        char *td_start = strstr(row_start, "</span></td>");
        if (td_start && td_start < row_end) {
            td_start = strstr(td_start, "<td>");
            if (td_start && td_start < row_end) {
                char *type = extract_text_between(td_start, "<td>", "</td>");
                if (type) {
                    html_decode(type);

                    // Extract manager - next <td>
                    char *manager_td = strstr(td_start + 4, "<td>");
                    char *manager = NULL;
                    if (manager_td && manager_td < row_end) {
                        manager = extract_text_between(manager_td, "<td>", "</td>");
                        if (manager) {
                            html_decode(manager);

                            // Remove HTML tags from manager
                            char *tag_start;
                            while ((tag_start = strchr(manager, '<'))) {
                                char *tag_end = strchr(tag_start, '>');
                                if (tag_end) {
                                    memmove(tag_start, tag_end + 1, strlen(tag_end + 1) + 1);
                                } else {
                                    break;
                                }
                            }

                            manager = trim(manager);
                        }
                    }

                    if (!manager) {
                        manager = strdup("");
                    }

                    // Write to CSV (escape commas)
                    char escaped_manager[512];
                    if (strchr(manager, ',') || strchr(manager, '"')) {
                        snprintf(escaped_manager, sizeof(escaped_manager), "\"%s\"", manager);
                        // Escape internal quotes
                        char *quote = escaped_manager;
                        while ((quote = strchr(quote + 1, '"'))) {
                            if (*(quote - 1) != '\\') {
                                memmove(quote + 1, quote, strlen(quote) + 1);
                                *quote = '"';
                                quote += 2;
                            } else {
                                quote++;
                            }
                        }
                    } else {
                        safe_strncpy(escaped_manager, manager, sizeof(escaped_manager));
                    }

                    fprintf(fp, "%s,%s,%s\n", domain, type, escaped_manager);
                    count++;

                    free(type);
                    free(manager);
                }
            }
        }

        free(domain);
        pos = row_end;
    }

    fclose(fp);
    free(buffer.data);

    sd_info("Parsed %d TLDs from IANA database", count);
    return count > 0 ? 0 : -1;
}

int tld_database_init(subdigger_ctx_t *ctx, bool force_update) {
    if (!ctx) {
        return -1;
    }

    const char *db_path = tld_database_get_path();
    if (!db_path) {
        sd_warn("Could not determine TLD database path");
        return -1;
    }

    // Check if update is needed
    bool needs_update = force_update || tld_database_needs_update(db_path);

    if (needs_update) {
        sd_info("TLD database is missing or outdated, downloading...");
        if (tld_database_fetch_and_parse(db_path) != 0) {
            if (force_update) {
                return -1;
            }
            // If not forced, continue with existing file if available
            if (access(db_path, F_OK) != 0) {
                sd_warn("TLD database not available");
                return -1;
            }
            sd_warn("Failed to update TLD database, using existing file");
        }
    }

    // Load database into memory
    FILE *fp = fopen(db_path, "r");
    if (!fp) {
        sd_warn("Could not open TLD database: %s", db_path);
        return -1;
    }

    tld_database_t *db = malloc(sizeof(tld_database_t));
    if (!db) {
        fclose(fp);
        return -1;
    }

    db->entries = malloc(2000 * sizeof(tld_database_entry_t));
    if (!db->entries) {
        free(db);
        fclose(fp);
        return -1;
    }

    pthread_mutex_init(&db->mutex, NULL);
    db->count = 0;

    char line[1024];
    bool first_line = true;

    while (fgets(line, sizeof(line), fp) && db->count < 2000) {
        if (first_line) {
            first_line = false;
            continue; // Skip header
        }

        char domain[64] = {0};
        char type[32] = {0};
        char manager[256] = {0};

        // Simple CSV parsing
        char *comma1 = strchr(line, ',');
        if (!comma1) continue;

        size_t domain_len = comma1 - line;
        if (domain_len >= sizeof(domain)) domain_len = sizeof(domain) - 1;
        memcpy(domain, line, domain_len);
        domain[domain_len] = '\0';

        char *comma2 = strchr(comma1 + 1, ',');
        if (!comma2) continue;

        size_t type_len = comma2 - comma1 - 1;
        if (type_len >= sizeof(type)) type_len = sizeof(type) - 1;
        memcpy(type, comma1 + 1, type_len);
        type[type_len] = '\0';

        char *manager_start = comma2 + 1;
        char *newline = strchr(manager_start, '\n');
        if (newline) *newline = '\0';

        // Handle quoted fields
        if (*manager_start == '"') {
            manager_start++;
            char *end_quote = strrchr(manager_start, '"');
            if (end_quote) *end_quote = '\0';
        }

        safe_strncpy(manager, manager_start, sizeof(manager));

        // Store entry
        safe_strncpy(db->entries[db->count].domain, domain, sizeof(db->entries[db->count].domain));
        safe_strncpy(db->entries[db->count].type, type, sizeof(db->entries[db->count].type));
        safe_strncpy(db->entries[db->count].manager, manager, sizeof(db->entries[db->count].manager));
        db->count++;
    }

    fclose(fp);
    ctx->tld_db = db;

    sd_info("Loaded %zu TLD entries from database", db->count);
    return 0;
}

void tld_database_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->tld_db) {
        return;
    }

    tld_database_t *db = ctx->tld_db;
    pthread_mutex_destroy(&db->mutex);
    free(db->entries);
    free(db);
    ctx->tld_db = NULL;
}

void tld_database_lookup(subdigger_ctx_t *ctx, const char *tld, char *type, char *manager) {
    if (!ctx || !ctx->tld_db || !tld || !type || !manager) {
        if (type) safe_strncpy(type, "", 32);
        if (manager) safe_strncpy(manager, "", 256);
        return;
    }

    tld_database_t *db = ctx->tld_db;
    pthread_mutex_lock(&db->mutex);

    // Remove leading dot if present
    const char *lookup_tld = tld;
    if (*lookup_tld == '.') {
        lookup_tld++;
    }

    for (size_t i = 0; i < db->count; i++) {
        if (strcasecmp(db->entries[i].domain, lookup_tld) == 0) {
            safe_strncpy(type, db->entries[i].type, 32);
            safe_strncpy(manager, db->entries[i].manager, 256);
            pthread_mutex_unlock(&db->mutex);
            return;
        }
    }

    pthread_mutex_unlock(&db->mutex);
    safe_strncpy(type, "", 32);
    safe_strncpy(manager, "", 256);
}
