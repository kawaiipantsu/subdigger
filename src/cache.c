#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <pwd.h>
#include "../include/subdigger.h"

#define CACHE_TTL_SECONDS (24 * 60 * 60)

static void get_cache_path(const char *domain, char *path, size_t path_size) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date[32];
    strftime(date, sizeof(date), "%Y-%m-%d", tm_info);

    snprintf(path, path_size, "%s/.subdigger/cache/%s-%s.cache", pw->pw_dir, domain, date);
}

int cache_load(const char *domain, result_buffer_t *buffer) {
    if (!domain || !buffer) {
        return -1;
    }

    char path[1024];
    get_cache_path(domain, path, sizeof(path));

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    int fd = fileno(fp);
    if (flock(fd, LOCK_SH) != 0) {
        fclose(fp);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        flock(fd, LOCK_UN);
        fclose(fp);
        return -1;
    }

    time_t now = time(NULL);
    if (now - st.st_mtime > CACHE_TTL_SECONDS) {
        flock(fd, LOCK_UN);
        fclose(fp);
        return 0;
    }

    char line[4096];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        subdomain_result_t result;
        memset(&result, 0, sizeof(result));

        char txt_present[8];
        // Simple cache format - just store basic fields
        // Full format with GeoIP data would be too complex for simple cache
        if (sscanf(line, "%255[^,],%45[^,],%255[^,],%255[^,],%7[^,],%63[^,],%255s",
                   result.subdomain, result.a_record, result.ns_record,
                   result.mx_record, txt_present, result.tld,
                   result.source) >= 6) {

            result.has_txt = (strcmp(txt_present, "true") == 0 || strcmp(txt_present, "Yes") == 0);
            result.timestamp = now;

            result_buffer_add(buffer, &result);
            count++;
        }
    }

    flock(fd, LOCK_UN);
    fclose(fp);

    if (count > 0) {
        sd_info("Loaded %d results from cache", count);
    }

    return count;
}

int cache_save(const char *domain, const result_buffer_t *buffer) {
    if (!domain || !buffer) {
        return -1;
    }

    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        return -1;
    }

    char cache_dir[1024];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.subdigger/cache", pw->pw_dir);
    mkdir(cache_dir, 0700);

    char path[1024];
    get_cache_path(domain, path, sizeof(path));

    FILE *fp = fopen(path, "w");
    if (!fp) {
        sd_warn("Failed to save cache to %s", path);
        return -1;
    }

    int fd = fileno(fp);
    if (flock(fd, LOCK_EX) != 0) {
        fclose(fp);
        return -1;
    }

    for (size_t i = 0; i < buffer->count; i++) {
        const subdomain_result_t *result = &buffer->results[i];

        // Simple cache format - basic fields only
        fprintf(fp, "%s,%s,%s,%s,%s,%s,%s\n",
                result->subdomain,
                result->a_record,
                result->ns_record,
                result->mx_record,
                result->has_txt ? "true" : "false",
                result->tld,
                result->source);
    }

    flock(fd, LOCK_UN);
    fclose(fp);

    sd_info("Saved %zu results to cache", buffer->count);
    return 0;
}
