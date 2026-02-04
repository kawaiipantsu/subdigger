#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include "../include/subdigger.h"

void sd_error(const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] ERROR: ", timestamp);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void sd_warn(const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] WARN: ", timestamp);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void sd_info(const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] INFO: ", timestamp);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

bool validate_domain(const char *domain) {
    if (!domain || strlen(domain) == 0 || strlen(domain) >= MAX_DOMAIN_LEN) {
        return false;
    }

    size_t len = strlen(domain);
    if (len < 3 || len > 253) {
        return false;
    }

    if (domain[0] == '.' || domain[len - 1] == '.') {
        return false;
    }

    if (domain[0] == '-' || domain[len - 1] == '-') {
        return false;
    }

    int label_len = 0;
    int dot_count = 0;

    for (size_t i = 0; i < len; i++) {
        char c = domain[i];

        if (c == '.') {
            if (label_len == 0 || label_len > 63) {
                return false;
            }
            label_len = 0;
            dot_count++;
            continue;
        }

        if (!isalnum(c) && c != '-') {
            return false;
        }

        label_len++;
        if (label_len > 63) {
            return false;
        }
    }

    if (dot_count == 0) {
        return false;
    }

    if (label_len == 0 || label_len > 63) {
        return false;
    }

    return true;
}

void extract_tld(const char *domain, char *tld, size_t tld_size) {
    if (!domain || !tld || tld_size == 0) {
        return;
    }

    const char *last_dot = strrchr(domain, '.');
    if (last_dot && *(last_dot + 1) != '\0') {
        safe_strncpy(tld, last_dot + 1, tld_size);
    } else {
        safe_strncpy(tld, "unknown", tld_size);
    }
}

void safe_strncpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) {
        return;
    }

    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';
}

char *trim(char *str) {
    if (!str) {
        return NULL;
    }

    while (isspace((unsigned char)*str)) {
        str++;
    }

    if (*str == '\0') {
        return str;
    }

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    *(end + 1) = '\0';

    return str;
}
