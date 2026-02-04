#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/subdigger.h"

void sanitize_domain(char *domain) {
    if (!domain) {
        return;
    }

    size_t len = strlen(domain);
    if (len >= MAX_DOMAIN_LEN) {
        domain[MAX_DOMAIN_LEN - 1] = '\0';
        len = MAX_DOMAIN_LEN - 1;
    }

    for (size_t i = 0; i < len; i++) {
        char c = domain[i];
        if (!isalnum(c) && c != '.' && c != '-') {
            memmove(&domain[i], &domain[i + 1], len - i);
            len--;
            i--;
        }
    }
}

bool validate_file_path(const char *path) {
    if (!path || strlen(path) == 0) {
        return false;
    }

    if (strstr(path, "..") != NULL) {
        sd_error("Path traversal detected in: %s", path);
        return false;
    }

    if (strlen(path) > 4096) {
        sd_error("Path too long: %s", path);
        return false;
    }

    return true;
}

int check_config_permissions(const char *path) {
    if (!path) {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }

    if (st.st_mode & S_IROTH) {
        sd_warn("Config file %s is world-readable (may contain API keys)", path);
        return 1;
    }

    if (st.st_mode & S_IWOTH) {
        sd_warn("Config file %s is world-writable (security risk)", path);
        return 1;
    }

    return 0;
}
