#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/subdigger.h"

char **wordlist_load(const char *path, size_t *count) {
    if (!path || !count) {
        return NULL;
    }

    *count = 0;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        sd_error("Failed to open wordlist: %s", path);
        return NULL;
    }

    char **wordlist = malloc(1000 * sizeof(char *));
    if (!wordlist) {
        fclose(fp);
        return NULL;
    }

    size_t capacity = 1000;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        if (strlen(trimmed) == 0 || trimmed[0] == '#') {
            continue;
        }

        if (strlen(trimmed) > 63) {
            continue;
        }

        bool is_duplicate = false;
        for (size_t i = 0; i < *count; i++) {
            if (strcmp(wordlist[i], trimmed) == 0) {
                is_duplicate = true;
                break;
            }
        }

        if (is_duplicate) {
            continue;
        }

        bool valid = true;
        for (size_t i = 0; i < strlen(trimmed); i++) {
            char c = trimmed[i];
            if (!isalnum(c) && c != '-') {
                valid = false;
                break;
            }
        }

        if (!valid) {
            continue;
        }

        if (*count >= capacity) {
            capacity *= 2;
            if (capacity > MAX_WORDLIST_LINES) {
                sd_warn("Wordlist exceeds maximum size, truncating");
                break;
            }
            char **new_wordlist = realloc(wordlist, capacity * sizeof(char *));
            if (!new_wordlist) {
                wordlist_free(wordlist, *count);
                fclose(fp);
                return NULL;
            }
            wordlist = new_wordlist;
        }

        wordlist[*count] = strdup(trimmed);
        (*count)++;
    }

    fclose(fp);

    if (*count == 0) {
        free(wordlist);
        return NULL;
    }

    sd_info("Loaded %zu words from wordlist", *count);
    return wordlist;
}

void wordlist_free(char **wordlist, size_t count) {
    if (!wordlist) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(wordlist[i]);
    }

    free(wordlist);
}
