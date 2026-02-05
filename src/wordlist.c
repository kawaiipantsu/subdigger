#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
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

static bool ends_with_txt(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) {
        return false;
    }
    return strcmp(filename + len - 4, ".txt") == 0;
}

char **wordlist_discover_auto(size_t *count) {
    if (!count) {
        return NULL;
    }

    *count = 0;
    char **paths = NULL;
    size_t path_count = 0;

    const char *search_dirs[] = {
        "/usr/share/subdigger/wordlists",
        NULL,
        NULL
    };

    struct passwd *pw = getpwuid(getuid());
    char user_dir[1024];
    if (pw) {
        snprintf(user_dir, sizeof(user_dir), "%s/.subdigger/wordlists", pw->pw_dir);
        search_dirs[1] = user_dir;
    }

    sd_info("Searching for wordlists in:");
    for (int i = 0; search_dirs[i] != NULL; i++) {
        sd_info("  - %s", search_dirs[i]);
    }

    for (int i = 0; search_dirs[i] != NULL; i++) {
        DIR *dir = opendir(search_dirs[i]);
        if (!dir) {
            continue;
        }

        size_t dir_count = 0;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) {
                continue;
            }

            if (!ends_with_txt(entry->d_name)) {
                continue;
            }

            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s/%s", search_dirs[i], entry->d_name);

            struct stat st;
            if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }

            paths = realloc(paths, (path_count + 1) * sizeof(char *));
            if (!paths) {
                closedir(dir);
                return NULL;
            }

            paths[path_count] = strdup(full_path);
            path_count++;
            dir_count++;

            sd_info("Found wordlist: %s", entry->d_name);
        }

        if (dir_count > 0) {
            sd_info("Found %zu wordlist(s) in %s", dir_count, search_dirs[i]);
        }

        closedir(dir);
    }

    if (path_count == 0) {
        sd_warn("No .txt wordlist files found in any search directory");
        return NULL;
    }

    sd_info("Total discovered: %zu wordlist file(s)", path_count);

    char **combined = wordlist_load_multiple(paths, path_count, count);

    for (size_t i = 0; i < path_count; i++) {
        free(paths[i]);
    }
    free(paths);

    return combined;
}

char **wordlist_load_multiple(char **paths, size_t path_count, size_t *total_count) {
    if (!paths || !total_count || path_count == 0) {
        return NULL;
    }

    *total_count = 0;
    char **combined = malloc(1000 * sizeof(char *));
    if (!combined) {
        return NULL;
    }

    size_t capacity = 1000;
    size_t unique_count = 0;

    for (size_t p = 0; p < path_count; p++) {
        size_t list_count = 0;
        char **wordlist = wordlist_load(paths[p], &list_count);

        if (!wordlist) {
            continue;
        }

        for (size_t i = 0; i < list_count; i++) {
            if (unique_count >= capacity) {
                capacity *= 2;
                if (capacity > MAX_WORDLIST_LINES) {
                    sd_warn("Combined wordlist exceeds maximum size, truncating");
                    wordlist_free(wordlist, list_count);
                    break;
                }
                char **new_combined = realloc(combined, capacity * sizeof(char *));
                if (!new_combined) {
                    wordlist_free(wordlist, list_count);
                    wordlist_free(combined, unique_count);
                    return NULL;
                }
                combined = new_combined;
            }

            combined[unique_count] = strdup(wordlist[i]);
            unique_count++;
        }

        wordlist_free(wordlist, list_count);
    }

    *total_count = unique_count;
    sd_info("Combined %zu unique entries from %zu wordlist file(s)", unique_count, path_count);

    return combined;
}

void wordlist_load_and_queue_auto(subdigger_ctx_t *ctx, const char *domain, size_t *total_candidates) {
    if (!ctx || !domain || !total_candidates) {
        return;
    }

    const char *search_dirs[] = {
        "/usr/share/subdigger/wordlists",
        NULL,
        NULL
    };

    struct passwd *pw = getpwuid(getuid());
    char user_dir[1024];
    if (pw) {
        snprintf(user_dir, sizeof(user_dir), "%s/.subdigger/wordlists", pw->pw_dir);
        search_dirs[1] = user_dir;
    }

    size_t total_files_loaded = 0;
    size_t total_words_queued = 0;

    // First pass: discover all wordlist files
    char **all_files = NULL;
    size_t all_files_count = 0;

    for (int i = 0; search_dirs[i] != NULL; i++) {
        DIR *dir = opendir(search_dirs[i]);
        if (!dir) {
            if (i == 0) {
                sd_warn("System wordlist directory not found: %s", search_dirs[i]);
            }
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) {
                continue;
            }

            if (!ends_with_txt(entry->d_name)) {
                continue;
            }

            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s/%s", search_dirs[i], entry->d_name);

            struct stat st;
            if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }

            all_files = realloc(all_files, (all_files_count + 1) * sizeof(char *));
            if (!all_files) {
                closedir(dir);
                return;
            }
            all_files[all_files_count] = strdup(full_path);
            all_files_count++;
        }

        closedir(dir);
    }

    if (all_files_count == 0) {
        sd_warn("No wordlist files found in any search directory");
        return;
    }

    sd_info("Discovered %zu wordlist file(s), loading...", all_files_count);

    // Second pass: load and queue all discovered files
    for (size_t f = 0; f < all_files_count && !shutdown_requested; f++) {
        const char *full_path = all_files[f];
        const char *filename = strrchr(full_path, '/');
        filename = filename ? filename + 1 : full_path;

        sd_info("Loading wordlist %zu/%zu: %s", f + 1, all_files_count, filename);

        size_t list_count = 0;
        char **wordlist = wordlist_load(full_path, &list_count);

        if (wordlist) {
            // Strip .txt extension from filename for cleaner source display
            char clean_name[64];
            safe_strncpy(clean_name, filename, sizeof(clean_name));
            size_t len = strlen(clean_name);
            if (len > 4 && strcmp(clean_name + len - 4, ".txt") == 0) {
                clean_name[len - 4] = '\0';
            }

            char source[64];
            snprintf(source, sizeof(source), "wordlist:%s", clean_name);

            size_t queued_from_this_file = 0;
            size_t last_progress_report = 0;
            for (size_t j = 0; j < list_count && !shutdown_requested; j++) {
                char subdomain[MAX_DOMAIN_LEN];
                snprintf(subdomain, sizeof(subdomain), "%s.%s", wordlist[j], domain);
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, subdomain, source)) {
                    (*total_candidates)++;
                    queued_from_this_file++;
                }

                // Show progress for large wordlists (every 50k items)
                if (list_count > 50000 && (j - last_progress_report) >= 50000) {
                    sd_info("  Queuing progress: %zu/%zu (%.0f%%)", j, list_count, (j * 100.0) / list_count);
                    last_progress_report = j;
                }
            }

            if (list_count > 50000) {
                sd_info("  Completed queuing %zu candidates from %s", queued_from_this_file, filename);
            }

            total_words_queued += queued_from_this_file;
            wordlist_free(wordlist, list_count);
            total_files_loaded++;
        }
    }

    // Cleanup
    for (size_t i = 0; i < all_files_count; i++) {
        free(all_files[i]);
    }
    free(all_files);

    if (total_files_loaded > 0) {
        sd_info("Auto-discovery complete: %zu wordlist file(s) loaded, %zu unique candidates queued",
                total_files_loaded, total_words_queued);
    } else {
        sd_warn("No wordlist files could be loaded");
    }
}

