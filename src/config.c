#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include "../include/subdigger.h"

void config_init(config_t *config) {
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(config_t));

    config->threads = 0;
    config->timeout = DEFAULT_TIMEOUT;
    config->bruteforce_depth = DEFAULT_BRUTEFORCE_DEPTH;
    config->cache_enabled = true;
    config->output_format = strdup("csv");
    config->quiet_mode = false;
    config->show_progress = true;
    config->auto_wordlists = true;

    config->dns_servers = malloc(7 * sizeof(char *));
    if (config->dns_servers) {
        config->dns_servers[0] = strdup("8.8.8.8");
        config->dns_servers[1] = strdup("8.8.4.4");
        config->dns_servers[2] = strdup("1.1.1.1");
        config->dns_servers[3] = strdup("1.0.0.1");
        config->dns_servers[4] = strdup("208.67.222.222");
        config->dns_servers[5] = strdup("208.67.220.220");
        config->dns_servers[6] = strdup("9.9.9.9");
        config->dns_server_count = 7;
    }

    config->methods = malloc(2 * sizeof(char *));
    if (config->methods) {
        config->methods[0] = strdup("wordlist");
        config->methods[1] = strdup("cert");
        config->method_count = 2;
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/.subdigger/wordlists/common-subdomains.txt", pw->pw_dir);
        config->wordlist_path = strdup(path);
    }
}

void config_free(config_t *config) {
    if (!config) {
        return;
    }

    if (config->dns_servers) {
        for (int i = 0; i < config->dns_server_count; i++) {
            free(config->dns_servers[i]);
        }
        free(config->dns_servers);
    }

    free(config->wordlist_path);

    if (config->methods) {
        for (int i = 0; i < config->method_count; i++) {
            free(config->methods[i]);
        }
        free(config->methods);
    }

    free(config->output_format);
    free(config->api_key_shodan);
    free(config->api_key_virustotal);
    free(config->target_domain);
    free(config->output_file);
}

static void parse_methods(config_t *config, const char *value) {
    if (config->methods) {
        for (int i = 0; i < config->method_count; i++) {
            free(config->methods[i]);
        }
        free(config->methods);
    }

    config->method_count = 0;
    config->methods = NULL;

    char *value_copy = strdup(value);
    if (!value_copy) {
        return;
    }

    char *token = strtok(value_copy, ",");
    while (token) {
        token = trim(token);
        config->methods = realloc(config->methods, (config->method_count + 1) * sizeof(char *));
        if (config->methods) {
            config->methods[config->method_count] = strdup(token);
            config->method_count++;
        }
        token = strtok(NULL, ",");
    }

    free(value_copy);
}

static void parse_dns_servers(config_t *config, const char *value) {
    if (config->dns_servers) {
        for (int i = 0; i < config->dns_server_count; i++) {
            free(config->dns_servers[i]);
        }
        free(config->dns_servers);
    }

    config->dns_server_count = 0;
    config->dns_servers = NULL;

    char *value_copy = strdup(value);
    if (!value_copy) {
        return;
    }

    char *token = strtok(value_copy, ",");
    while (token) {
        token = trim(token);
        config->dns_servers = realloc(config->dns_servers, (config->dns_server_count + 1) * sizeof(char *));
        if (config->dns_servers) {
            config->dns_servers[config->dns_server_count] = strdup(token);
            config->dns_server_count++;
        }
        token = strtok(NULL, ",");
    }

    free(value_copy);
}

int config_load(config_t *config, const char *path) {
    if (!config || !path) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    check_config_permissions(path);

    char line[1024];
    char section[64] = "";

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        if (strlen(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                safe_strncpy(section, trimmed + 1, sizeof(section));
            }
            continue;
        }

        char *equals = strchr(trimmed, '=');
        if (!equals) {
            continue;
        }

        *equals = '\0';
        char *key = trim(trimmed);
        char *value = trim(equals + 1);

        if (strcmp(section, "general") == 0) {
            if (strcmp(key, "threads") == 0) {
                config->threads = atoi(value);
                if (config->threads <= 0 || config->threads > (MAX_DNS_SERVERS * MAX_THREADS_PER_DNS_SERVER)) {
                    config->threads = 0;
                }
            } else if (strcmp(key, "timeout") == 0) {
                config->timeout = atoi(value);
                if (config->timeout <= 0) {
                    config->timeout = DEFAULT_TIMEOUT;
                }
            }
        } else if (strcmp(section, "dns") == 0) {
            if (strcmp(key, "servers") == 0) {
                parse_dns_servers(config, value);
            }
        } else if (strcmp(section, "discovery") == 0) {
            if (strcmp(key, "methods") == 0) {
                parse_methods(config, value);
            } else if (strcmp(key, "wordlist_path") == 0) {
                free(config->wordlist_path);
                if (value[0] == '~') {
                    struct passwd *pw = getpwuid(getuid());
                    if (pw) {
                        char expanded[1024];
                        snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, value + 1);
                        config->wordlist_path = strdup(expanded);
                    }
                } else {
                    config->wordlist_path = strdup(value);
                }
            } else if (strcmp(key, "bruteforce_depth") == 0) {
                config->bruteforce_depth = atoi(value);
            }
        } else if (strcmp(section, "output") == 0) {
            if (strcmp(key, "format") == 0) {
                free(config->output_format);
                config->output_format = strdup(value);
            }
        } else if (strcmp(section, "cache") == 0) {
            if (strcmp(key, "enabled") == 0) {
                config->cache_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
        } else if (strcmp(section, "apis") == 0) {
            if (strcmp(key, "shodan_key") == 0 && strlen(value) > 0) {
                free(config->api_key_shodan);
                config->api_key_shodan = strdup(value);
            } else if (strcmp(key, "virustotal_key") == 0 && strlen(value) > 0) {
                free(config->api_key_virustotal);
                config->api_key_virustotal = strdup(value);
            }
        }
    }

    fclose(fp);

    return 0;
}
