#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <ares.h>
#include "../include/subdigger.h"

// Generate a random impossible subdomain for wildcard testing
static void generate_random_subdomain(char *output, size_t size, const char *domain) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t prefix_len = 20;

    char prefix[32];
    for (size_t i = 0; i < prefix_len; i++) {
        prefix[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    prefix[prefix_len] = '\0';

    snprintf(output, size, "%s-wildcard-test.%s", prefix, domain);
}

// Callback for wildcard detection queries
typedef struct {
    char ip[MAX_IP_LEN];
    bool resolved;
} wildcard_test_result_t;

static void wildcard_callback(void *arg, int status, int timeouts, struct hostent *host) {
    (void)timeouts;
    wildcard_test_result_t *result = (wildcard_test_result_t *)arg;

    if (status == ARES_SUCCESS && host && host->h_addr_list[0]) {
        char ip[MAX_IP_LEN];
        if (host->h_addrtype == AF_INET) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
            if (inet_ntop(AF_INET, &addr, ip, sizeof(ip))) {
                safe_strncpy(result->ip, ip, sizeof(result->ip));
                result->resolved = true;
            }
        } else if (host->h_addrtype == AF_INET6) {
            struct in6_addr addr6;
            memcpy(&addr6, host->h_addr_list[0], sizeof(struct in6_addr));
            if (inet_ntop(AF_INET6, &addr6, ip, sizeof(ip))) {
                safe_strncpy(result->ip, ip, sizeof(result->ip));
                result->resolved = true;
            }
        }
    }
}

// Detect wildcard DNS records by testing random subdomains
int wildcard_detect(subdigger_ctx_t *ctx, const char *domain) {
    if (!ctx || !domain) {
        return -1;
    }

    pthread_mutex_init(&ctx->wildcard_mutex, NULL);
    ctx->wildcard_ips = NULL;
    ctx->wildcard_ip_count = 0;
    ctx->wildcard_filtered = 0;

    // Test 3 random subdomains
    const int test_count = 3;
    wildcard_test_result_t results[3] = {0};
    char test_domains[3][MAX_DOMAIN_LEN];

    // Seed random number generator
    srand(time(NULL));

    // Generate random test subdomains
    for (int i = 0; i < test_count; i++) {
        generate_random_subdomain(test_domains[i], sizeof(test_domains[i]), domain);
    }

    sd_info("Testing for wildcard DNS records...");

    // Use first DNS server for wildcard detection
    if (ctx->dns_server_count == 0) {
        sd_warn("No DNS servers configured, skipping wildcard detection");
        return 0;
    }

    ares_channel channel;
    struct ares_options options;
    memset(&options, 0, sizeof(options));
    options.timeout = ctx->config->timeout * 1000;
    options.tries = 2;
    options.servers = NULL;
    options.nservers = 0;

    int optmask = ARES_OPT_TIMEOUT | ARES_OPT_TRIES;
    int status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        sd_warn("Failed to initialize DNS channel for wildcard detection");
        return -1;
    }

    // Set DNS server
    struct ares_addr_node dns_server;
    memset(&dns_server, 0, sizeof(dns_server));
    dns_server.family = AF_INET;
    inet_pton(AF_INET, ctx->dns_servers[0].server, &dns_server.addr.addr4);
    dns_server.next = NULL;
    ares_set_servers(channel, &dns_server);

    // Query all test subdomains
    for (int i = 0; i < test_count; i++) {
        results[i].resolved = false;
        results[i].ip[0] = '\0';
        ares_gethostbyname(channel, test_domains[i], AF_INET, wildcard_callback, &results[i]);
    }

    // Wait for all queries to complete
    fd_set read_fds, write_fds;
    struct timeval tv;
    int nfds;

    while (1) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0) {
            break;
        }

        tv.tv_sec = 2;
        tv.tv_usec = 0;
        select(nfds, &read_fds, &write_fds, NULL, &tv);
        ares_process(channel, &read_fds, &write_fds);
    }

    ares_destroy(channel);

    // Analyze results - if 2+ random subdomains resolve to the same IP, it's a wildcard
    int resolved_count = 0;
    for (int i = 0; i < test_count; i++) {
        if (results[i].resolved && strlen(results[i].ip) > 0) {
            resolved_count++;
        }
    }

    if (resolved_count >= 2) {
        // Check if they all resolve to the same IP
        bool all_same = true;
        const char *first_ip = results[0].ip;

        for (int i = 1; i < test_count; i++) {
            if (results[i].resolved && strcmp(results[i].ip, first_ip) != 0) {
                all_same = false;
                break;
            }
        }

        if (all_same && resolved_count >= 2) {
            // Wildcard detected
            ctx->wildcard_ips = malloc(sizeof(char *));
            if (ctx->wildcard_ips) {
                ctx->wildcard_ips[0] = strdup(first_ip);
                ctx->wildcard_ip_count = 1;
                sd_warn("Wildcard DNS detected: *.%s -> %s", domain, first_ip);
                sd_info("Results matching wildcard IP will be filtered");
                return 1;
            }
        } else if (resolved_count == test_count) {
            // Multiple different IPs - could be round-robin wildcard
            ctx->wildcard_ips = malloc(test_count * sizeof(char *));
            if (ctx->wildcard_ips) {
                for (int i = 0; i < test_count; i++) {
                    if (results[i].resolved) {
                        ctx->wildcard_ips[ctx->wildcard_ip_count++] = strdup(results[i].ip);
                    }
                }
                sd_warn("Round-robin wildcard DNS detected: *.%s -> multiple IPs", domain);
                sd_info("Results matching wildcard IPs will be filtered");
                return 1;
            }
        }
    }

    sd_info("No wildcard DNS detected");
    return 0;
}

// Check if an IP matches a wildcard IP
bool wildcard_is_filtered_ip(subdigger_ctx_t *ctx, const char *ip) {
    if (!ctx || !ip || !ctx->wildcard_ips || ctx->wildcard_ip_count == 0) {
        return false;
    }

    pthread_mutex_lock(&ctx->wildcard_mutex);

    for (size_t i = 0; i < ctx->wildcard_ip_count; i++) {
        if (ctx->wildcard_ips[i] && strcmp(ctx->wildcard_ips[i], ip) == 0) {
            pthread_mutex_unlock(&ctx->wildcard_mutex);
            return true;
        }
    }

    pthread_mutex_unlock(&ctx->wildcard_mutex);
    return false;
}

// Clean up wildcard detection data
void wildcard_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->wildcard_ips) {
        for (size_t i = 0; i < ctx->wildcard_ip_count; i++) {
            free(ctx->wildcard_ips[i]);
        }
        free(ctx->wildcard_ips);
        ctx->wildcard_ips = NULL;
        ctx->wildcard_ip_count = 0;
    }

    pthread_mutex_destroy(&ctx->wildcard_mutex);

    if (ctx->wildcard_filtered > 0) {
        sd_info("Filtered %zu wildcard results", ctx->wildcard_filtered);
    }
}
