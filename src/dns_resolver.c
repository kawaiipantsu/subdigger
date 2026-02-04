#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include "../include/subdigger.h"

typedef struct {
    bool completed;
    bool has_result;
    char result[MAX_DOMAIN_LEN];
} dns_query_result_t;

static void dns_callback_a(void *arg, int status, int timeouts __attribute__((unused)), struct hostent *host) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && host && host->h_addr_list[0]) {
        char ip[MAX_IP_LEN];
        if (host->h_addrtype == AF_INET) {
            inet_ntop(AF_INET, host->h_addr_list[0], ip, sizeof(ip));
        } else if (host->h_addrtype == AF_INET6) {
            inet_ntop(AF_INET6, host->h_addr_list[0], ip, sizeof(ip));
        } else {
            result->completed = true;
            return;
        }
        safe_strncpy(result->result, ip, sizeof(result->result));
        result->has_result = true;
    }

    result->completed = true;
}

static void dns_callback_cname(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && abuf) {
        struct hostent *host;
        if (ares_parse_a_reply(abuf, alen, &host, NULL, NULL) == ARES_SUCCESS) {
            if (host && host->h_name) {
                safe_strncpy(result->result, host->h_name, sizeof(result->result));
                result->has_result = true;
            }
            if (host) {
                ares_free_hostent(host);
            }
        }
    }

    result->completed = true;
}

static void dns_callback_ns(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && abuf) {
        struct hostent *host;
        if (ares_parse_ns_reply(abuf, alen, &host) == ARES_SUCCESS) {
            if (host && host->h_aliases && host->h_aliases[0]) {
                safe_strncpy(result->result, host->h_aliases[0], sizeof(result->result));
                result->has_result = true;
            }
            if (host) {
                ares_free_hostent(host);
            }
        }
    }

    result->completed = true;
}

static void dns_callback_mx(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && abuf) {
        struct ares_mx_reply *mx_reply = NULL;
        if (ares_parse_mx_reply(abuf, alen, &mx_reply) == ARES_SUCCESS) {
            if (mx_reply && mx_reply->host) {
                safe_strncpy(result->result, mx_reply->host, sizeof(result->result));
                result->has_result = true;
            }
            if (mx_reply) {
                ares_free_data(mx_reply);
            }
        }
    }

    result->completed = true;
}

static void dns_callback_txt(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && abuf) {
        struct ares_txt_reply *txt_reply = NULL;
        if (ares_parse_txt_reply(abuf, alen, &txt_reply) == ARES_SUCCESS) {
            if (txt_reply) {
                result->has_result = true;
                ares_free_data(txt_reply);
            }
        }
    }

    result->completed = true;
}

static void wait_for_query(ares_channel channel, dns_query_result_t *result, int timeout_sec) {
    struct timeval tv, *tvp;
    fd_set read_fds, write_fds;
    int nfds;
    time_t start_time = time(NULL);

    while (!result->completed && !shutdown_requested) {
        time_t now = time(NULL);
        if (now - start_time > timeout_sec) {
            break;
        }

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            tvp = &tv;
        } else {
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            tvp = &tv;
            select(nfds, &read_fds, &write_fds, NULL, tvp);
        }

        ares_process(channel, &read_fds, &write_fds);
    }

    if (!result->completed) {
        ares_cancel(channel);
        result->completed = true;
    }
}

int dns_init(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config) {
        return -1;
    }

    const char *default_servers[] = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222", "208.67.220.220", "9.9.9.9"};
    size_t server_count = 0;
    char **servers = NULL;

    if (ctx->config->dns_servers && ctx->config->dns_server_count > 0) {
        servers = ctx->config->dns_servers;
        server_count = ctx->config->dns_server_count;
    } else {
        servers = (char **)default_servers;
        server_count = 7;
    }

    if (server_count > MAX_DNS_SERVERS) {
        server_count = MAX_DNS_SERVERS;
    }

    ctx->dns_servers = malloc(server_count * sizeof(dns_server_stats_t));
    if (!ctx->dns_servers) {
        sd_error("Failed to allocate DNS server stats");
        return -1;
    }

    ctx->dns_server_count = server_count;

    for (size_t i = 0; i < server_count; i++) {
        memset(&ctx->dns_servers[i], 0, sizeof(dns_server_stats_t));
        safe_strncpy(ctx->dns_servers[i].server, servers[i], sizeof(ctx->dns_servers[i].server));
        ctx->dns_servers[i].last_reset = time(NULL);
    }

    sd_info("Initialized %zu DNS server(s)", server_count);
    for (size_t i = 0; i < server_count; i++) {
        sd_info("  DNS server %zu: %s", i + 1, ctx->dns_servers[i].server);
    }

    return 0;
}

void dns_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->dns_servers) {
        return;
    }

    free(ctx->dns_servers);
    ctx->dns_servers = NULL;
    ctx->dns_server_count = 0;
}

bool dns_resolve_full(subdigger_ctx_t *ctx, const char *subdomain, subdomain_result_t *result, thread_dns_context_t *dns_ctx) {
    if (!ctx || !subdomain || !result || !dns_ctx || !dns_ctx->channel || !ctx->dns_servers || dns_ctx->server_idx >= ctx->dns_server_count) {
        return false;
    }

    dns_server_stats_t *server = &ctx->dns_servers[dns_ctx->server_idx];
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    ares_channel channel = (ares_channel)dns_ctx->channel;
    int timeout = ctx->config ? ctx->config->timeout : DEFAULT_TIMEOUT;

    safe_strncpy(result->subdomain, subdomain, sizeof(result->subdomain));
    safe_strncpy(result->a_record, "N/A", sizeof(result->a_record));
    safe_strncpy(result->cname_record, "N/A", sizeof(result->cname_record));
    safe_strncpy(result->ns_record, "N/A", sizeof(result->ns_record));
    safe_strncpy(result->mx_record, "N/A", sizeof(result->mx_record));
    result->has_txt = false;
    safe_strncpy(result->country_code, "N/A", sizeof(result->country_code));
    result->timestamp = time(NULL);

    extract_tld(subdomain, result->tld, sizeof(result->tld));

    dns_query_result_t a_result = {false, false, ""};
    ares_gethostbyname(channel, subdomain, AF_INET, dns_callback_a, &a_result);
    wait_for_query(channel, &a_result, timeout);

    if (!a_result.has_result) {
        dns_query_result_t a6_result = {false, false, ""};
        ares_gethostbyname(channel, subdomain, AF_INET6, dns_callback_a, &a6_result);
        wait_for_query(channel, &a6_result, timeout);

        if (a6_result.has_result) {
            safe_strncpy(result->a_record, a6_result.result, sizeof(result->a_record));
            a_result.has_result = true;
        }
    } else {
        safe_strncpy(result->a_record, a_result.result, sizeof(result->a_record));
    }

    bool has_a_record = a_result.has_result;

    dns_query_result_t cname_result = {false, false, ""};
    ares_query(channel, subdomain, ns_c_in, ns_t_cname, dns_callback_cname, &cname_result);
    wait_for_query(channel, &cname_result, timeout);
    if (cname_result.has_result) {
        safe_strncpy(result->cname_record, cname_result.result, sizeof(result->cname_record));
    }

    dns_query_result_t ns_result = {false, false, ""};
    ares_query(channel, subdomain, ns_c_in, ns_t_ns, dns_callback_ns, &ns_result);
    wait_for_query(channel, &ns_result, timeout);
    if (ns_result.has_result) {
        safe_strncpy(result->ns_record, ns_result.result, sizeof(result->ns_record));
    }

    bool has_resolution = has_a_record || cname_result.has_result || ns_result.has_result;

    if (has_a_record && ctx->geoip_db && strcmp(result->a_record, "N/A") != 0) {
        pthread_mutex_lock(&ctx->geoip_mutex);
        geoip_lookup(ctx, result->a_record, result->country_code);
        pthread_mutex_unlock(&ctx->geoip_mutex);
    }

    if (has_a_record) {
        dns_query_result_t mx_result = {false, false, ""};
        ares_query(channel, subdomain, ns_c_in, ns_t_mx, dns_callback_mx, &mx_result);
        wait_for_query(channel, &mx_result, timeout);
        if (mx_result.has_result) {
            safe_strncpy(result->mx_record, mx_result.result, sizeof(result->mx_record));
        }

        dns_query_result_t txt_result = {false, false, ""};
        ares_query(channel, subdomain, ns_c_in, ns_t_txt, dns_callback_txt, &txt_result);
        wait_for_query(channel, &txt_result, timeout);
        result->has_txt = txt_result.has_result;
    }

    gettimeofday(&end_time, NULL);
    size_t elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_usec - start_time.tv_usec) / 1000;

    __sync_add_and_fetch(&server->queries, 1);
    __sync_add_and_fetch(&server->total_time_ms, elapsed_ms);
    if (has_resolution) {
        __sync_add_and_fetch(&server->successes, 1);
    } else {
        __sync_add_and_fetch(&server->failures, 1);
    }

    return has_resolution;
}

static void *dns_stats_thread(void *arg) {
    subdigger_ctx_t *ctx = (subdigger_ctx_t *)arg;

    while (ctx->stats_active && !shutdown_requested) {
        for (int i = 0; i < 60 && ctx->stats_active && !shutdown_requested; i++) {
            sleep(1);
        }

        if (!ctx->stats_active || shutdown_requested) {
            break;
        }

        if (!global_quiet_mode) {
            fprintf(stderr, "\n========== DNS Server Statistics ==========\n");
            for (size_t i = 0; i < ctx->dns_server_count; i++) {
                dns_server_stats_t *s = &ctx->dns_servers[i];
                time_t elapsed = time(NULL) - s->last_reset;
                if (elapsed == 0) elapsed = 1;

                size_t queries = s->queries;
                size_t successes = s->successes;
                size_t total_time = s->total_time_ms;
                size_t active = s->active_threads;

                double qps = (double)queries / elapsed;
                double avg_ms = queries > 0 ? (double)total_time / queries : 0;
                double success_rate = queries > 0 ? (double)successes * 100 / queries : 0;

                fprintf(stderr, "[%s] %.1f q/s | %.0f ms avg | %.1f%% success | %zu threads | %zu queries\n",
                       s->server, qps, avg_ms, success_rate, active, queries);
            }
            fprintf(stderr, "===========================================\n\n");
        }
    }

    return NULL;
}

void start_dns_stats_monitor(subdigger_ctx_t *ctx) {
    if (!ctx || ctx->config->quiet_mode) {
        return;
    }

    ctx->stats_active = true;
    if (pthread_create(&ctx->stats_thread, NULL, dns_stats_thread, ctx) != 0) {
        sd_warn("Failed to create DNS stats thread");
        ctx->stats_active = false;
    }
}

void stop_dns_stats_monitor(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->stats_active) {
        return;
    }

    ctx->stats_active = false;
    pthread_join(ctx->stats_thread, NULL);
}
