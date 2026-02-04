#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/select.h>
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
    struct timeval tv;
    fd_set read_fds, write_fds;
    int nfds;
    time_t start_time = time(NULL);

    while (!result->completed) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0) {
            break;
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        select(nfds, &read_fds, &write_fds, NULL, &tv);

        ares_process(channel, &read_fds, &write_fds);

        if (time(NULL) - start_time > timeout_sec) {
            break;
        }
    }
}

int dns_init(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config) {
        return -1;
    }

    ares_channel channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        sd_error("Failed to initialize c-ares: %s", ares_strerror(status));
        return -1;
    }

    if (ctx->config->dns_servers && ctx->config->dns_server_count > 0) {
        struct ares_options options;
        memset(&options, 0, sizeof(options));
        options.timeout = ctx->config->timeout * 1000;
        options.tries = 3;

        ares_set_servers_csv(channel, ctx->config->dns_servers[0]);
    }

    ctx->dns_channel = channel;
    return 0;
}

void dns_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->dns_channel) {
        return;
    }

    ares_destroy((ares_channel)ctx->dns_channel);
    ctx->dns_channel = NULL;
}

bool dns_resolve_full(subdigger_ctx_t *ctx, const char *subdomain, subdomain_result_t *result) {
    if (!ctx || !subdomain || !result || !ctx->dns_channel) {
        return false;
    }

    ares_channel channel = (ares_channel)ctx->dns_channel;
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

    if (!a_result.has_result) {
        return false;
    }

    if (ctx->geoip_db && strcmp(result->a_record, "N/A") != 0) {
        geoip_lookup(ctx, result->a_record, result->country_code);
    }

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

    return true;
}
