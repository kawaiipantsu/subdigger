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
    bool servfail;
    char result[MAX_DOMAIN_LEN];
} dns_query_result_t;

typedef struct {
    dns_query_result_t base;
    char cname[MAX_DOMAIN_LEN];
    bool has_cname;
    const char *query_name;
} dns_a_query_result_t;

static void dns_callback_a(void *arg, int status, int timeouts __attribute__((unused)), struct hostent *host) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_ESERVFAIL) {
        result->servfail = true;
        result->completed = true;
        return;
    }

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

static void dns_callback_a_with_cname(void *arg, int status, int timeouts __attribute__((unused)), struct hostent *host) {
    dns_a_query_result_t *result = (dns_a_query_result_t *)arg;

    if (status == ARES_ESERVFAIL) {
        result->base.servfail = true;
        result->base.completed = true;
        return;
    }

    if (status == ARES_SUCCESS && host) {
        // Check if h_name (canonical name) differs from query name - indicates CNAME
        if (host->h_name && result->query_name && strcasecmp(host->h_name, result->query_name) != 0) {
            safe_strncpy(result->cname, host->h_name, sizeof(result->cname));
            result->has_cname = true;
        }

        if (host->h_addr_list[0]) {
            char ip[MAX_IP_LEN];
            if (host->h_addrtype == AF_INET) {
                inet_ntop(AF_INET, host->h_addr_list[0], ip, sizeof(ip));
            } else if (host->h_addrtype == AF_INET6) {
                inet_ntop(AF_INET6, host->h_addr_list[0], ip, sizeof(ip));
            } else {
                result->base.completed = true;
                return;
            }
            safe_strncpy(result->base.result, ip, sizeof(result->base.result));
            result->base.has_result = true;
        }
    }

    result->base.completed = true;
}

static void dns_callback_cname(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    // Parse CNAME even if status indicates the target doesn't exist
    // Status might be ARES_ENODATA or ARES_ENOTFOUND when CNAME target is dangling
    if ((status == ARES_SUCCESS || status == ARES_ENODATA || status == ARES_ENOTFOUND) && abuf) {
        struct hostent *host = NULL;
        if (ares_parse_a_reply(abuf, alen, &host, NULL, NULL) == ARES_SUCCESS && host) {
            if (host->h_name && host->h_name[0] != '\0') {
                safe_strncpy(result->result, host->h_name, sizeof(result->result));
                result->has_result = true;
            }
            ares_free_hostent(host);
            result->completed = true;
            return;
        }
    }

    // Manual parsing for CNAME-only responses
    if ((status == ARES_SUCCESS || status == ARES_ENODATA || status == ARES_ENOTFOUND) && abuf && alen > 12) {
        unsigned short ancount = (abuf[6] << 8) | abuf[7];

        if (ancount > 0) {
            const unsigned char *aptr = abuf + 12;
            const unsigned char *end = abuf + alen;

            // Skip question section
            char *qname = NULL;
            long len = 0;
            if (ares_expand_name(aptr, abuf, alen, &qname, &len) == ARES_SUCCESS) {
                if (qname) ares_free_string(qname);
                aptr += len + 4;  // Skip QNAME + QTYPE + QCLASS

                // Parse first answer
                if (aptr < end) {
                    char *aname = NULL;
                    if (ares_expand_name(aptr, abuf, alen, &aname, &len) == ARES_SUCCESS) {
                        if (aname) ares_free_string(aname);
                        aptr += len;

                        if (aptr + 10 <= end) {
                            unsigned short atype = (aptr[0] << 8) | aptr[1];
                            aptr += 8;  // Skip TYPE, CLASS, TTL
                            unsigned short rdlen = (aptr[0] << 8) | aptr[1];
                            aptr += 2;

                            // CNAME type is 5
                            if (atype == 5 && aptr + rdlen <= end) {
                                char *cname = NULL;
                                if (ares_expand_name(aptr, abuf, alen, &cname, &len) == ARES_SUCCESS && cname) {
                                    safe_strncpy(result->result, cname, sizeof(result->result));
                                    result->has_result = true;
                                    ares_free_string(cname);
                                }
                            }
                        }
                    }
                }
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

static void dns_callback_caa(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && abuf) {
        struct ares_caa_reply *caa_reply = NULL;
        if (ares_parse_caa_reply(abuf, alen, &caa_reply) == ARES_SUCCESS) {
            if (caa_reply && caa_reply->value) {
                char caa_str[512] = {0};
                int offset = 0;
                struct ares_caa_reply *current = caa_reply;
                while (current && offset < 490) {
                    if (offset > 0) {
                        caa_str[offset++] = ';';
                        caa_str[offset++] = ' ';
                    }
                    int written = snprintf(caa_str + offset, sizeof(caa_str) - offset,
                                          "%s \"%s\"", current->property ? (const char*)current->property : "",
                                          current->value ? (const char*)current->value : "");
                    if (written > 0 && written < (int)(sizeof(caa_str) - offset)) {
                        offset += written;
                    }
                    current = current->next;
                }
                safe_strncpy(result->result, caa_str, sizeof(result->result));
                result->has_result = true;
                ares_free_data(caa_reply);
            }
        }
    }

    result->completed = true;
}

static void dns_callback_ptr(void *arg, int status, int timeouts __attribute__((unused)), struct hostent *host) {
    dns_query_result_t *result = (dns_query_result_t *)arg;

    if (status == ARES_SUCCESS && host && host->h_name) {
        safe_strncpy(result->result, host->h_name, sizeof(result->result));
        result->has_result = true;
    }

    result->completed = true;
}

static void wait_for_query(ares_channel channel, dns_query_result_t *result, int timeout_sec) {
    struct timeval tv, *tvp;
    fd_set read_fds, write_fds;
    int nfds;
    struct timeval abs_start;
    gettimeofday(&abs_start, NULL);
    long timeout_usec = timeout_sec * 1000000L;

    while (!result->completed && !shutdown_requested) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long elapsed_usec = (now.tv_sec - abs_start.tv_sec) * 1000000L + (now.tv_usec - abs_start.tv_usec);

        if (elapsed_usec >= timeout_usec) {
            break;
        }

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
            tvp = &tv;
            usleep(50000);
        } else {
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
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
    time_t wall_start = time(NULL);

    ares_channel channel = (ares_channel)dns_ctx->channel;
    int timeout = ctx->config ? ctx->config->timeout : DEFAULT_TIMEOUT;
    int hard_timeout = timeout * 2;

    // If subdomain matches the root domain, leave subdomain field empty
    if (ctx->config && ctx->config->target_domain && strcmp(subdomain, ctx->config->target_domain) == 0) {
        safe_strncpy(result->subdomain, "", sizeof(result->subdomain));
    } else {
        safe_strncpy(result->subdomain, subdomain, sizeof(result->subdomain));
    }

    safe_strncpy(result->a_record, "", sizeof(result->a_record));
    safe_strncpy(result->aaaa_record, "", sizeof(result->aaaa_record));
    safe_strncpy(result->reverse_dns, "", sizeof(result->reverse_dns));
    safe_strncpy(result->cname_record, "", sizeof(result->cname_record));
    safe_strncpy(result->cname_ip, "", sizeof(result->cname_ip));
    safe_strncpy(result->ns_record, "", sizeof(result->ns_record));
    safe_strncpy(result->mx_record, "", sizeof(result->mx_record));
    result->has_caa = false;
    result->has_txt = false;
    result->dangling = false;
    safe_strncpy(result->tld_iso, "", sizeof(result->tld_iso));
    safe_strncpy(result->tld_country, "", sizeof(result->tld_country));
    safe_strncpy(result->tld_type, "", sizeof(result->tld_type));
    safe_strncpy(result->tld_manager, "", sizeof(result->tld_manager));
    safe_strncpy(result->ip_iso, "", sizeof(result->ip_iso));
    safe_strncpy(result->ip_country, "", sizeof(result->ip_country));
    safe_strncpy(result->ip_city, "", sizeof(result->ip_city));
    safe_strncpy(result->asn_org, "", sizeof(result->asn_org));
    result->timestamp = time(NULL);

    extract_tld(subdomain, result->tld, sizeof(result->tld));

    if (time(NULL) - wall_start >= hard_timeout) {
        ares_cancel(channel);
        return false;
    }

    // Query A record (with CNAME detection)
    dns_a_query_result_t a_result = {{false, false, false, ""}, "", false, subdomain};
    ares_gethostbyname(channel, subdomain, AF_INET, dns_callback_a_with_cname, &a_result);
    wait_for_query(channel, &a_result.base, timeout);

    if (time(NULL) - wall_start >= hard_timeout) {
        ares_cancel(channel);
        return false;
    }

    if (a_result.base.servfail) {
        __sync_add_and_fetch(&server->servfails, 1);
        if (server->servfails >= 3 && !server->disabled) {
            server->disabled = true;
            server->disabled_time = time(NULL);
            if (!global_quiet_mode) {
                sd_warn("DNS server %s disabled due to ServFail errors (will retry in 10s)", server->server);
            }
        }
        return false;
    }

    if (a_result.base.has_result) {
        safe_strncpy(result->a_record, a_result.base.result, sizeof(result->a_record));
    }

    // If CNAME was detected from A query, use it
    bool has_cname_from_a_query = a_result.has_cname;

    // Query AAAA record (separately, not fallback)
    if (time(NULL) - wall_start < hard_timeout) {
        dns_query_result_t aaaa_result = {false, false, false, ""};
        ares_gethostbyname(channel, subdomain, AF_INET6, dns_callback_a, &aaaa_result);
        wait_for_query(channel, &aaaa_result, timeout);

        if (time(NULL) - wall_start >= hard_timeout) {
            ares_cancel(channel);
            return a_result.base.has_result;
        }

        if (aaaa_result.servfail) {
            __sync_add_and_fetch(&server->servfails, 1);
            if (server->servfails >= 3 && !server->disabled) {
                server->disabled = true;
                server->disabled_time = time(NULL);
                if (!global_quiet_mode) {
                    sd_warn("DNS server %s disabled due to ServFail errors (will retry in 10s)", server->server);
                }
            }
            return a_result.base.has_result;
        }

        if (aaaa_result.has_result) {
            safe_strncpy(result->aaaa_record, aaaa_result.result, sizeof(result->aaaa_record));
        }
    }

    bool has_a_record = a_result.base.has_result;

    // Reverse DNS lookup for A record
    if (has_a_record && result->a_record[0] != '\0' && (time(NULL) - wall_start < hard_timeout)) {
        struct in_addr addr;
        if (inet_pton(AF_INET, result->a_record, &addr) == 1) {
            dns_query_result_t ptr_result = {false, false, false, ""};
            ares_gethostbyaddr(channel, &addr, sizeof(addr), AF_INET, dns_callback_ptr, &ptr_result);
            wait_for_query(channel, &ptr_result, timeout);

            if (ptr_result.has_result && ptr_result.result[0] != '\0') {
                safe_strncpy(result->reverse_dns, ptr_result.result, sizeof(result->reverse_dns));

                // Check if reverse DNS is a subdomain of target domain
                if (ctx->config && ctx->config->target_domain) {
                    const char *target_domain = ctx->config->target_domain;
                    size_t target_len = strlen(target_domain);
                    size_t ptr_len = strlen(ptr_result.result);

                    // Check if it ends with target domain
                    if (ptr_len >= target_len) {
                        const char *domain_part = ptr_result.result + (ptr_len - target_len);
                        if (strcasecmp(domain_part, target_domain) == 0 &&
                            (ptr_len == target_len || ptr_result.result[ptr_len - target_len - 1] == '.')) {

                            // Remove trailing dot if present
                            char clean_hostname[MAX_DOMAIN_LEN];
                            safe_strncpy(clean_hostname, ptr_result.result, sizeof(clean_hostname));
                            size_t len = strlen(clean_hostname);
                            if (len > 0 && clean_hostname[len - 1] == '.') {
                                clean_hostname[len - 1] = '\0';
                            }

                            // Check if it's different from current subdomain
                            if (strcasecmp(clean_hostname, subdomain) != 0) {
                                // Add to task queue for processing (unique check)
                                if (ctx->task_queue && ctx->discovered_buffer && ctx->discovery_active) {
                                    task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, clean_hostname, "rdns");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (time(NULL) - wall_start >= hard_timeout) {
        ares_cancel(channel);
        return has_a_record;
    }

    // Follow CNAME chain
    dns_query_result_t cname_result = {false, false, false, ""};

    // Use CNAME from A query if available, otherwise query specifically
    if (has_cname_from_a_query) {
        safe_strncpy(cname_result.result, a_result.cname, sizeof(cname_result.result));
        cname_result.has_result = true;
        cname_result.completed = true;
    } else {
        ares_query(channel, subdomain, ns_c_in, ns_t_cname, dns_callback_cname, &cname_result);
        wait_for_query(channel, &cname_result, timeout);
    }

    if (cname_result.has_result) {
        char cname_chain[MAX_DOMAIN_LEN * 3] = {0};
        safe_strncpy(cname_chain, cname_result.result, sizeof(cname_chain));

        char current_target[MAX_DOMAIN_LEN];
        safe_strncpy(current_target, cname_result.result, sizeof(current_target));

        int chain_depth = 0;
        const int max_chain_depth = 10;

        // Follow the CNAME chain
        while (chain_depth < max_chain_depth && time(NULL) - wall_start < hard_timeout) {
            dns_query_result_t next_cname = {false, false, false, ""};
            ares_query(channel, current_target, ns_c_in, ns_t_cname, dns_callback_cname, &next_cname);
            wait_for_query(channel, &next_cname, timeout);

            if (next_cname.has_result && strlen(next_cname.result) > 0) {
                // Add to chain with arrow separator
                size_t current_len = strlen(cname_chain);
                if (current_len + strlen(next_cname.result) + 4 < sizeof(cname_chain)) {
                    strncat(cname_chain, " > ", sizeof(cname_chain) - current_len - 1);
                    strncat(cname_chain, next_cname.result, sizeof(cname_chain) - current_len - 4);
                }
                safe_strncpy(current_target, next_cname.result, sizeof(current_target));
                chain_depth++;
            } else {
                break;
            }
        }

        safe_strncpy(result->cname_record, cname_chain, sizeof(result->cname_record));

        // Resolve final CNAME to IP
        bool cname_target_resolves = false;
        if (time(NULL) - wall_start < hard_timeout) {
            dns_query_result_t cname_ip_result = {false, false, false, ""};
            ares_gethostbyname(channel, current_target, AF_INET, dns_callback_a, &cname_ip_result);
            wait_for_query(channel, &cname_ip_result, timeout);
            if (cname_ip_result.has_result) {
                safe_strncpy(result->cname_ip, cname_ip_result.result, sizeof(result->cname_ip));
                cname_target_resolves = true;
            }
        }

        // Check for dangling CNAME (CNAME points to non-existent domain)
        if (!cname_target_resolves) {
            result->dangling = true;
        }
    }

    if (time(NULL) - wall_start >= hard_timeout) {
        ares_cancel(channel);
        return has_a_record;
    }

    dns_query_result_t ns_result = {false, false, false, ""};
    ares_query(channel, subdomain, ns_c_in, ns_t_ns, dns_callback_ns, &ns_result);
    wait_for_query(channel, &ns_result, timeout);
    if (ns_result.has_result) {
        safe_strncpy(result->ns_record, ns_result.result, sizeof(result->ns_record));

        // Check if NS server resolves (for dangling NS detection)
        if (time(NULL) - wall_start < hard_timeout) {
            dns_query_result_t ns_ip_result = {false, false, false, ""};
            ares_gethostbyname(channel, ns_result.result, AF_INET, dns_callback_a, &ns_ip_result);
            wait_for_query(channel, &ns_ip_result, timeout);

            // If NS record exists but NS server doesn't resolve, it's dangling
            if (!ns_ip_result.has_result) {
                result->dangling = true;
            }
        }
    }

    // Query CAA record
    if (time(NULL) - wall_start < hard_timeout) {
        dns_query_result_t caa_result = {false, false, false, ""};
        ares_query(channel, subdomain, ns_c_in, ns_t_caa, dns_callback_caa, &caa_result);
        wait_for_query(channel, &caa_result, timeout);
        result->has_caa = caa_result.has_result;
    }

    bool has_resolution = has_a_record || cname_result.has_result || ns_result.has_result;

    // GeoIP lookup - prefer A record, fallback to CNAME IP
    const char *lookup_ip = NULL;
    if (has_a_record && result->a_record[0] != '\0') {
        lookup_ip = result->a_record;
    } else if (result->cname_ip[0] != '\0') {
        lookup_ip = result->cname_ip;
    }

    if (lookup_ip) {
        geoip_lookup(ctx, lookup_ip, result);
    }

    tld_lookup_country(result->tld, result->tld_iso, result->tld_country);
    tld_database_lookup(ctx, result->tld, result->tld_type, result->tld_manager);

    if (has_a_record && (time(NULL) - wall_start < hard_timeout)) {
        dns_query_result_t mx_result = {false, false, false, ""};
        ares_query(channel, subdomain, ns_c_in, ns_t_mx, dns_callback_mx, &mx_result);
        wait_for_query(channel, &mx_result, timeout);
        if (mx_result.has_result) {
            safe_strncpy(result->mx_record, mx_result.result, sizeof(result->mx_record));
        }

        if (time(NULL) - wall_start < hard_timeout) {
            dns_query_result_t txt_result = {false, false, false, ""};
            ares_query(channel, subdomain, ns_c_in, ns_t_txt, dns_callback_txt, &txt_result);
            wait_for_query(channel, &txt_result, timeout);
            result->has_txt = txt_result.has_result;
        }
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

    // Check if result matches wildcard IP and should be filtered
    if (has_resolution && (strlen(result->a_record) > 0 || strlen(result->aaaa_record) > 0)) {
        const char *check_ip = strlen(result->a_record) > 0 ? result->a_record : result->aaaa_record;
        if (wildcard_is_filtered_ip(ctx, check_ip)) {
            __sync_add_and_fetch(&ctx->wildcard_filtered, 1);
            return false;
        }
    }

    return has_resolution;
}

static void *dns_stats_thread(void *arg) {
    subdigger_ctx_t *ctx = (subdigger_ctx_t *)arg;
    int loop_counter = 0;

    while (ctx->stats_active && !shutdown_requested) {
        for (int i = 0; i < 10 && ctx->stats_active && !shutdown_requested; i++) {
            sleep(1);
        }

        if (!ctx->stats_active || shutdown_requested) {
            break;
        }

        loop_counter++;
        time_t now = time(NULL);

        for (size_t i = 0; i < ctx->dns_server_count; i++) {
            dns_server_stats_t *s = &ctx->dns_servers[i];

            if (s->disabled && (now - s->disabled_time >= 10)) {
                s->disabled = false;
                s->servfails = 0;
                if (!global_quiet_mode) {
                    sd_info("DNS server %s re-enabled after cooldown", s->server);
                }
            }
        }

        if (loop_counter >= 6 && !global_quiet_mode) {
            loop_counter = 0;
            fprintf(stderr, "\n========== DNS Server Statistics ==========\n");
            for (size_t i = 0; i < ctx->dns_server_count; i++) {
                dns_server_stats_t *s = &ctx->dns_servers[i];
                time_t elapsed = time(NULL) - s->last_reset;
                if (elapsed == 0) elapsed = 1;

                size_t queries = s->queries;
                size_t successes = s->successes;
                size_t servfails = s->servfails;
                size_t total_time = s->total_time_ms;
                size_t active = s->active_threads;
                bool disabled = s->disabled;

                double qps = (double)queries / elapsed;
                double avg_ms = queries > 0 ? (double)total_time / queries : 0;
                double success_rate = queries > 0 ? (double)successes * 100 / queries : 0;

                const char *status = disabled ? " [DISABLED]" : "";
                fprintf(stderr, "[%s] %.1f q/s | %.0f ms avg | %.1f%% success | %zu servfail | %zu threads | %zu queries%s\n",
                       s->server, qps, avg_ms, success_rate, servfails, active, queries, status);
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
