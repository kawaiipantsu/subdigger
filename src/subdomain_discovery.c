#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/subdigger.h"

static bool method_enabled(config_t *config, const char *method) {
    if (!config || !config->methods || !method) {
        return false;
    }

    for (int i = 0; i < config->method_count; i++) {
        if (strcmp(config->methods[i], method) == 0) {
            return true;
        }
    }

    return false;
}

static int compare_results(const void *a, const void *b) {
    const subdomain_result_t *ra = (const subdomain_result_t *)a;
    const subdomain_result_t *rb = (const subdomain_result_t *)b;
    return strcmp(ra->subdomain, rb->subdomain);
}

static void deduplicate_results(result_buffer_t *buffer) {
    if (!buffer || buffer->count <= 1) {
        return;
    }

    qsort(buffer->results, buffer->count, sizeof(subdomain_result_t), compare_results);

    size_t write_idx = 0;
    for (size_t read_idx = 0; read_idx < buffer->count; read_idx++) {
        if (write_idx == 0 || strcmp(buffer->results[write_idx - 1].subdomain, buffer->results[read_idx].subdomain) != 0) {
            if (write_idx != read_idx) {
                memcpy(&buffer->results[write_idx], &buffer->results[read_idx], sizeof(subdomain_result_t));
            }
            write_idx++;
        }
    }

    buffer->count = write_idx;
}

int discover_subdomains(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config || !ctx->config->target_domain) {
        return -1;
    }

    config_t *config = ctx->config;
    const char *domain = config->target_domain;

    if (config->cache_enabled && !shutdown_requested) {
        sd_info("Checking cache for %s", domain);
        int cached = cache_load(domain, ctx->result_buffer);
        if (cached > 0) {
            sd_info("Using %d cached results", cached);
            return 0;
        }
    }

    if (shutdown_requested) {
        return -1;
    }

    start_progress_monitor(ctx);

    size_t total_candidates = 0;

    if (method_enabled(config, "cert") && !shutdown_requested) {
        sd_info("Querying certificate transparency logs");
        size_t cert_count = 0;
        char **cert_results = cert_query_crtsh(domain, &cert_count);

        if (cert_results) {
            for (size_t i = 0; i < cert_count && !shutdown_requested; i++) {
                task_queue_push(ctx->task_queue, cert_results[i], "crtsh");
                total_candidates++;
            }
            cert_free_results(cert_results, cert_count);
        }
    }

    if (method_enabled(config, "wordlist") && !shutdown_requested) {
        if (config->auto_wordlists) {
            sd_info("Auto-discovering wordlist files");
            wordlist_load_and_queue_auto(ctx, domain, &total_candidates);
        } else if (config->wordlist_path) {
            sd_info("Loading wordlist");
            char source[64];
            const char *filename = strrchr(config->wordlist_path, '/');
            filename = filename ? filename + 1 : config->wordlist_path;
            snprintf(source, sizeof(source), "wordlist:%s", filename);

            size_t wordlist_count = 0;
            char **wordlist = wordlist_load(config->wordlist_path, &wordlist_count);

            if (wordlist) {
                for (size_t i = 0; i < wordlist_count && !shutdown_requested; i++) {
                    char subdomain[MAX_DOMAIN_LEN];
                    snprintf(subdomain, sizeof(subdomain), "%s.%s", wordlist[i], domain);
                    task_queue_push(ctx->task_queue, subdomain, source);
                    total_candidates++;
                }
                wordlist_free(wordlist, wordlist_count);
            }
        }
    }

    if (method_enabled(config, "dns") && !shutdown_requested) {
        sd_info("Attempting DNS zone transfer");
        size_t axfr_count = 0;
        char **axfr_results = NULL;
        dns_axfr_attempt(domain, &axfr_results, &axfr_count);

        if (axfr_results) {
            for (size_t i = 0; i < axfr_count && !shutdown_requested; i++) {
                task_queue_push(ctx->task_queue, axfr_results[i], "dns-axfr");
                total_candidates++;
            }
            api_free_results(axfr_results, axfr_count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_shodan) && config->api_key_shodan && !shutdown_requested) {
        sd_info("Querying Shodan API");
        size_t shodan_count = 0;
        char **shodan_results = api_shodan_query(domain, config->api_key_shodan, &shodan_count);

        if (shodan_results) {
            for (size_t i = 0; i < shodan_count && !shutdown_requested; i++) {
                task_queue_push(ctx->task_queue, shodan_results[i], "shodan");
                total_candidates++;
            }
            api_free_results(shodan_results, shodan_count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_virustotal) && config->api_key_virustotal && !shutdown_requested) {
        sd_info("Querying VirusTotal API");
        size_t vt_count = 0;
        char **vt_results = api_virustotal_query(domain, config->api_key_virustotal, &vt_count);

        if (vt_results) {
            for (size_t i = 0; i < vt_count && !shutdown_requested; i++) {
                task_queue_push(ctx->task_queue, vt_results[i], "virustotal");
                total_candidates++;
            }
            api_free_results(vt_results, vt_count);
        }
    }

    if (config->enable_bruteforce && !shutdown_requested) {
        sd_info("Starting bruteforce enumeration");
        bruteforce_generate(ctx);
    }

    if (shutdown_requested) {
        sd_info("Shutdown requested during candidate generation");
        task_queue_shutdown(ctx->task_queue);
        thread_pool_destroy(ctx);
        stop_progress_monitor(ctx);
        return -1;
    }

    sd_info("Generated %zu subdomain candidates", total_candidates);

    start_dns_stats_monitor(ctx);

    task_queue_shutdown(ctx->task_queue);

    thread_pool_destroy(ctx);

    stop_dns_stats_monitor(ctx);
    stop_progress_monitor(ctx);

    sd_info("DNS resolution completed, found %zu subdomains", ctx->result_buffer->count);

    deduplicate_results(ctx->result_buffer);
    sd_info("After deduplication: %zu unique subdomains", ctx->result_buffer->count);

    if (config->cache_enabled) {
        cache_save(domain, ctx->result_buffer);
    }

    return 0;
}
