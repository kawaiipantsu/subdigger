#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/subdigger.h"

static const char *normalize_method_name(const char *method) {
    if (!method) {
        return NULL;
    }

    // Support plural aliases
    if (strcmp(method, "wordlists") == 0) {
        return "wordlist";
    }
    if (strcmp(method, "certs") == 0 || strcmp(method, "certificate") == 0 || strcmp(method, "certificates") == 0) {
        return "cert";
    }
    if (strcmp(method, "apis") == 0) {
        return "api";
    }

    return method;
}

static bool method_enabled(config_t *config, const char *method) {
    if (!config || !config->methods || !method) {
        return false;
    }

    const char *normalized = normalize_method_name(method);
    if (!normalized) {
        return false;
    }

    for (int i = 0; i < config->method_count; i++) {
        const char *config_method = normalize_method_name(config->methods[i]);
        if (config_method && strcmp(config_method, normalized) == 0) {
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

    // Detect wildcard DNS records
    wildcard_detect(ctx, domain);

    if (shutdown_requested) {
        return -1;
    }

    start_progress_monitor(ctx);

    size_t total_candidates = 0;

    // Always check the root domain itself first
    if (!shutdown_requested) {
        if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, domain, "root-domain")) {
            total_candidates++;
        }
    }

    if (method_enabled(config, "cert") && !shutdown_requested) {
        sd_info("Querying certificate transparency logs");
        size_t cert_count = 0;
        char **cert_results = cert_query_crtsh(domain, &cert_count);

        if (cert_results) {
            for (size_t i = 0; i < cert_count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, cert_results[i], "crtsh")) {
                    total_candidates++;
                }
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

            // Extract filename and strip .txt extension for cleaner source display
            const char *filename = strrchr(config->wordlist_path, '/');
            filename = filename ? filename + 1 : config->wordlist_path;

            char clean_name[64];
            safe_strncpy(clean_name, filename, sizeof(clean_name));
            size_t len = strlen(clean_name);
            if (len > 4 && strcmp(clean_name + len - 4, ".txt") == 0) {
                clean_name[len - 4] = '\0';
            }

            char source[64];
            snprintf(source, sizeof(source), "wordlist:%s", clean_name);

            size_t wordlist_count = 0;
            char **wordlist = wordlist_load(config->wordlist_path, &wordlist_count);

            if (wordlist) {
                for (size_t i = 0; i < wordlist_count && !shutdown_requested; i++) {
                    char subdomain[MAX_DOMAIN_LEN];
                    snprintf(subdomain, sizeof(subdomain), "%s.%s", wordlist[i], domain);
                    if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, subdomain, source)) {
                        total_candidates++;
                    }
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
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, axfr_results[i], "dns-axfr")) {
                    total_candidates++;
                }
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
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, shodan_results[i], "shodan")) {
                    total_candidates++;
                }
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
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, vt_results[i], "virustotal")) {
                    total_candidates++;
                }
            }
            api_free_results(vt_results, vt_count);
        }
    }

    // Additional API integrations
    if ((method_enabled(config, "api") || config->api_key_bevigil) && config->api_key_bevigil && !shutdown_requested) {
        sd_info("Querying BeVigil API");
        size_t count = 0;
        char **results = api_bevigil_query(domain, config->api_key_bevigil, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "bevigil")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_binaryedge) && config->api_key_binaryedge && !shutdown_requested) {
        sd_info("Querying BinaryEdge API");
        size_t count = 0;
        char **results = api_binaryedge_query(domain, config->api_key_binaryedge, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "binaryedge")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    // BufferOver (free, no key required)
    if (method_enabled(config, "api") && !shutdown_requested) {
        sd_info("Querying BufferOver API (free)");
        size_t count = 0;
        char **results = api_bufferover_query(domain, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "bufferover")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_c99) && config->api_key_c99 && !shutdown_requested) {
        sd_info("Querying C99 API");
        size_t count = 0;
        char **results = api_c99_query(domain, config->api_key_c99, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "c99")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || (config->api_key_censys_id && config->api_key_censys_secret)) &&
        config->api_key_censys_id && config->api_key_censys_secret && !shutdown_requested) {
        sd_info("Querying Censys API");
        size_t count = 0;
        char **results = api_censys_query(domain, config->api_key_censys_id, config->api_key_censys_secret, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "censys")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_certspotter) && !shutdown_requested) {
        sd_info("Querying CertSpotter API");
        size_t count = 0;
        char **results = api_certspotter_query(domain, config->api_key_certspotter, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "certspotter")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_chaos) && config->api_key_chaos && !shutdown_requested) {
        sd_info("Querying Chaos API");
        size_t count = 0;
        char **results = api_chaos_query(domain, config->api_key_chaos, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "chaos")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_fullhunt) && config->api_key_fullhunt && !shutdown_requested) {
        sd_info("Querying FullHunt API");
        size_t count = 0;
        char **results = api_fullhunt_query(domain, config->api_key_fullhunt, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "fullhunt")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_github) && config->api_key_github && !shutdown_requested) {
        sd_info("Querying GitHub API");
        size_t count = 0;
        char **results = api_github_query(domain, config->api_key_github, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "github")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_hunter) && config->api_key_hunter && !shutdown_requested) {
        sd_info("Querying Hunter API");
        size_t count = 0;
        char **results = api_hunter_query(domain, config->api_key_hunter, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "hunter")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_intelx) && config->api_key_intelx && !shutdown_requested) {
        sd_info("Querying IntelX API");
        size_t count = 0;
        char **results = api_intelx_query(domain, config->api_key_intelx, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "intelx")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_leakix) && config->api_key_leakix && !shutdown_requested) {
        sd_info("Querying LeakIX API");
        size_t count = 0;
        char **results = api_leakix_query(domain, config->api_key_leakix, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "leakix")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_netlas) && config->api_key_netlas && !shutdown_requested) {
        sd_info("Querying Netlas API");
        size_t count = 0;
        char **results = api_netlas_query(domain, config->api_key_netlas, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "netlas")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || (config->api_key_passivetotal_user && config->api_key_passivetotal_key)) &&
        config->api_key_passivetotal_user && config->api_key_passivetotal_key && !shutdown_requested) {
        sd_info("Querying PassiveTotal API");
        size_t count = 0;
        char **results = api_passivetotal_query(domain, config->api_key_passivetotal_user, config->api_key_passivetotal_key, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "passivetotal")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_securitytrails) && config->api_key_securitytrails && !shutdown_requested) {
        sd_info("Querying SecurityTrails API");
        size_t count = 0;
        char **results = api_securitytrails_query(domain, config->api_key_securitytrails, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "securitytrails")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_whoisxmlapi) && config->api_key_whoisxmlapi && !shutdown_requested) {
        sd_info("Querying WhoisXMLAPI");
        size_t count = 0;
        char **results = api_whoisxmlapi_query(domain, config->api_key_whoisxmlapi, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "whoisxmlapi")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if ((method_enabled(config, "api") || config->api_key_zoomeye) && config->api_key_zoomeye && !shutdown_requested) {
        sd_info("Querying ZoomEye API");
        size_t count = 0;
        char **results = api_zoomeye_query(domain, config->api_key_zoomeye, &count);
        if (results) {
            for (size_t i = 0; i < count && !shutdown_requested; i++) {
                if (task_queue_push_unique(ctx->task_queue, ctx->discovered_buffer, results[i], "zoomeye")) {
                    total_candidates++;
                }
            }
            api_free_results(results, count);
        }
    }

    if (method_enabled(config, "bruteforce") && !shutdown_requested) {
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

    // Process candidates iteratively to handle discovered subdomains
    int iteration = 0;
    const int max_iterations = 5;  // Prevent infinite loops
    size_t previous_discovered_count = 0;

    while (iteration < max_iterations && !shutdown_requested) {
        iteration++;

        task_queue_shutdown(ctx->task_queue);
        thread_pool_destroy(ctx);

        // Check if new subdomains were discovered in this iteration
        size_t current_discovered_count = 0;
        pthread_mutex_lock(&ctx->discovered_buffer->mutex);
        current_discovered_count = ctx->discovered_buffer->count;
        pthread_mutex_unlock(&ctx->discovered_buffer->mutex);

        size_t new_discovered = current_discovered_count - previous_discovered_count;

        if (new_discovered == 0) {
            break;
        }

        sd_info("Iteration %d: discovered %zu new subdomains from CNAME/NS/ReverseDNS records", iteration, new_discovered);

        // Reset queue for next iteration
        ctx->task_queue->shutdown = false;
        ctx->task_queue->head = 0;
        ctx->task_queue->tail = 0;
        ctx->task_queue->count = 0;

        // Queue only the newly discovered subdomains
        pthread_mutex_lock(&ctx->discovered_buffer->mutex);
        for (size_t i = previous_discovered_count; i < current_discovered_count && !shutdown_requested; i++) {
            // Check if already processed
            bool already_processed = false;
            pthread_mutex_lock(&ctx->result_buffer->mutex);
            for (size_t j = 0; j < ctx->result_buffer->count; j++) {
                if (strcmp(ctx->result_buffer->results[j].subdomain, ctx->discovered_buffer->subdomains[i]) == 0) {
                    already_processed = true;
                    break;
                }
            }
            pthread_mutex_unlock(&ctx->result_buffer->mutex);

            if (!already_processed) {
                task_queue_push(ctx->task_queue, ctx->discovered_buffer->subdomains[i], "recursive-dns");
            }
        }
        pthread_mutex_unlock(&ctx->discovered_buffer->mutex);

        // Update the count for next iteration (don't clear the buffer)
        previous_discovered_count = current_discovered_count;

        // Restart thread pool
        if (thread_pool_create(ctx) != 0) {
            sd_error("Failed to create thread pool for iteration %d", iteration);
            break;
        }
    }

    stop_dns_stats_monitor(ctx);
    stop_progress_monitor(ctx);

    sd_info("DNS resolution completed, found %zu subdomains", ctx->result_buffer->count);

    // Shutdown task queue and destroy thread pool before cleanup
    task_queue_shutdown(ctx->task_queue);
    thread_pool_destroy(ctx);

    deduplicate_results(ctx->result_buffer);
    sd_info("After deduplication: %zu unique subdomains", ctx->result_buffer->count);

    if (config->cache_enabled) {
        cache_save(domain, ctx->result_buffer);
    }

    wildcard_cleanup(ctx);

    return 0;
}
