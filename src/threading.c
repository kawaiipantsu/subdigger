#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ares.h>
#include <arpa/nameser.h>
#include "../include/subdigger.h"

task_queue_t *task_queue_init(size_t capacity) {
    task_queue_t *queue = malloc(sizeof(task_queue_t));
    if (!queue) {
        return NULL;
    }

    queue->tasks = malloc(capacity * sizeof(task_item_t));
    if (!queue->tasks) {
        free(queue);
        return NULL;
    }

    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);

    queue->head = 0;
    queue->tail = 0;
    queue->capacity = capacity;
    queue->count = 0;
    queue->shutdown = false;

    return queue;
}

void task_queue_destroy(task_queue_t *queue) {
    if (!queue) {
        return;
    }

    free(queue->tasks);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue);
}

bool task_queue_push(task_queue_t *queue, const char *subdomain, const char *source) {
    if (!queue || !subdomain || !source) {
        return false;
    }

    pthread_mutex_lock(&queue->mutex);

    while (queue->count == queue->capacity && !queue->shutdown) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    if (queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return false;
    }

    safe_strncpy(queue->tasks[queue->tail].subdomain, subdomain, sizeof(queue->tasks[queue->tail].subdomain));
    safe_strncpy(queue->tasks[queue->tail].source, source, sizeof(queue->tasks[queue->tail].source));
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);

    return true;
}

bool task_queue_push_unique(task_queue_t *queue, discovered_buffer_t *tracker, const char *subdomain, const char *source) {
    if (!queue || !tracker || !subdomain || !source) {
        return false;
    }

    // Check if subdomain has already been queued
    if (!discovered_buffer_add(tracker, subdomain)) {
        return false; // Already exists or error
    }

    // If it's new, add to task queue
    return task_queue_push(queue, subdomain, source);
}

bool task_queue_pop(task_queue_t *queue, task_item_t *item) {
    if (!queue || !item) {
        return false;
    }

    pthread_mutex_lock(&queue->mutex);

    while (queue->count == 0 && !queue->shutdown) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    if (queue->count == 0 && queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return false;
    }

    memcpy(item, &queue->tasks[queue->head], sizeof(task_item_t));
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return true;
}

void task_queue_shutdown(task_queue_t *queue) {
    if (!queue) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    queue->shutdown = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

result_buffer_t *result_buffer_init(size_t capacity) {
    result_buffer_t *buffer = malloc(sizeof(result_buffer_t));
    if (!buffer) {
        return NULL;
    }

    buffer->results = malloc(capacity * sizeof(subdomain_result_t));
    if (!buffer->results) {
        free(buffer);
        return NULL;
    }

    pthread_mutex_init(&buffer->mutex, NULL);
    buffer->count = 0;
    buffer->capacity = capacity;

    return buffer;
}

void result_buffer_destroy(result_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    free(buffer->results);
    pthread_mutex_destroy(&buffer->mutex);
    free(buffer);
}

bool result_buffer_add(result_buffer_t *buffer, const subdomain_result_t *result) {
    if (!buffer || !result) {
        return false;
    }

    pthread_mutex_lock(&buffer->mutex);

    // Check for duplicate subdomain
    for (size_t i = 0; i < buffer->count; i++) {
        if (strcmp(buffer->results[i].subdomain, result->subdomain) == 0 &&
            strcmp(buffer->results[i].domain, result->domain) == 0) {
            pthread_mutex_unlock(&buffer->mutex);
            return false; // Already exists, return false to indicate duplicate
        }
    }

    if (buffer->count >= buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        subdomain_result_t *new_results = realloc(buffer->results, new_capacity * sizeof(subdomain_result_t));
        if (!new_results) {
            pthread_mutex_unlock(&buffer->mutex);
            return false;
        }
        buffer->results = new_results;
        buffer->capacity = new_capacity;
    }

    memcpy(&buffer->results[buffer->count], result, sizeof(subdomain_result_t));
    buffer->count++;

    pthread_mutex_unlock(&buffer->mutex);

    return true;
}

discovered_buffer_t *discovered_buffer_init(size_t capacity) {
    discovered_buffer_t *buffer = malloc(sizeof(discovered_buffer_t));
    if (!buffer) {
        return NULL;
    }

    buffer->subdomains = malloc(capacity * sizeof(char *));
    if (!buffer->subdomains) {
        free(buffer);
        return NULL;
    }

    pthread_mutex_init(&buffer->mutex, NULL);
    buffer->count = 0;
    buffer->capacity = capacity;

    return buffer;
}

void discovered_buffer_destroy(discovered_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    for (size_t i = 0; i < buffer->count; i++) {
        free(buffer->subdomains[i]);
    }
    free(buffer->subdomains);
    pthread_mutex_destroy(&buffer->mutex);
    free(buffer);
}

bool discovered_buffer_add(discovered_buffer_t *buffer, const char *subdomain) {
    if (!buffer || !subdomain) {
        return false;
    }

    pthread_mutex_lock(&buffer->mutex);

    // Check for duplicates
    for (size_t i = 0; i < buffer->count; i++) {
        if (strcmp(buffer->subdomains[i], subdomain) == 0) {
            pthread_mutex_unlock(&buffer->mutex);
            return true;
        }
    }

    if (buffer->count >= buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        char **new_subdomains = realloc(buffer->subdomains, new_capacity * sizeof(char *));
        if (!new_subdomains) {
            pthread_mutex_unlock(&buffer->mutex);
            return false;
        }
        buffer->subdomains = new_subdomains;
        buffer->capacity = new_capacity;
    }

    buffer->subdomains[buffer->count] = strdup(subdomain);
    if (!buffer->subdomains[buffer->count]) {
        pthread_mutex_unlock(&buffer->mutex);
        return false;
    }
    buffer->count++;

    pthread_mutex_unlock(&buffer->mutex);

    return true;
}

void discovered_buffer_clear(discovered_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    pthread_mutex_lock(&buffer->mutex);

    for (size_t i = 0; i < buffer->count; i++) {
        free(buffer->subdomains[i]);
    }
    buffer->count = 0;

    pthread_mutex_unlock(&buffer->mutex);
}

typedef struct {
    subdigger_ctx_t *ctx;
    size_t server_idx;
} worker_thread_args_t;

static void extract_discovered_subdomains(subdigger_ctx_t *ctx, const subdomain_result_t *result) {
    if (!ctx || !result || !ctx->discovered_buffer || !ctx->config || !ctx->config->target_domain) {
        return;
    }

    const char *target_domain = ctx->config->target_domain;
    size_t target_len = strlen(target_domain);

    // Extract subdomains from CNAME chain (separated by " > ")
    if (strlen(result->cname_record) > 0) {
        char cname_copy[MAX_DOMAIN_LEN * 3];
        safe_strncpy(cname_copy, result->cname_record, sizeof(cname_copy));

        // Split by " > " separator
        char *saveptr = NULL;
        char *token = strtok_r(cname_copy, ">", &saveptr);
        while (token != NULL) {
            // Trim whitespace
            while (*token == ' ' || *token == '\t') {
                token++;
            }

            size_t len = strlen(token);
            while (len > 0 && (token[len-1] == ' ' || token[len-1] == '\t' || token[len-1] == '.')) {
                token[len-1] = '\0';
                len--;
            }

            if (len > 0) {
                // Check if it ends with target domain
                if (len >= target_len) {
                    // Check if it's exactly the target domain
                    if (strcmp(token, target_domain) == 0) {
                        // Skip - this is the root domain itself
                        token = strtok_r(NULL, ">", &saveptr);
                        continue;
                    }

                    // Check if it ends with .target_domain
                    if (len > target_len + 1) {
                        const char *suffix = token + (len - target_len);
                        const char *dot = token + (len - target_len - 1);
                        if (*dot == '.' && strcmp(suffix, target_domain) == 0) {
                            discovered_buffer_add(ctx->discovered_buffer, token);
                        }
                    }
                }
            }

            token = strtok_r(NULL, ">", &saveptr);
        }
    }

    // Extract subdomain from NS record
    if (strlen(result->ns_record) > 0) {
        char ns_copy[MAX_DOMAIN_LEN];
        safe_strncpy(ns_copy, result->ns_record, sizeof(ns_copy));

        size_t len = strlen(ns_copy);
        // Remove trailing dot if present
        if (len > 0 && ns_copy[len-1] == '.') {
            ns_copy[len-1] = '\0';
            len--;
        }

        if (len > 0 && len >= target_len) {
            // Check if it's exactly the target domain
            if (strcmp(ns_copy, target_domain) == 0) {
                // Skip - this is the root domain itself
            } else if (len > target_len + 1) {
                // Check if it ends with .target_domain
                const char *suffix = ns_copy + (len - target_len);
                const char *dot = ns_copy + (len - target_len - 1);
                if (*dot == '.' && strcmp(suffix, target_domain) == 0) {
                    discovered_buffer_add(ctx->discovered_buffer, ns_copy);
                }
            }
        }
    }

    // Extract subdomain from ReverseDNS record
    if (strlen(result->reverse_dns) > 0) {
        char rdns_copy[MAX_DOMAIN_LEN];
        safe_strncpy(rdns_copy, result->reverse_dns, sizeof(rdns_copy));

        size_t len = strlen(rdns_copy);
        // Remove trailing dot if present
        if (len > 0 && rdns_copy[len-1] == '.') {
            rdns_copy[len-1] = '\0';
            len--;
        }

        if (len > 0 && len >= target_len) {
            // Check if it's exactly the target domain
            if (strcmp(rdns_copy, target_domain) == 0) {
                // Skip - this is the root domain itself
            } else if (len > target_len + 1) {
                // Check if it ends with .target_domain
                const char *suffix = rdns_copy + (len - target_len);
                const char *dot = rdns_copy + (len - target_len - 1);
                if (*dot == '.' && strcmp(suffix, target_domain) == 0) {
                    discovered_buffer_add(ctx->discovered_buffer, rdns_copy);
                }
            }
        }
    }
}

static void *worker_thread(void *arg) {
    worker_thread_args_t *args = (worker_thread_args_t *)arg;
    subdigger_ctx_t *ctx = args->ctx;
    size_t server_idx = args->server_idx;
    free(args);

    thread_dns_context_t dns_ctx;
    dns_ctx.server_idx = server_idx;

    ares_channel channel;
    struct ares_options options;
    memset(&options, 0, sizeof(options));

    options.flags = ARES_FLAG_NOSEARCH | ARES_FLAG_NOALIASES;
    options.timeout = ctx->config->timeout * 1000;
    options.tries = 2;
    options.ndomains = 0;
    options.domains = NULL;

    int optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_DOMAINS;

    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
        sd_error("Worker thread failed to initialize DNS channel");
        return NULL;
    }

    if (server_idx < ctx->dns_server_count) {
        ares_set_servers_csv(channel, ctx->dns_servers[server_idx].server);
        __sync_add_and_fetch(&ctx->dns_servers[server_idx].active_threads, 1);
    }

    dns_ctx.channel = channel;

    while (!shutdown_requested) {
        if (server_idx < ctx->dns_server_count && ctx->dns_servers[server_idx].disabled) {
            usleep(100000);
            continue;
        }

        task_item_t item;
        if (!task_queue_pop(ctx->task_queue, &item)) {
            break;
        }

        subdomain_result_t result;
        memset(&result, 0, sizeof(result));

        if (ctx->config && ctx->config->target_domain) {
            safe_strncpy(result.domain, ctx->config->target_domain, sizeof(result.domain));
        }

        bool resolved = dns_resolve_full(ctx, item.subdomain, &result, &dns_ctx);

        bool include_non_resolving = (strstr(item.source, "crtsh") != NULL ||
                                     strstr(item.source, "shodan") != NULL ||
                                     strstr(item.source, "virustotal") != NULL ||
                                     strstr(item.source, "dns-axfr") != NULL ||
                                     strstr(item.source, "recursive-dns") != NULL ||
                                     strstr(item.source, "rdns") != NULL);

        if (resolved || include_non_resolving) {
            safe_strncpy(result.source, item.source, sizeof(result.source));

            // Always extract discovered subdomains from CNAME/NS/ReverseDNS (even for duplicates)
            if (resolved) {
                extract_discovered_subdomains(ctx, &result);
            }

            // Only output and increment counter if this is a NEW result (not a duplicate)
            bool is_new = result_buffer_add(ctx->result_buffer, &result);

            if (is_new) {
                __sync_add_and_fetch(&ctx->results_found, 1);

                if (ctx->output_fp) {
                    pthread_mutex_lock(&ctx->output_mutex);
                    if (strcmp(ctx->config->output_format, "json") == 0) {
                        output_json_record(ctx->output_fp, &result, true);
                        fprintf(ctx->output_fp, "\n");
                    } else {
                        output_csv_record(ctx->output_fp, &result);
                    }
                    fflush(ctx->output_fp);
                    pthread_mutex_unlock(&ctx->output_mutex);
                }
            }
        }

        __sync_add_and_fetch(&ctx->candidates_processed, 1);
    }

    if (server_idx < ctx->dns_server_count) {
        __sync_sub_and_fetch(&ctx->dns_servers[server_idx].active_threads, 1);
    }

    ares_destroy(channel);

    return NULL;
}

int thread_pool_create(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config) {
        return -1;
    }

    int total_threads;
    if (ctx->config->threads > 0) {
        total_threads = ctx->config->threads;
    } else {
        total_threads = ctx->dns_server_count * DEFAULT_THREADS_PER_DNS_SERVER;
    }

    int max_total_threads = ctx->dns_server_count * MAX_THREADS_PER_DNS_SERVER;
    if (total_threads > max_total_threads) {
        total_threads = max_total_threads;
    }

    ctx->threads = malloc(total_threads * sizeof(pthread_t));
    if (!ctx->threads) {
        sd_error("Failed to allocate thread pool");
        return -1;
    }

    ctx->config->threads = total_threads;

    int threads_per_server = total_threads / ctx->dns_server_count;
    int remaining = total_threads % ctx->dns_server_count;
    int thread_idx = 0;

    for (size_t server_idx = 0; server_idx < ctx->dns_server_count; server_idx++) {
        int threads_for_this_server = threads_per_server;
        if (remaining > 0) {
            threads_for_this_server++;
            remaining--;
        }

        for (int i = 0; i < threads_for_this_server; i++) {
            worker_thread_args_t *args = malloc(sizeof(worker_thread_args_t));
            if (!args) {
                sd_error("Failed to allocate worker thread args");
                return -1;
            }
            args->ctx = ctx;
            args->server_idx = server_idx;

            if (pthread_create(&ctx->threads[thread_idx], NULL, worker_thread, args) != 0) {
                sd_error("Failed to create worker thread %d", thread_idx);
                free(args);
                return -1;
            }
            thread_idx++;
        }
    }

    sd_info("Started %d worker threads (%d per DNS server)", total_threads, threads_per_server);
    return 0;
}

void thread_pool_destroy(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->threads || !ctx->config) {
        return;
    }

    task_queue_shutdown(ctx->task_queue);

    int timeout_per_thread = 3;  // 3 seconds per thread
    int completed = 0;
    int abandoned = 0;
    int respawned = 0;

    for (int i = 0; i < ctx->config->threads; i++) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_per_thread;  // Give each thread 3 seconds

        int ret = pthread_timedjoin_np(ctx->threads[i], NULL, &ts);
        if (ret == ETIMEDOUT) {
            pthread_detach(ctx->threads[i]);
            abandoned++;
        } else if (ret == 0) {
            completed++;
        }
    }

    if (abandoned > 0) {
        size_t queue_remaining = 0;
        pthread_mutex_lock(&ctx->task_queue->mutex);
        queue_remaining = ctx->task_queue->count;
        pthread_mutex_unlock(&ctx->task_queue->mutex);

        if (queue_remaining > 0) {
            sd_warn("Abandoned %d stuck threads with %zu queries remaining, respawning workers", abandoned, queue_remaining);

            size_t respawn_count = (size_t)abandoned < queue_remaining ? (size_t)abandoned : queue_remaining;
            if (respawn_count > 50) respawn_count = 50;

            pthread_t *respawn_threads = malloc(respawn_count * sizeof(pthread_t));
            if (respawn_threads) {
                size_t threads_per_server = respawn_count / ctx->dns_server_count;
                size_t remaining_threads = respawn_count % ctx->dns_server_count;
                size_t thread_idx = 0;

                for (size_t server_idx = 0; server_idx < ctx->dns_server_count && thread_idx < respawn_count; server_idx++) {
                    size_t threads_for_this_server = threads_per_server;
                    if (remaining_threads > 0) {
                        threads_for_this_server++;
                        remaining_threads--;
                    }

                    for (size_t i = 0; i < threads_for_this_server && thread_idx < respawn_count; i++) {
                        worker_thread_args_t *args = malloc(sizeof(worker_thread_args_t));
                        if (args) {
                            args->ctx = ctx;
                            args->server_idx = server_idx;

                            if (pthread_create(&respawn_threads[thread_idx], NULL, worker_thread, args) == 0) {
                                thread_idx++;
                            } else {
                                free(args);
                            }
                        }
                    }
                }

                respawned = thread_idx;

                size_t respawn_completed = 0;

                for (size_t i = 0; i < (size_t)respawned; i++) {
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    ts.tv_sec += timeout_per_thread;  // Give each respawned thread 3 seconds

                    int ret = pthread_timedjoin_np(respawn_threads[i], NULL, &ts);
                    if (ret == 0) {
                        respawn_completed++;
                    } else {
                        pthread_detach(respawn_threads[i]);
                    }
                }

                free(respawn_threads);
                sd_info("Respawned %d threads, %zu completed successfully", respawned, respawn_completed);
            }
        } else {
            sd_warn("Abandoned %d stuck threads (no remaining queries to process)", abandoned);
        }
    }

    free(ctx->threads);
    ctx->threads = NULL;

    sd_info("%d worker threads completed successfully", completed + respawned);
}
