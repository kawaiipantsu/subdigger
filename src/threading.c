#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
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

typedef struct {
    subdigger_ctx_t *ctx;
    size_t server_idx;
} worker_thread_args_t;

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
        task_item_t item;
        if (!task_queue_pop(ctx->task_queue, &item)) {
            break;
        }

        subdomain_result_t result;
        memset(&result, 0, sizeof(result));

        bool resolved = dns_resolve_full(ctx, item.subdomain, &result, &dns_ctx);

        bool include_non_resolving = (strstr(item.source, "crtsh") != NULL ||
                                     strstr(item.source, "shodan") != NULL ||
                                     strstr(item.source, "virustotal") != NULL ||
                                     strstr(item.source, "dns-axfr") != NULL);

        if (resolved || include_non_resolving) {
            safe_strncpy(result.source, item.source, sizeof(result.source));
            result_buffer_add(ctx->result_buffer, &result);
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

    for (int i = 0; i < ctx->config->threads; i++) {
        pthread_join(ctx->threads[i], NULL);
    }

    free(ctx->threads);
    ctx->threads = NULL;

    sd_info("All worker threads completed");
}
