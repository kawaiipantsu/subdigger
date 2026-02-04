#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/subdigger.h"

task_queue_t *task_queue_init(size_t capacity) {
    task_queue_t *queue = malloc(sizeof(task_queue_t));
    if (!queue) {
        return NULL;
    }

    queue->tasks = malloc(capacity * sizeof(char *));
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

    pthread_mutex_lock(&queue->mutex);
    for (size_t i = 0; i < queue->count; i++) {
        size_t idx = (queue->head + i) % queue->capacity;
        free(queue->tasks[idx]);
    }
    pthread_mutex_unlock(&queue->mutex);

    free(queue->tasks);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue);
}

bool task_queue_push(task_queue_t *queue, const char *task) {
    if (!queue || !task) {
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

    queue->tasks[queue->tail] = strdup(task);
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);

    return true;
}

char *task_queue_pop(task_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    pthread_mutex_lock(&queue->mutex);

    while (queue->count == 0 && !queue->shutdown) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    if (queue->count == 0 && queue->shutdown) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    char *task = queue->tasks[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return task;
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

static void *worker_thread(void *arg) {
    subdigger_ctx_t *ctx = (subdigger_ctx_t *)arg;

    while (1) {
        char *subdomain = task_queue_pop(ctx->task_queue);
        if (!subdomain) {
            break;
        }

        subdomain_result_t result;
        memset(&result, 0, sizeof(result));

        if (dns_resolve_full(ctx, subdomain, &result)) {
            result_buffer_add(ctx->result_buffer, &result);
        }

        free(subdomain);
    }

    return NULL;
}

int thread_pool_create(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config) {
        return -1;
    }

    int thread_count = ctx->config->threads;
    if (thread_count <= 0 || thread_count > MAX_THREADS) {
        thread_count = DEFAULT_THREADS;
    }

    ctx->threads = malloc(thread_count * sizeof(pthread_t));
    if (!ctx->threads) {
        sd_error("Failed to allocate thread pool");
        return -1;
    }

    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&ctx->threads[i], NULL, worker_thread, ctx) != 0) {
            sd_error("Failed to create worker thread %d", i);
            return -1;
        }
    }

    sd_info("Started %d worker threads", thread_count);
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
