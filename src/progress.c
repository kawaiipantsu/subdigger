#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include "../include/subdigger.h"

static void *progress_thread(void *arg) {
    subdigger_ctx_t *ctx = (subdigger_ctx_t *)arg;
    size_t last_processed = 0;
    time_t last_time = ctx->start_time;

    while (ctx->discovery_active && !shutdown_requested) {
        for (int i = 0; i < 2 && ctx->discovery_active && !shutdown_requested; i++) {
            sleep(1);
        }

        if (!ctx->discovery_active || shutdown_requested) {
            break;
        }

        time_t now = time(NULL);
        time_t elapsed = now - ctx->start_time;

        size_t processed = ctx->candidates_processed;
        size_t found = ctx->results_found;
        size_t queue_size = 0;

        if (ctx->task_queue) {
            pthread_mutex_lock(&ctx->task_queue->mutex);
            queue_size = ctx->task_queue->count;
            pthread_mutex_unlock(&ctx->task_queue->mutex);
        }

        char eta_str[64] = "";
        if (elapsed > 0 && processed > 0 && queue_size > 0) {
            time_t delta_time = now - last_time;
            if (delta_time > 0) {
                size_t delta_processed = processed - last_processed;
                double rate = (double)delta_processed / delta_time;
                if (rate > 0) {
                    time_t eta_seconds = (time_t)(queue_size / rate);
                    if (eta_seconds < 60) {
                        snprintf(eta_str, sizeof(eta_str), " | ETA: %ld sec", eta_seconds);
                    } else if (eta_seconds < 3600) {
                        snprintf(eta_str, sizeof(eta_str), " | ETA: %ld min", eta_seconds / 60);
                    } else {
                        snprintf(eta_str, sizeof(eta_str), " | ETA: %ld hr", eta_seconds / 3600);
                    }
                }
            }
        }

        last_processed = processed;
        last_time = now;

        if (elapsed < 60) {
            sd_progress("Progress: %zu processed | %zu found | %zu queued | %ld sec%s",
                       processed, found, queue_size, elapsed, eta_str);
        } else if (elapsed < 3600) {
            sd_progress("Progress: %zu processed | %zu found | %zu queued | %ld min%s",
                       processed, found, queue_size, elapsed / 60, eta_str);
        } else {
            sd_progress("Progress: %zu processed | %zu found | %zu queued | %ld hr%s",
                       processed, found, queue_size, elapsed / 3600, eta_str);
        }
    }

    if (!global_quiet_mode) {
        fprintf(stderr, "\n");
    }

    return NULL;
}

int start_progress_monitor(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config || !ctx->config->show_progress || ctx->config->quiet_mode) {
        return 0;
    }

    ctx->discovery_active = true;
    ctx->start_time = time(NULL);

    pthread_t progress_tid;
    if (pthread_create(&progress_tid, NULL, progress_thread, ctx) != 0) {
        sd_warn("Failed to create progress thread");
        return -1;
    }

    pthread_detach(progress_tid);
    return 0;
}

void stop_progress_monitor(subdigger_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    ctx->discovery_active = false;
    sleep(1);
}
