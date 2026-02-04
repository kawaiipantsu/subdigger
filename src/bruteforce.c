#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/subdigger.h"

static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
static const int charset_len = 37;

int bruteforce_generate(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config || !ctx->config->target_domain) {
        return -1;
    }

    int depth = ctx->config->bruteforce_depth;
    if (depth <= 0) {
        depth = 1;
    }
    if (depth > MAX_BRUTEFORCE_DEPTH) {
        sd_warn("Bruteforce depth %d exceeds maximum, limiting to %d", depth, MAX_BRUTEFORCE_DEPTH);
        depth = MAX_BRUTEFORCE_DEPTH;
    }

    sd_info("Generating bruteforce candidates (depth=%d)", depth);

    for (int d = 1; d <= depth && !shutdown_requested; d++) {
        if (d == 1) {
            for (int i = 0; i < charset_len && !shutdown_requested; i++) {
                char prefix[2];
                prefix[0] = charset[i];
                prefix[1] = '\0';

                char subdomain[MAX_DOMAIN_LEN];
                snprintf(subdomain, sizeof(subdomain), "%s.%s", prefix, ctx->config->target_domain);
                task_queue_push(ctx->task_queue, subdomain, "bruteforce");
            }
        } else if (d == 2) {
            for (int i = 0; i < charset_len && !shutdown_requested; i++) {
                for (int j = 0; j < charset_len && !shutdown_requested; j++) {
                    char prefix[3];
                    snprintf(prefix, sizeof(prefix), "%c%c", charset[i], charset[j]);

                    char subdomain[MAX_DOMAIN_LEN];
                    snprintf(subdomain, sizeof(subdomain), "%s.%s", prefix, ctx->config->target_domain);
                    task_queue_push(ctx->task_queue, subdomain, "bruteforce");
                }
            }
        } else if (d == 3) {
            for (int i = 0; i < charset_len && !shutdown_requested; i++) {
                for (int j = 0; j < charset_len && !shutdown_requested; j++) {
                    for (int k = 0; k < charset_len && !shutdown_requested; k++) {
                        char prefix[4];
                        snprintf(prefix, sizeof(prefix), "%c%c%c", charset[i], charset[j], charset[k]);

                        char subdomain[MAX_DOMAIN_LEN];
                        snprintf(subdomain, sizeof(subdomain), "%s.%s", prefix, ctx->config->target_domain);
                        task_queue_push(ctx->task_queue, subdomain, "bruteforce");
                    }
                }
            }
        }
    }

    sd_info("Bruteforce generation completed");
    return 0;
}
