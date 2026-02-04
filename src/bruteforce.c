#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/subdigger.h"

static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
static const int charset_len = 36;

int bruteforce_generate(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->config || !ctx->config->target_domain) {
        return -1;
    }

    int depth = ctx->config->bruteforce_depth;
    if (depth <= 0) {
        depth = 1;
    }
    if (depth > 3) {
        sd_warn("Bruteforce depth %d is very high, limiting to 3", depth);
        depth = 3;
    }

    sd_info("Generating bruteforce candidates (depth=%d)", depth);

    for (int i = 0; i < charset_len; i++) {
        char prefix[2];
        prefix[0] = charset[i];
        prefix[1] = '\0';

        char subdomain[MAX_DOMAIN_LEN];
        snprintf(subdomain, sizeof(subdomain), "%s.%s", prefix, ctx->config->target_domain);
        task_queue_push(ctx->task_queue, subdomain);

        if (depth > 1) {
            for (int j = 0; j < charset_len; j++) {
                char prefix2[3];
                snprintf(prefix2, sizeof(prefix2), "%c%c", charset[i], charset[j]);

                snprintf(subdomain, sizeof(subdomain), "%s.%s", prefix2, ctx->config->target_domain);
                task_queue_push(ctx->task_queue, subdomain);
            }
        }
    }

    sd_info("Bruteforce generation completed");
    return 0;
}
