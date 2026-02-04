#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include "../include/subdigger.h"

int dns_axfr_attempt(const char *domain, char ***results, size_t *count) {
    if (!domain || !results || !count) {
        return -1;
    }

    *results = NULL;
    *count = 0;

    unsigned char answer[8192];
    int answer_len;

    res_init();

    answer_len = res_query(domain, ns_c_in, ns_t_ns, answer, sizeof(answer));
    if (answer_len < 0) {
        return 0;
    }

    ns_msg msg;
    if (ns_initparse(answer, answer_len, &msg) < 0) {
        return 0;
    }

    int ns_count = ns_msg_count(msg, ns_s_an);
    if (ns_count <= 0) {
        return 0;
    }

    for (int i = 0; i < ns_count; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) {
            continue;
        }

        if (ns_rr_type(rr) != ns_t_ns) {
            continue;
        }

        char ns_name[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), ns_rr_rdata(rr), ns_name, sizeof(ns_name)) < 0) {
            continue;
        }

        unsigned char axfr_answer[65536];
        int axfr_len = res_query(domain, ns_c_in, ns_t_axfr, axfr_answer, sizeof(axfr_answer));

        if (axfr_len > 0) {
            sd_info("Zone transfer successful from %s", ns_name);
            return 0;
        }
    }

    return 0;
}
