#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/subdigger.h"

static void escape_csv_field(const char *field, char *escaped, size_t escaped_size) {
    if (!field || !escaped || escaped_size == 0) {
        return;
    }

    bool needs_quotes = (strchr(field, ',') != NULL || strchr(field, '"') != NULL || strchr(field, '\n') != NULL);

    if (!needs_quotes) {
        safe_strncpy(escaped, field, escaped_size);
        return;
    }

    size_t j = 0;
    escaped[j++] = '"';

    for (size_t i = 0; field[i] != '\0' && j < escaped_size - 3; i++) {
        if (field[i] == '"') {
            escaped[j++] = '"';
            escaped[j++] = '"';
        } else {
            escaped[j++] = field[i];
        }
    }

    escaped[j++] = '"';
    escaped[j] = '\0';
}

void output_csv_header(FILE *fp) {
    if (!fp) {
        return;
    }

    fprintf(fp, "Date,Subdomain,A/CNAME,NS,MX,TXT_Present,TLD,Country,Source\n");
}

void output_csv_record(FILE *fp, const subdomain_result_t *result) {
    if (!fp || !result) {
        return;
    }

    struct tm *tm_info = gmtime(&result->timestamp);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    char escaped_subdomain[MAX_DOMAIN_LEN * 2];
    char escaped_a[MAX_IP_LEN * 2];
    char escaped_ns[MAX_DOMAIN_LEN * 2];
    char escaped_mx[MAX_DOMAIN_LEN * 2];

    escape_csv_field(result->subdomain, escaped_subdomain, sizeof(escaped_subdomain));
    escape_csv_field(result->a_record, escaped_a, sizeof(escaped_a));
    escape_csv_field(result->ns_record, escaped_ns, sizeof(escaped_ns));
    escape_csv_field(result->mx_record, escaped_mx, sizeof(escaped_mx));

    fprintf(fp, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
            timestamp,
            escaped_subdomain,
            escaped_a,
            escaped_ns,
            escaped_mx,
            result->has_txt ? "Yes" : "No",
            result->tld,
            result->country_code,
            result->source);
}

void output_json_start(FILE *fp) {
    if (!fp) {
        return;
    }

    fprintf(fp, "{\n  \"subdomains\": [\n");
}

void output_json_record(FILE *fp, const subdomain_result_t *result, bool is_last) {
    if (!fp || !result) {
        return;
    }

    struct tm *tm_info = gmtime(&result->timestamp);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    fprintf(fp, "    {\n");
    fprintf(fp, "      \"timestamp\": \"%s\",\n", timestamp);
    fprintf(fp, "      \"subdomain\": \"%s\",\n", result->subdomain);
    fprintf(fp, "      \"a_record\": \"%s\",\n", result->a_record);
    fprintf(fp, "      \"cname_record\": \"%s\",\n", result->cname_record);
    fprintf(fp, "      \"ns_record\": \"%s\",\n", result->ns_record);
    fprintf(fp, "      \"mx_record\": \"%s\",\n", result->mx_record);
    fprintf(fp, "      \"has_txt\": %s,\n", result->has_txt ? "true" : "false");
    fprintf(fp, "      \"tld\": \"%s\",\n", result->tld);
    fprintf(fp, "      \"country_code\": \"%s\",\n", result->country_code);
    fprintf(fp, "      \"source\": \"%s\"\n", result->source);
    fprintf(fp, "    }%s\n", is_last ? "" : ",");
}

void output_json_end(FILE *fp) {
    if (!fp) {
        return;
    }

    fprintf(fp, "  ]\n}\n");
}
