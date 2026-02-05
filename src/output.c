#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/subdigger.h"

static bool is_unwanted_char(char c) {
    return (c == '"' || c == '`' || c == '\'' || c == ';' || c == '|');
}

static void sanitize_string(const char *field, char *sanitized, size_t sanitized_size) {
    if (!field || !sanitized || sanitized_size == 0) {
        return;
    }

    size_t j = 0;
    for (size_t i = 0; field[i] != '\0' && j < sanitized_size - 1; i++) {
        if (!is_unwanted_char(field[i])) {
            sanitized[j++] = field[i];
        }
    }
    sanitized[j] = '\0';
}

static void escape_csv_field(const char *field, char *escaped, size_t escaped_size) {
    if (!field || !escaped || escaped_size == 0) {
        return;
    }

    // First sanitize the input by stripping unwanted characters
    char sanitized[escaped_size];
    sanitize_string(field, sanitized, sizeof(sanitized));

    // Always quote all string fields for better CSV compatibility
    size_t j = 0;
    escaped[j++] = '"';

    for (size_t i = 0; sanitized[i] != '\0' && j < escaped_size - 2; i++) {
        escaped[j++] = sanitized[i];
    }

    escaped[j++] = '"';
    escaped[j] = '\0';
}

void output_csv_header(FILE *fp) {
    if (!fp) {
        return;
    }

    fprintf(fp, "Date,Domain,Subdomain,A,AAAA,ReverseDNS,CNAME,CNAME-IP,NS,MX,CAA,TXT,Dangling,TLD,TLD-ISO,TLD-Country,TLD-Type,TLD-Manager,IP-ISO,IP-Country,IP-City,ASN-Org,Source\n");
}

void output_csv_record(FILE *fp, const subdomain_result_t *result) {
    if (!fp || !result) {
        return;
    }

    struct tm *tm_info = gmtime(&result->timestamp);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    char escaped_timestamp[64];
    char escaped_domain[MAX_DOMAIN_LEN * 2];
    char escaped_subdomain[MAX_DOMAIN_LEN * 2];
    char escaped_a[MAX_IP_LEN * 2];
    char escaped_aaaa[MAX_IP_LEN * 2];
    char escaped_reverse_dns[MAX_DOMAIN_LEN * 2];
    char escaped_cname[MAX_DOMAIN_LEN * 6];
    char escaped_cname_ip[MAX_IP_LEN * 2];
    char escaped_ns[MAX_DOMAIN_LEN * 2];
    char escaped_mx[MAX_DOMAIN_LEN * 2];
    char escaped_tld[128];
    char escaped_tld_iso[16];
    char escaped_tld_country[128];
    char escaped_tld_type[64];
    char escaped_tld_manager[512];
    char escaped_ip_iso[16];
    char escaped_ip_country[128];
    char escaped_ip_city[256];
    char escaped_asn_org[512];
    char escaped_source[64];

    escape_csv_field(timestamp, escaped_timestamp, sizeof(escaped_timestamp));
    escape_csv_field(result->domain, escaped_domain, sizeof(escaped_domain));
    escape_csv_field(result->subdomain, escaped_subdomain, sizeof(escaped_subdomain));
    escape_csv_field(result->a_record, escaped_a, sizeof(escaped_a));
    escape_csv_field(result->aaaa_record, escaped_aaaa, sizeof(escaped_aaaa));
    escape_csv_field(result->reverse_dns, escaped_reverse_dns, sizeof(escaped_reverse_dns));
    escape_csv_field(result->cname_record, escaped_cname, sizeof(escaped_cname));
    escape_csv_field(result->cname_ip, escaped_cname_ip, sizeof(escaped_cname_ip));
    escape_csv_field(result->ns_record, escaped_ns, sizeof(escaped_ns));
    escape_csv_field(result->mx_record, escaped_mx, sizeof(escaped_mx));
    escape_csv_field(result->tld, escaped_tld, sizeof(escaped_tld));
    escape_csv_field(result->tld_iso, escaped_tld_iso, sizeof(escaped_tld_iso));
    escape_csv_field(result->tld_country, escaped_tld_country, sizeof(escaped_tld_country));
    escape_csv_field(result->tld_type, escaped_tld_type, sizeof(escaped_tld_type));
    escape_csv_field(result->tld_manager, escaped_tld_manager, sizeof(escaped_tld_manager));
    escape_csv_field(result->ip_iso, escaped_ip_iso, sizeof(escaped_ip_iso));
    escape_csv_field(result->ip_country, escaped_ip_country, sizeof(escaped_ip_country));
    escape_csv_field(result->ip_city, escaped_ip_city, sizeof(escaped_ip_city));
    escape_csv_field(result->asn_org, escaped_asn_org, sizeof(escaped_asn_org));
    escape_csv_field(result->source, escaped_source, sizeof(escaped_source));

    fprintf(fp, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
            escaped_timestamp,
            escaped_domain,
            escaped_subdomain,
            escaped_a,
            escaped_aaaa,
            escaped_reverse_dns,
            escaped_cname,
            escaped_cname_ip,
            escaped_ns,
            escaped_mx,
            result->has_caa ? "true" : "false",
            result->has_txt ? "true" : "false",
            result->dangling ? "true" : "false",
            escaped_tld,
            escaped_tld_iso,
            escaped_tld_country,
            escaped_tld_type,
            escaped_tld_manager,
            escaped_ip_iso,
            escaped_ip_country,
            escaped_ip_city,
            escaped_asn_org,
            escaped_source);
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

    char sanitized_timestamp[64];
    char sanitized_domain[MAX_DOMAIN_LEN];
    char sanitized_subdomain[MAX_DOMAIN_LEN];
    char sanitized_a[MAX_IP_LEN];
    char sanitized_aaaa[MAX_IP_LEN];
    char sanitized_reverse_dns[MAX_DOMAIN_LEN];
    char sanitized_cname[MAX_DOMAIN_LEN * 3];
    char sanitized_cname_ip[MAX_IP_LEN];
    char sanitized_ns[MAX_DOMAIN_LEN];
    char sanitized_mx[MAX_DOMAIN_LEN];
    char sanitized_tld[64];
    char sanitized_tld_iso[4];
    char sanitized_tld_country[64];
    char sanitized_tld_type[32];
    char sanitized_tld_manager[256];
    char sanitized_ip_iso[4];
    char sanitized_ip_country[64];
    char sanitized_ip_city[128];
    char sanitized_asn_org[256];
    char sanitized_source[32];

    sanitize_string(timestamp, sanitized_timestamp, sizeof(sanitized_timestamp));
    sanitize_string(result->domain, sanitized_domain, sizeof(sanitized_domain));
    sanitize_string(result->subdomain, sanitized_subdomain, sizeof(sanitized_subdomain));
    sanitize_string(result->a_record, sanitized_a, sizeof(sanitized_a));
    sanitize_string(result->aaaa_record, sanitized_aaaa, sizeof(sanitized_aaaa));
    sanitize_string(result->reverse_dns, sanitized_reverse_dns, sizeof(sanitized_reverse_dns));
    sanitize_string(result->cname_record, sanitized_cname, sizeof(sanitized_cname));
    sanitize_string(result->cname_ip, sanitized_cname_ip, sizeof(sanitized_cname_ip));
    sanitize_string(result->ns_record, sanitized_ns, sizeof(sanitized_ns));
    sanitize_string(result->mx_record, sanitized_mx, sizeof(sanitized_mx));
    sanitize_string(result->tld, sanitized_tld, sizeof(sanitized_tld));
    sanitize_string(result->tld_iso, sanitized_tld_iso, sizeof(sanitized_tld_iso));
    sanitize_string(result->tld_country, sanitized_tld_country, sizeof(sanitized_tld_country));
    sanitize_string(result->tld_type, sanitized_tld_type, sizeof(sanitized_tld_type));
    sanitize_string(result->tld_manager, sanitized_tld_manager, sizeof(sanitized_tld_manager));
    sanitize_string(result->ip_iso, sanitized_ip_iso, sizeof(sanitized_ip_iso));
    sanitize_string(result->ip_country, sanitized_ip_country, sizeof(sanitized_ip_country));
    sanitize_string(result->ip_city, sanitized_ip_city, sizeof(sanitized_ip_city));
    sanitize_string(result->asn_org, sanitized_asn_org, sizeof(sanitized_asn_org));
    sanitize_string(result->source, sanitized_source, sizeof(sanitized_source));

    fprintf(fp, "    {\n");
    fprintf(fp, "      \"timestamp\": \"%s\",\n", sanitized_timestamp);
    fprintf(fp, "      \"domain\": \"%s\",\n", sanitized_domain);
    fprintf(fp, "      \"subdomain\": \"%s\",\n", sanitized_subdomain);
    fprintf(fp, "      \"a_record\": \"%s\",\n", sanitized_a);
    fprintf(fp, "      \"aaaa_record\": \"%s\",\n", sanitized_aaaa);
    fprintf(fp, "      \"reverse_dns\": \"%s\",\n", sanitized_reverse_dns);
    fprintf(fp, "      \"cname_record\": \"%s\",\n", sanitized_cname);
    fprintf(fp, "      \"cname_ip\": \"%s\",\n", sanitized_cname_ip);
    fprintf(fp, "      \"ns_record\": \"%s\",\n", sanitized_ns);
    fprintf(fp, "      \"mx_record\": \"%s\",\n", sanitized_mx);
    fprintf(fp, "      \"caa\": %s,\n", result->has_caa ? "true" : "false");
    fprintf(fp, "      \"txt\": %s,\n", result->has_txt ? "true" : "false");
    fprintf(fp, "      \"dangling\": %s,\n", result->dangling ? "true" : "false");
    fprintf(fp, "      \"tld\": \"%s\",\n", sanitized_tld);
    fprintf(fp, "      \"tld_iso\": \"%s\",\n", sanitized_tld_iso);
    fprintf(fp, "      \"tld_country\": \"%s\",\n", sanitized_tld_country);
    fprintf(fp, "      \"tld_type\": \"%s\",\n", sanitized_tld_type);
    fprintf(fp, "      \"tld_manager\": \"%s\",\n", sanitized_tld_manager);
    fprintf(fp, "      \"ip_iso\": \"%s\",\n", sanitized_ip_iso);
    fprintf(fp, "      \"ip_country\": \"%s\",\n", sanitized_ip_country);
    fprintf(fp, "      \"ip_city\": \"%s\",\n", sanitized_ip_city);
    fprintf(fp, "      \"asn_org\": \"%s\",\n", sanitized_asn_org);
    fprintf(fp, "      \"source\": \"%s\"\n", sanitized_source);
    fprintf(fp, "    }%s\n", is_last ? "" : ",");
}

void output_json_end(FILE *fp) {
    if (!fp) {
        return;
    }

    fprintf(fp, "  ]\n}\n");
}
