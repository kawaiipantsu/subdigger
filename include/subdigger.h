#ifndef SUBDIGGER_H
#define SUBDIGGER_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define MAX_DOMAIN_LEN 256
#define MAX_IP_LEN 46
#define MAX_THREADS 200
#define MAX_WORDLIST_LINES 10000000
#define DEFAULT_THREADS 50
#define DEFAULT_TIMEOUT 5
#define DEFAULT_BRUTEFORCE_DEPTH 2

typedef enum {
    SD_OK = 0,
    SD_ERROR_INVALID_DOMAIN,
    SD_ERROR_INVALID_CONFIG,
    SD_ERROR_DNS_INIT,
    SD_ERROR_THREAD_CREATE,
    SD_ERROR_FILE_IO,
    SD_ERROR_MEMORY,
    SD_ERROR_API
} sd_error_code_t;

typedef struct {
    char subdomain[MAX_DOMAIN_LEN];
    char a_record[MAX_IP_LEN];
    char cname_record[MAX_DOMAIN_LEN];
    char ns_record[MAX_DOMAIN_LEN];
    char mx_record[MAX_DOMAIN_LEN];
    bool has_txt;
    char tld[64];
    char country_code[3];
    char source[32];
    time_t timestamp;
} subdomain_result_t;

typedef struct {
    int threads;
    int timeout;
    char **dns_servers;
    int dns_server_count;
    char *wordlist_path;
    int bruteforce_depth;
    char **methods;
    int method_count;
    bool cache_enabled;
    char *output_format;
    char *api_key_shodan;
    char *api_key_virustotal;
    char *target_domain;
    char *output_file;
} config_t;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    char **tasks;
    size_t head;
    size_t tail;
    size_t capacity;
    size_t count;
    bool shutdown;
} task_queue_t;

typedef struct {
    pthread_mutex_t mutex;
    subdomain_result_t *results;
    size_t count;
    size_t capacity;
} result_buffer_t;

typedef struct {
    config_t *config;
    task_queue_t *task_queue;
    result_buffer_t *result_buffer;
    pthread_t *threads;
    void *dns_channel;
    void *geoip_db;
} subdigger_ctx_t;

void config_init(config_t *config);
void config_free(config_t *config);
int config_load(config_t *config, const char *path);

bool validate_domain(const char *domain);
void sanitize_domain(char *domain);
void extract_tld(const char *domain, char *tld, size_t tld_size);
void safe_strncpy(char *dest, const char *src, size_t size);
char *trim(char *str);

void sd_error(const char *fmt, ...);
void sd_warn(const char *fmt, ...);
void sd_info(const char *fmt, ...);

int check_config_permissions(const char *path);
bool validate_file_path(const char *path);

task_queue_t *task_queue_init(size_t capacity);
void task_queue_destroy(task_queue_t *queue);
bool task_queue_push(task_queue_t *queue, const char *task);
char *task_queue_pop(task_queue_t *queue);
void task_queue_shutdown(task_queue_t *queue);

result_buffer_t *result_buffer_init(size_t capacity);
void result_buffer_destroy(result_buffer_t *buffer);
bool result_buffer_add(result_buffer_t *buffer, const subdomain_result_t *result);

int thread_pool_create(subdigger_ctx_t *ctx);
void thread_pool_destroy(subdigger_ctx_t *ctx);

int dns_init(subdigger_ctx_t *ctx);
void dns_cleanup(subdigger_ctx_t *ctx);
bool dns_resolve_full(subdigger_ctx_t *ctx, const char *subdomain, subdomain_result_t *result);

int geoip_init(subdigger_ctx_t *ctx);
void geoip_cleanup(subdigger_ctx_t *ctx);
void geoip_lookup(subdigger_ctx_t *ctx, const char *ip, char *country_code);

char **wordlist_load(const char *path, size_t *count);
void wordlist_free(char **wordlist, size_t count);

int bruteforce_generate(subdigger_ctx_t *ctx);

char **cert_query_crtsh(const char *domain, size_t *count);
void cert_free_results(char **results, size_t count);

char **api_shodan_query(const char *domain, const char *api_key, size_t *count);
char **api_virustotal_query(const char *domain, const char *api_key, size_t *count);
void api_free_results(char **results, size_t count);

int dns_axfr_attempt(const char *domain, char ***results, size_t *count);

void output_csv_header(FILE *fp);
void output_csv_record(FILE *fp, const subdomain_result_t *result);
void output_json_start(FILE *fp);
void output_json_record(FILE *fp, const subdomain_result_t *result, bool is_last);
void output_json_end(FILE *fp);

int cache_load(const char *domain, result_buffer_t *buffer);
int cache_save(const char *domain, const result_buffer_t *buffer);

int discover_subdomains(subdigger_ctx_t *ctx);

#endif
