#ifndef SUBDIGGER_H
#define SUBDIGGER_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#define MAX_DOMAIN_LEN 256
#define MAX_IP_LEN 46
#define MAX_THREADS_PER_DNS_SERVER 200
#define MAX_WORDLIST_LINES 10000000
#define DEFAULT_THREADS_PER_DNS_SERVER 20
#define DEFAULT_TIMEOUT 2
#define DEFAULT_BRUTEFORCE_DEPTH 3
#define MAX_BRUTEFORCE_DEPTH 5
#define MAX_DNS_SERVERS 10

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
    char country_code[4];
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
    bool quiet_mode;
    bool show_progress;
    bool auto_wordlists;
    bool enable_bruteforce;
} config_t;

typedef struct {
    char subdomain[MAX_DOMAIN_LEN];
    char source[64];
} task_item_t;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    task_item_t *tasks;
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
    char server[64];
    volatile size_t queries;
    volatile size_t successes;
    volatile size_t failures;
    volatile size_t servfails;
    volatile size_t total_time_ms;
    volatile size_t active_threads;
    volatile bool disabled;
    time_t disabled_time;
    time_t last_reset;
} dns_server_stats_t;

typedef struct {
    void *channel;
    size_t server_idx;
} thread_dns_context_t;

typedef struct {
    config_t *config;
    task_queue_t *task_queue;
    result_buffer_t *result_buffer;
    pthread_t *threads;
    void *geoip_db;
    dns_server_stats_t *dns_servers;
    size_t dns_server_count;
    pthread_mutex_t geoip_mutex;
    pthread_mutex_t output_mutex;
    FILE *output_fp;
    volatile bool output_header_written;
    volatile size_t candidates_processed;
    volatile size_t results_found;
    volatile bool discovery_active;
    time_t start_time;
    pthread_t stats_thread;
    volatile bool stats_active;
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
void sd_progress(const char *fmt, ...);

extern bool global_quiet_mode;
extern volatile sig_atomic_t shutdown_requested;

int check_config_permissions(const char *path);
bool validate_file_path(const char *path);

task_queue_t *task_queue_init(size_t capacity);
void task_queue_destroy(task_queue_t *queue);
bool task_queue_push(task_queue_t *queue, const char *subdomain, const char *source);
bool task_queue_pop(task_queue_t *queue, task_item_t *item);
void task_queue_shutdown(task_queue_t *queue);

result_buffer_t *result_buffer_init(size_t capacity);
void result_buffer_destroy(result_buffer_t *buffer);
bool result_buffer_add(result_buffer_t *buffer, const subdomain_result_t *result);

int thread_pool_create(subdigger_ctx_t *ctx);
void thread_pool_destroy(subdigger_ctx_t *ctx);

int dns_init(subdigger_ctx_t *ctx);
void dns_cleanup(subdigger_ctx_t *ctx);
bool dns_resolve_full(subdigger_ctx_t *ctx, const char *subdomain, subdomain_result_t *result, thread_dns_context_t *dns_ctx);
void start_dns_stats_monitor(subdigger_ctx_t *ctx);
void stop_dns_stats_monitor(subdigger_ctx_t *ctx);

int geoip_init(subdigger_ctx_t *ctx);
void geoip_cleanup(subdigger_ctx_t *ctx);
void geoip_lookup(subdigger_ctx_t *ctx, const char *ip, char *country_code);

char **wordlist_load(const char *path, size_t *count);
void wordlist_free(char **wordlist, size_t count);
char **wordlist_discover_auto(size_t *count);
char **wordlist_load_multiple(char **paths, size_t path_count, size_t *total_count);
void wordlist_load_and_queue_auto(subdigger_ctx_t *ctx, const char *domain, size_t *total_candidates);

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

int start_progress_monitor(subdigger_ctx_t *ctx);
void stop_progress_monitor(subdigger_ctx_t *ctx);

#endif
