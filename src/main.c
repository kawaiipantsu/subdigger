#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include "../include/subdigger.h"

#define VERSION "1.2.6"

static subdigger_ctx_t *global_ctx = NULL;

static void print_version(void) {
    printf("SubDigger v%s\n", VERSION);
    printf("High-performance subdomain discovery tool\n");
}

static void print_help(const char *program_name) {
    printf("Usage: %s -d <domain> [options]\n\n", program_name);
    printf("Required:\n");
    printf("  -d, --domain <domain>     Target domain to scan\n\n");
    printf("Optional:\n");
    printf("  -t, --threads <num>       Number of worker threads (default: 20/server, max: 200/server)\n");
    printf("  -w, --wordlist <file>     Path to wordlist file (disables auto-discovery)\n");
    printf("  -o, --output <file>       Output file (default: stdout)\n");
    printf("  -f, --format <csv|json>   Output format (default: csv)\n");
    printf("  -m, --methods <list>      Comma-separated discovery methods\n");
    printf("                            Available: wordlist,cert,bruteforce,dns,api\n");
    printf("  -q, --quiet               Quiet mode: only output data (no logs)\n");
    printf("  --no-progress             Disable progress reporting\n");
    printf("  --no-auto-wordlists       Disable automatic wordlist discovery (default: enabled)\n");
    printf("  --bruteforce              Enable bruteforce subdomain generation\n");
    printf("  --bruteforce-depth <n>    Bruteforce depth 1-5 (default: 3, includes a-z0-9_)\n");
    printf("  --no-cache                Disable caching\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -v, --version             Show version information\n\n");
    printf("Examples:\n");
    printf("  %s -d example.com\n", program_name);
    printf("  %s -d example.com -f json -o results.json\n", program_name);
    printf("  %s -d example.com --bruteforce --bruteforce-depth 4\n", program_name);
    printf("  %s -d example.com -q | grep -i admin\n", program_name);
    printf("  %s -d example.com -w custom.txt\n\n", program_name);
    printf("Configuration:\n");
    printf("  Config file: ~/.subdigger/config\n");
    printf("  Wordlists:   ~/.subdigger/wordlists/\n");
    printf("  Cache:       ~/.subdigger/cache/\n\n");
    printf("Environment Variables:\n");
    printf("  SHODAN_API_KEY         Shodan API key\n");
    printf("  VIRUSTOTAL_API_KEY     VirusTotal API key\n\n");
}

static void signal_handler(int signum) {
    (void)signum;
    if (!global_quiet_mode) {
        fprintf(stderr, "\n[SIGNAL] Interrupted, exiting immediately...\n");
    }
    _exit(130);
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void ensure_directories(void) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        return;
    }

    char path[1024];

    snprintf(path, sizeof(path), "%s/.subdigger", pw->pw_dir);
    mkdir(path, 0700);

    snprintf(path, sizeof(path), "%s/.subdigger/cache", pw->pw_dir);
    mkdir(path, 0700);

    snprintf(path, sizeof(path), "%s/.subdigger/wordlists", pw->pw_dir);
    mkdir(path, 0700);

    snprintf(path, sizeof(path), "%s/.subdigger/config", pw->pw_dir);
    if (access(path, F_OK) != 0) {
        FILE *fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "[general]\n");
            fprintf(fp, "# threads = 140  # Auto: 20 per DNS server (default)\n");
            fprintf(fp, "timeout = 2\n\n");
            fprintf(fp, "[dns]\n");
            fprintf(fp, "servers = 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,208.67.222.222,208.67.220.220,9.9.9.9\n\n");
            fprintf(fp, "[discovery]\n");
            fprintf(fp, "methods = wordlist,cert\n");
            fprintf(fp, "wordlist_path = ~/.subdigger/wordlists/common-subdomains.txt\n");
            fprintf(fp, "auto_wordlists = true\n");
            fprintf(fp, "bruteforce_depth = 3\n\n");
            fprintf(fp, "[output]\n");
            fprintf(fp, "format = csv\n\n");
            fprintf(fp, "[cache]\n");
            fprintf(fp, "enabled = true\n\n");
            fprintf(fp, "[apis]\n");
            fprintf(fp, "shodan_key = \n");
            fprintf(fp, "virustotal_key = \n");
            fclose(fp);
            chmod(path, 0600);
        }
    }
}

int main(int argc, char *argv[]) {
    config_t config;
    config_init(&config);

    ensure_directories();
    setup_signal_handlers();

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char config_path[1024];
        snprintf(config_path, sizeof(config_path), "%s/.subdigger/config", pw->pw_dir);
        config_load(&config, config_path);
    }

    static struct option long_options[] = {
        {"domain",            required_argument, 0, 'd'},
        {"threads",           required_argument, 0, 't'},
        {"wordlist",          required_argument, 0, 'w'},
        {"output",            required_argument, 0, 'o'},
        {"format",            required_argument, 0, 'f'},
        {"methods",           required_argument, 0, 'm'},
        {"quiet",             no_argument,       0, 'q'},
        {"no-progress",       no_argument,       0, 'P'},
        {"no-auto-wordlists", no_argument,       0, 'N'},
        {"bruteforce",        no_argument,       0, 'B'},
        {"bruteforce-depth",  required_argument, 0, 'D'},
        {"no-cache",          no_argument,       0, 'n'},
        {"help",              no_argument,       0, 'h'},
        {"version",           no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "d:t:w:o:f:m:qnhv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                config.target_domain = strdup(optarg);
                break;
            case 't':
                config.threads = atoi(optarg);
                if (config.threads <= 0 || config.threads > (MAX_DNS_SERVERS * MAX_THREADS_PER_DNS_SERVER)) {
                    sd_error("Invalid thread count: %s (max: %d per DNS server)", optarg, MAX_THREADS_PER_DNS_SERVER);
                    config_free(&config);
                    return 1;
                }
                break;
            case 'w':
                free(config.wordlist_path);
                config.wordlist_path = strdup(optarg);
                config.auto_wordlists = false;
                break;
            case 'o':
                config.output_file = strdup(optarg);
                break;
            case 'f':
                free(config.output_format);
                config.output_format = strdup(optarg);
                if (strcmp(config.output_format, "csv") != 0 && strcmp(config.output_format, "json") != 0) {
                    sd_error("Invalid format: %s (must be csv or json)", config.output_format);
                    config_free(&config);
                    return 1;
                }
                break;
            case 'm':
                if (config.methods) {
                    for (int i = 0; i < config.method_count; i++) {
                        free(config.methods[i]);
                    }
                    free(config.methods);
                }
                config.method_count = 0;
                config.methods = NULL;

                char *methods_copy = strdup(optarg);
                char *token = strtok(methods_copy, ",");
                while (token) {
                    token = trim(token);
                    config.methods = realloc(config.methods, (config.method_count + 1) * sizeof(char *));
                    config.methods[config.method_count] = strdup(token);
                    config.method_count++;
                    token = strtok(NULL, ",");
                }
                free(methods_copy);
                break;
            case 'q':
                config.quiet_mode = true;
                config.show_progress = false;
                global_quiet_mode = true;
                break;
            case 'P':
                config.show_progress = false;
                break;
            case 'N':
                config.auto_wordlists = false;
                break;
            case 'B':
                config.enable_bruteforce = true;
                break;
            case 'D':
                config.bruteforce_depth = atoi(optarg);
                if (config.bruteforce_depth < 1 || config.bruteforce_depth > MAX_BRUTEFORCE_DEPTH) {
                    sd_error("Invalid bruteforce depth: %s (must be 1-%d)", optarg, MAX_BRUTEFORCE_DEPTH);
                    config_free(&config);
                    return 1;
                }
                config.enable_bruteforce = true;
                break;
            case 'n':
                config.cache_enabled = false;
                break;
            case 'h':
                print_help(argv[0]);
                config_free(&config);
                return 0;
            case 'v':
                print_version();
                config_free(&config);
                return 0;
            default:
                print_help(argv[0]);
                config_free(&config);
                return 1;
        }
    }

    if (!config.target_domain) {
        sd_error("Domain is required (use -d or --domain)");
        print_help(argv[0]);
        config_free(&config);
        return 1;
    }

    if (!validate_domain(config.target_domain)) {
        sd_error("Invalid domain: %s", config.target_domain);
        config_free(&config);
        return 1;
    }

    sanitize_domain(config.target_domain);

    subdigger_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &config;
    ctx.candidates_processed = 0;
    ctx.results_found = 0;
    ctx.discovery_active = false;

    global_ctx = &ctx;

    pthread_mutex_init(&ctx.geoip_mutex, NULL);
    pthread_mutex_init(&ctx.output_mutex, NULL);

    ctx.output_fp = stdout;
    if (config.output_file) {
        ctx.output_fp = fopen(config.output_file, "w");
        if (!ctx.output_fp) {
            sd_error("Failed to open output file: %s", config.output_file);
            ctx.output_fp = stdout;
        }
    }

    ctx.output_header_written = false;

    if (strcmp(config.output_format, "csv") == 0) {
        output_csv_header(ctx.output_fp);
        ctx.output_header_written = true;
    }

    ctx.task_queue = task_queue_init(10000);
    if (!ctx.task_queue) {
        sd_error("Failed to initialize task queue");
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    ctx.result_buffer = result_buffer_init(1000);
    if (!ctx.result_buffer) {
        sd_error("Failed to initialize result buffer");
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    if (dns_init(&ctx) != 0) {
        sd_error("Failed to initialize DNS resolver");
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    geoip_init(&ctx);

    sd_info("Starting subdomain discovery for %s", config.target_domain);

    if (thread_pool_create(&ctx) != 0) {
        sd_error("Failed to create thread pool");
        dns_cleanup(&ctx);
        geoip_cleanup(&ctx);
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    sd_info("DNS timeout: %d seconds", config.timeout);

    if (discover_subdomains(&ctx) != 0) {
        sd_error("Subdomain discovery failed");
        dns_cleanup(&ctx);
        geoip_cleanup(&ctx);
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    if (ctx.output_fp && ctx.output_fp != stdout) {
        fclose(ctx.output_fp);
        sd_info("Results written to %s", config.output_file);
    }

    sd_info("Discovery completed: %zu subdomains found", ctx.result_buffer->count);

    dns_cleanup(&ctx);
    geoip_cleanup(&ctx);
    result_buffer_destroy(ctx.result_buffer);
    task_queue_destroy(ctx.task_queue);

    pthread_mutex_destroy(&ctx.output_mutex);
    pthread_mutex_destroy(&ctx.geoip_mutex);

    global_ctx = NULL;

    config_free(&config);

    return 0;
}
