#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "../include/subdigger.h"

#define VERSION "1.0.0"

static void print_version(void) {
    printf("SubDigger v%s\n", VERSION);
    printf("High-performance subdomain discovery tool\n");
}

static void print_help(const char *program_name) {
    printf("Usage: %s -d <domain> [options]\n\n", program_name);
    printf("Required:\n");
    printf("  -d, --domain <domain>     Target domain to scan\n\n");
    printf("Optional:\n");
    printf("  -t, --threads <num>       Number of worker threads (default: 50, max: 200)\n");
    printf("  -w, --wordlist <file>     Path to wordlist file\n");
    printf("  -o, --output <file>       Output file (default: stdout)\n");
    printf("  -f, --format <csv|json>   Output format (default: csv)\n");
    printf("  -m, --methods <list>      Comma-separated discovery methods\n");
    printf("                            Available: wordlist,cert,bruteforce,dns,api\n");
    printf("  --no-cache                Disable caching\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -v, --version             Show version information\n\n");
    printf("Examples:\n");
    printf("  %s -d example.com\n", program_name);
    printf("  %s -d example.com -f json -o results.json\n", program_name);
    printf("  %s -d example.com -m wordlist,cert -t 100\n", program_name);
    printf("  %s -d example.com -w /usr/share/wordlists/subdomains.txt\n\n", program_name);
    printf("Configuration:\n");
    printf("  Config file: ~/.subdigger/config\n");
    printf("  Wordlists:   ~/.subdigger/wordlists/\n");
    printf("  Cache:       ~/.subdigger/cache/\n\n");
    printf("Environment Variables:\n");
    printf("  SHODAN_API_KEY         Shodan API key\n");
    printf("  VIRUSTOTAL_API_KEY     VirusTotal API key\n\n");
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
            fprintf(fp, "threads = 50\n");
            fprintf(fp, "timeout = 5\n\n");
            fprintf(fp, "[dns]\n");
            fprintf(fp, "servers = 8.8.8.8,1.1.1.1\n\n");
            fprintf(fp, "[discovery]\n");
            fprintf(fp, "methods = wordlist,cert,bruteforce\n");
            fprintf(fp, "wordlist_path = ~/.subdigger/wordlists/common-subdomains.txt\n");
            fprintf(fp, "bruteforce_depth = 2\n\n");
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

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char config_path[1024];
        snprintf(config_path, sizeof(config_path), "%s/.subdigger/config", pw->pw_dir);
        config_load(&config, config_path);
    }

    static struct option long_options[] = {
        {"domain",    required_argument, 0, 'd'},
        {"threads",   required_argument, 0, 't'},
        {"wordlist",  required_argument, 0, 'w'},
        {"output",    required_argument, 0, 'o'},
        {"format",    required_argument, 0, 'f'},
        {"methods",   required_argument, 0, 'm'},
        {"no-cache",  no_argument,       0, 'n'},
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "d:t:w:o:f:m:nhv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                config.target_domain = strdup(optarg);
                break;
            case 't':
                config.threads = atoi(optarg);
                if (config.threads <= 0 || config.threads > MAX_THREADS) {
                    sd_error("Invalid thread count: %s (max: %d)", optarg, MAX_THREADS);
                    config_free(&config);
                    return 1;
                }
                break;
            case 'w':
                free(config.wordlist_path);
                config.wordlist_path = strdup(optarg);
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

    ctx.task_queue = task_queue_init(10000);
    if (!ctx.task_queue) {
        sd_error("Failed to initialize task queue");
        config_free(&config);
        return 1;
    }

    ctx.result_buffer = result_buffer_init(1000);
    if (!ctx.result_buffer) {
        sd_error("Failed to initialize result buffer");
        task_queue_destroy(ctx.task_queue);
        config_free(&config);
        return 1;
    }

    if (dns_init(&ctx) != 0) {
        sd_error("Failed to initialize DNS resolver");
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        config_free(&config);
        return 1;
    }

    geoip_init(&ctx);

    sd_info("Starting subdomain discovery for %s", config.target_domain);
    sd_info("Using %d threads with %d second timeout", config.threads, config.timeout);

    if (thread_pool_create(&ctx) != 0) {
        sd_error("Failed to create thread pool");
        dns_cleanup(&ctx);
        geoip_cleanup(&ctx);
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        config_free(&config);
        return 1;
    }

    if (discover_subdomains(&ctx) != 0) {
        sd_error("Subdomain discovery failed");
        dns_cleanup(&ctx);
        geoip_cleanup(&ctx);
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        config_free(&config);
        return 1;
    }

    FILE *output_fp = stdout;
    if (config.output_file) {
        output_fp = fopen(config.output_file, "w");
        if (!output_fp) {
            sd_error("Failed to open output file: %s", config.output_file);
            output_fp = stdout;
        }
    }

    if (strcmp(config.output_format, "json") == 0) {
        output_json_start(output_fp);
        for (size_t i = 0; i < ctx.result_buffer->count; i++) {
            output_json_record(output_fp, &ctx.result_buffer->results[i], i == ctx.result_buffer->count - 1);
        }
        output_json_end(output_fp);
    } else {
        output_csv_header(output_fp);
        for (size_t i = 0; i < ctx.result_buffer->count; i++) {
            safe_strncpy(ctx.result_buffer->results[i].source, "discovery", sizeof(ctx.result_buffer->results[i].source));
            output_csv_record(output_fp, &ctx.result_buffer->results[i]);
        }
    }

    if (output_fp != stdout) {
        fclose(output_fp);
        sd_info("Results written to %s", config.output_file);
    }

    sd_info("Discovery completed: %zu subdomains found", ctx.result_buffer->count);

    dns_cleanup(&ctx);
    geoip_cleanup(&ctx);
    result_buffer_destroy(ctx.result_buffer);
    task_queue_destroy(ctx.task_queue);
    config_free(&config);

    return 0;
}
