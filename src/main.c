#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include "../include/subdigger.h"

#define VERSION "1.4.0"

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
    printf("                            (Plural forms like 'wordlists', 'certs' are also accepted)\n");
    printf("  -q, --quiet               Quiet mode: only output data (no logs)\n");
    printf("  --no-progress             Disable progress reporting\n");
    printf("  --no-auto-wordlists       Disable automatic wordlist discovery (default: enabled)\n");
    printf("  --bruteforce-depth <n>    Bruteforce depth 1-5 (default: 3, includes a-z0-9_)\n");
    printf("                            Note: Also add 'bruteforce' to --methods to enable\n");
    printf("  --no-cache                Disable caching\n");
    printf("  --get-root-db             Fetch and update IANA TLD database\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -v, --version             Show version information\n\n");
    printf("Configuration:\n");
    printf("  Config file: ~/.subdigger/config\n");
    printf("  Wordlists:   ~/.subdigger/wordlists/\n");
    printf("  Cache:       ~/.subdigger/cache/\n\n");
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

static bool is_valid_method(const char *method) {
    const char *valid_methods[] = {
        "wordlist", "wordlists",
        "cert", "certs", "certificate", "certificates",
        "bruteforce",
        "dns",
        "api", "apis",
        NULL
    };

    for (int i = 0; valid_methods[i] != NULL; i++) {
        if (strcmp(method, valid_methods[i]) == 0) {
            return true;
        }
    }

    return false;
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
            fprintf(fp, "# Add API keys for passive subdomain discovery services\n");
            fprintf(fp, "# Free tier available (no key required): BufferOver\n");
            fprintf(fp, "# Get keys from respective service providers\n\n");
            fprintf(fp, "# BeVigil - https://bevigil.com/osint-api\n");
            fprintf(fp, "bevigil_key = \n\n");
            fprintf(fp, "# BinaryEdge - https://www.binaryedge.io/\n");
            fprintf(fp, "binaryedge_key = \n\n");
            fprintf(fp, "# C99.nl - https://api.c99.nl/\n");
            fprintf(fp, "c99_key = \n\n");
            fprintf(fp, "# Censys - https://search.censys.io/api\n");
            fprintf(fp, "censys_id = \n");
            fprintf(fp, "censys_secret = \n\n");
            fprintf(fp, "# CertSpotter - https://sslmate.com/certspotter/api/\n");
            fprintf(fp, "certspotter_key = \n\n");
            fprintf(fp, "# Chaos - https://chaos.projectdiscovery.io/\n");
            fprintf(fp, "chaos_key = \n\n");
            fprintf(fp, "# FullHunt - https://fullhunt.io/\n");
            fprintf(fp, "fullhunt_key = \n\n");
            fprintf(fp, "# GitHub - https://github.com/settings/tokens\n");
            fprintf(fp, "github_token = \n\n");
            fprintf(fp, "# Hunter - https://hunter.io/api\n");
            fprintf(fp, "hunter_key = \n\n");
            fprintf(fp, "# IntelX - https://intelx.io/\n");
            fprintf(fp, "intelx_key = \n\n");
            fprintf(fp, "# LeakIX - https://leakix.net/\n");
            fprintf(fp, "leakix_key = \n\n");
            fprintf(fp, "# Netlas - https://netlas.io/\n");
            fprintf(fp, "netlas_key = \n\n");
            fprintf(fp, "# PassiveTotal - https://community.riskiq.com/\n");
            fprintf(fp, "passivetotal_user = \n");
            fprintf(fp, "passivetotal_key = \n\n");
            fprintf(fp, "# SecurityTrails - https://securitytrails.com/\n");
            fprintf(fp, "securitytrails_key = \n\n");
            fprintf(fp, "# Shodan - https://account.shodan.io/\n");
            fprintf(fp, "shodan_key = \n\n");
            fprintf(fp, "# VirusTotal - https://www.virustotal.com/gui/my-apikey\n");
            fprintf(fp, "virustotal_key = \n\n");
            fprintf(fp, "# WhoisXMLAPI - https://whoisxmlapi.com/\n");
            fprintf(fp, "whoisxmlapi_key = \n\n");
            fprintf(fp, "# ZoomEye - https://www.zoomeye.org/\n");
            fprintf(fp, "zoomeye_key = \n");
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
        {"bruteforce-depth",  required_argument, 0, 'D'},
        {"no-cache",          no_argument,       0, 'n'},
        {"get-root-db",       no_argument,       0, 'G'},
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
                bool has_invalid = false;
                while (token) {
                    token = trim(token);
                    if (!is_valid_method(token)) {
                        sd_warn("Invalid method '%s' - valid methods: wordlist,cert,bruteforce,dns,api", token);
                        has_invalid = true;
                    }
                    config.methods = realloc(config.methods, (config.method_count + 1) * sizeof(char *));
                    config.methods[config.method_count] = strdup(token);
                    config.method_count++;
                    token = strtok(NULL, ",");
                }
                free(methods_copy);
                if (has_invalid) {
                    sd_info("Note: 'wordlists', 'certs', 'apis' are accepted as aliases");
                }
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
            case 'D':
                config.bruteforce_depth = atoi(optarg);
                if (config.bruteforce_depth < 1 || config.bruteforce_depth > MAX_BRUTEFORCE_DEPTH) {
                    sd_error("Invalid bruteforce depth: %s (must be 1-%d)", optarg, MAX_BRUTEFORCE_DEPTH);
                    config_free(&config);
                    return 1;
                }
                break;
            case 'n':
                config.cache_enabled = false;
                break;
            case 'G':
                config.get_root_db = true;
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

    // Handle --get-root-db flag (can run standalone)
    if (config.get_root_db) {
        const char *db_path = tld_database_get_path();
        if (!db_path) {
            sd_error("Failed to determine TLD database path");
            config_free(&config);
            return 1;
        }

        sd_info("Fetching IANA root database...");
        if (tld_database_fetch_and_parse(db_path) == 0) {
            sd_info("TLD database updated successfully: %s", db_path);
            config_free(&config);
            return 0;
        } else {
            sd_error("Failed to fetch/parse IANA root database");
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

    ctx.task_queue = task_queue_init(500000);
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

    ctx.discovered_buffer = discovered_buffer_init(1000);
    if (!ctx.discovered_buffer) {
        sd_error("Failed to initialize discovered buffer");
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    if (dns_init(&ctx) != 0) {
        sd_error("Failed to initialize DNS resolver");
        discovered_buffer_destroy(ctx.discovered_buffer);
        result_buffer_destroy(ctx.result_buffer);
        task_queue_destroy(ctx.task_queue);
        if (ctx.output_fp && ctx.output_fp != stdout) fclose(ctx.output_fp);
        pthread_mutex_destroy(&ctx.output_mutex);
        pthread_mutex_destroy(&ctx.geoip_mutex);
        config_free(&config);
        return 1;
    }

    geoip_init(&ctx);
    tld_database_init(&ctx, false);

    sd_info("Starting subdomain discovery for %s", config.target_domain);

    if (thread_pool_create(&ctx) != 0) {
        sd_error("Failed to create thread pool");
        dns_cleanup(&ctx);
        geoip_cleanup(&ctx);
        tld_database_cleanup(&ctx);
        discovered_buffer_destroy(ctx.discovered_buffer);
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
        tld_database_cleanup(&ctx);
        discovered_buffer_destroy(ctx.discovered_buffer);
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
    tld_database_cleanup(&ctx);
    discovered_buffer_destroy(ctx.discovered_buffer);
    result_buffer_destroy(ctx.result_buffer);
    task_queue_destroy(ctx.task_queue);

    pthread_mutex_destroy(&ctx.output_mutex);
    pthread_mutex_destroy(&ctx.geoip_mutex);

    global_ctx = NULL;

    config_free(&config);

    return 0;
}
