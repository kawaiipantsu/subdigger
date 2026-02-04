#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <maxminddb.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "../include/subdigger.h"

static const char *geoip_paths[] = {
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    NULL
};

int geoip_init(subdigger_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }

    MMDB_s *mmdb = malloc(sizeof(MMDB_s));
    if (!mmdb) {
        return -1;
    }

    for (int i = 0; geoip_paths[i] != NULL; i++) {
        int status = MMDB_open(geoip_paths[i], MMDB_MODE_MMAP, mmdb);
        if (status == MMDB_SUCCESS) {
            ctx->geoip_db = mmdb;
            sd_info("Loaded GeoIP database: %s", geoip_paths[i]);
            return 0;
        }
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char user_path[1024];
        snprintf(user_path, sizeof(user_path), "%s/.subdigger/GeoLite2-Country.mmdb", pw->pw_dir);

        int status = MMDB_open(user_path, MMDB_MODE_MMAP, mmdb);
        if (status == MMDB_SUCCESS) {
            ctx->geoip_db = mmdb;
            sd_info("Loaded GeoIP database: %s", user_path);
            return 0;
        }
    }

    free(mmdb);
    sd_warn("GeoIP database not found, country resolution disabled");
    sd_info("Install with: apt-get install geoipupdate && geoipupdate");
    ctx->geoip_db = NULL;
    return 0;
}

void geoip_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx || !ctx->geoip_db) {
        return;
    }

    MMDB_s *mmdb = (MMDB_s *)ctx->geoip_db;
    MMDB_close(mmdb);
    free(mmdb);
    ctx->geoip_db = NULL;
}

void geoip_lookup(subdigger_ctx_t *ctx, const char *ip, char *country_code) {
    if (!ctx || !ctx->geoip_db || !ip || !country_code) {
        safe_strncpy(country_code, "N/A", 3);
        return;
    }

    MMDB_s *mmdb = (MMDB_s *)ctx->geoip_db;

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(mmdb, ip, &gai_error, &mmdb_error);

    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        safe_strncpy(country_code, "N/A", 3);
        return;
    }

    MMDB_entry_data_s entry_data;
    int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

    if (status != MMDB_SUCCESS || !entry_data.has_data || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        safe_strncpy(country_code, "N/A", 3);
        return;
    }

    size_t copy_len = entry_data.data_size < 2 ? entry_data.data_size : 2;
    memcpy(country_code, entry_data.utf8_string, copy_len);
    country_code[copy_len] = '\0';
}
