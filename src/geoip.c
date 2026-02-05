#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <maxminddb.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "../include/subdigger.h"

static const char *geoip_country_paths[] = {
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    NULL
};

static const char *geoip_city_paths[] = {
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    NULL
};

static const char *geoip_asn_paths[] = {
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    NULL
};

typedef struct {
    const char *tld;
    const char *iso;
    const char *country;
} tld_mapping_t;

static const tld_mapping_t tld_mappings[] = {
    {"dk", "DK", "Denmark"},
    {"com", "US", "United States"},
    {"net", "US", "United States"},
    {"org", "US", "United States"},
    {"uk", "GB", "United Kingdom"},
    {"de", "DE", "Germany"},
    {"fr", "FR", "France"},
    {"nl", "NL", "Netherlands"},
    {"se", "SE", "Sweden"},
    {"no", "NO", "Norway"},
    {"fi", "FI", "Finland"},
    {"es", "ES", "Spain"},
    {"it", "IT", "Italy"},
    {"pl", "PL", "Poland"},
    {"ru", "RU", "Russia"},
    {"cn", "CN", "China"},
    {"jp", "JP", "Japan"},
    {"au", "AU", "Australia"},
    {"ca", "CA", "Canada"},
    {"br", "BR", "Brazil"},
    {"in", "IN", "India"},
    {"mx", "MX", "Mexico"},
    {"ar", "AR", "Argentina"},
    {"ch", "CH", "Switzerland"},
    {"at", "AT", "Austria"},
    {"be", "BE", "Belgium"},
    {"cz", "CZ", "Czech Republic"},
    {"ie", "IE", "Ireland"},
    {"nz", "NZ", "New Zealand"},
    {"sg", "SG", "Singapore"},
    {"hk", "HK", "Hong Kong"},
    {"kr", "KR", "South Korea"},
    {"tw", "TW", "Taiwan"},
    {"za", "ZA", "South Africa"},
    {"tr", "TR", "Turkey"},
    {"il", "IL", "Israel"},
    {"ae", "AE", "United Arab Emirates"},
    {"sa", "SA", "Saudi Arabia"},
    {"eg", "EG", "Egypt"},
    {"id", "ID", "Indonesia"},
    {"th", "TH", "Thailand"},
    {"my", "MY", "Malaysia"},
    {"ph", "PH", "Philippines"},
    {"vn", "VN", "Vietnam"},
    {"pt", "PT", "Portugal"},
    {"gr", "GR", "Greece"},
    {"ro", "RO", "Romania"},
    {"hu", "HU", "Hungary"},
    {"bg", "BG", "Bulgaria"},
    {"hr", "HR", "Croatia"},
    {"sk", "SK", "Slovakia"},
    {"si", "SI", "Slovenia"},
    {"lt", "LT", "Lithuania"},
    {"lv", "LV", "Latvia"},
    {"ee", "EE", "Estonia"},
    {"is", "IS", "Iceland"},
    {"lu", "LU", "Luxembourg"},
    {"mt", "MT", "Malta"},
    {"cy", "CY", "Cyprus"},
    {NULL, NULL, NULL}
};

void tld_lookup_country(const char *tld, char *iso_code, char *country_name) {
    if (!tld || !iso_code || !country_name) {
        return;
    }

    for (int i = 0; tld_mappings[i].tld != NULL; i++) {
        if (strcasecmp(tld, tld_mappings[i].tld) == 0) {
            safe_strncpy(iso_code, tld_mappings[i].iso, 4);
            safe_strncpy(country_name, tld_mappings[i].country, 64);
            return;
        }
    }

    safe_strncpy(iso_code, "", 4);
    safe_strncpy(country_name, "", 64);
}

static MMDB_s *try_open_database(const char **paths, const char *db_name) {
    MMDB_s *mmdb = malloc(sizeof(MMDB_s));
    if (!mmdb) {
        return NULL;
    }

    for (int i = 0; paths[i] != NULL; i++) {
        int status = MMDB_open(paths[i], MMDB_MODE_MMAP, mmdb);
        if (status == MMDB_SUCCESS) {
            sd_info("Loaded %s database: %s", db_name, paths[i]);
            return mmdb;
        }
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        char user_path[1024];
        snprintf(user_path, sizeof(user_path), "%s/.subdigger/%s", pw->pw_dir, db_name);

        int status = MMDB_open(user_path, MMDB_MODE_MMAP, mmdb);
        if (status == MMDB_SUCCESS) {
            sd_info("Loaded %s database: %s", db_name, user_path);
            return mmdb;
        }
    }

    free(mmdb);
    return NULL;
}

int geoip_init(subdigger_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }

    ctx->geoip_db = try_open_database(geoip_country_paths, "GeoLite2-Country.mmdb");
    ctx->geoip_city_db = try_open_database(geoip_city_paths, "GeoLite2-City.mmdb");
    ctx->geoip_asn_db = try_open_database(geoip_asn_paths, "GeoLite2-ASN.mmdb");

    if (!ctx->geoip_db && !ctx->geoip_city_db) {
        sd_warn("GeoIP databases not found, IP geolocation disabled");
        sd_info("Install with: apt-get install geoipupdate && geoipupdate");
    }

    return 0;
}

void geoip_cleanup(subdigger_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->geoip_db) {
        MMDB_s *mmdb = (MMDB_s *)ctx->geoip_db;
        MMDB_close(mmdb);
        free(mmdb);
        ctx->geoip_db = NULL;
    }

    if (ctx->geoip_city_db) {
        MMDB_s *mmdb = (MMDB_s *)ctx->geoip_city_db;
        MMDB_close(mmdb);
        free(mmdb);
        ctx->geoip_city_db = NULL;
    }

    if (ctx->geoip_asn_db) {
        MMDB_s *mmdb = (MMDB_s *)ctx->geoip_asn_db;
        MMDB_close(mmdb);
        free(mmdb);
        ctx->geoip_asn_db = NULL;
    }
}

void geoip_lookup(subdigger_ctx_t *ctx, const char *ip, subdomain_result_t *result) {
    if (!ctx || !ip || !result) {
        return;
    }

    safe_strncpy(result->ip_iso, "", 4);
    safe_strncpy(result->ip_country, "", 64);
    safe_strncpy(result->ip_city, "", 128);
    safe_strncpy(result->asn_org, "", 256);

    pthread_mutex_lock(&ctx->geoip_mutex);

    MMDB_s *city_db = (MMDB_s *)ctx->geoip_city_db;
    MMDB_s *country_db = (MMDB_s *)ctx->geoip_db;
    MMDB_s *asn_db = (MMDB_s *)ctx->geoip_asn_db;

    int gai_error, mmdb_error;

    // Try City database first (has country + city)
    if (city_db) {
        MMDB_lookup_result_s city_result = MMDB_lookup_string(city_db, ip, &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && city_result.found_entry) {
            MMDB_entry_data_s entry_data;

            // Get country ISO code
            int status = MMDB_get_value(&city_result.entry, &entry_data, "country", "iso_code", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 3 ? entry_data.data_size : 3;
                memcpy(result->ip_iso, entry_data.utf8_string, copy_len);
                result->ip_iso[copy_len] = '\0';
            }

            // Get country name
            status = MMDB_get_value(&city_result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 63 ? entry_data.data_size : 63;
                memcpy(result->ip_country, entry_data.utf8_string, copy_len);
                result->ip_country[copy_len] = '\0';
            }

            // Get city name
            status = MMDB_get_value(&city_result.entry, &entry_data, "city", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 127 ? entry_data.data_size : 127;
                memcpy(result->ip_city, entry_data.utf8_string, copy_len);
                result->ip_city[copy_len] = '\0';
            }
        }
    }
    // Fallback to Country database if City not available
    else if (country_db) {
        MMDB_lookup_result_s country_result = MMDB_lookup_string(country_db, ip, &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && country_result.found_entry) {
            MMDB_entry_data_s entry_data;

            // Get country ISO code
            int status = MMDB_get_value(&country_result.entry, &entry_data, "country", "iso_code", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 3 ? entry_data.data_size : 3;
                memcpy(result->ip_iso, entry_data.utf8_string, copy_len);
                result->ip_iso[copy_len] = '\0';
            }

            // Get country name
            status = MMDB_get_value(&country_result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 63 ? entry_data.data_size : 63;
                memcpy(result->ip_country, entry_data.utf8_string, copy_len);
                result->ip_country[copy_len] = '\0';
            }
        }
    }

    // Get ASN information
    if (asn_db) {
        MMDB_lookup_result_s asn_result = MMDB_lookup_string(asn_db, ip, &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && asn_result.found_entry) {
            MMDB_entry_data_s entry_data;

            // Get ASN organization
            int status = MMDB_get_value(&asn_result.entry, &entry_data, "autonomous_system_organization", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                size_t copy_len = entry_data.data_size < 255 ? entry_data.data_size : 255;
                memcpy(result->asn_org, entry_data.utf8_string, copy_len);
                result->asn_org[copy_len] = '\0';
            }
        }
    }

    pthread_mutex_unlock(&ctx->geoip_mutex);
}
