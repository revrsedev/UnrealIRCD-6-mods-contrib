#include "unrealircd.h"
#include <maxminddb.h>
#include <arpa/inet.h>

#define MYCONF "citywhois"

typedef struct {
    char *db_path;
    MMDB_s mmdb;
    int db_loaded;
} CityWhoisConfig;

static CityWhoisConfig citywhois_config;

// Module header
ModuleHeader MOD_HEADER = {
    "third/citywhois",                // Module name
    "1.0.6",                          // Version
    "Show city information in WHOIS", // Description
    "reverse",                       // Author
    "unrealircd-6",                   // UnrealIRCd version
};

// Function prototypes
int citywhois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int citywhois_configposttest(int *errs);
int citywhois_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int citywhois_whois(Client *requester, Client *acptr, NameValuePrioList **list);

// Module initialization functions
MOD_TEST() {
    memset(&citywhois_config, 0, sizeof(citywhois_config));
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, citywhois_configtest);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, citywhois_configposttest);
    return MOD_SUCCESS;
}

MOD_INIT() {
    MARK_AS_GLOBAL_MODULE(modinfo);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, citywhois_configrun);
    HookAdd(modinfo->handle, HOOKTYPE_WHOIS, 0, citywhois_whois);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    // Open the MaxMind DB during module load
    if (citywhois_config.db_path && !citywhois_config.db_loaded) {
        int status = MMDB_open(citywhois_config.db_path, MMDB_MODE_MMAP, &citywhois_config.mmdb);
        if (status != MMDB_SUCCESS) {
            config_error("CityWhois: Failed to open MaxMind DB '%s': %s", citywhois_config.db_path, MMDB_strerror(status));
            return MOD_FAILED;
        }
        citywhois_config.db_loaded = 1;
    }
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    if (citywhois_config.db_loaded) {
        MMDB_close(&citywhois_config.mmdb);
        citywhois_config.db_loaded = 0;
    }
    if (citywhois_config.db_path) {
        free(citywhois_config.db_path);
        citywhois_config.db_path = NULL;
    }
    return MOD_SUCCESS;
}

// Configuration test function
int citywhois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
    int errors = 0;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || strcmp(ce->name, MYCONF))
        return 0;

    ConfigEntry *cep = ce->items;
    while (cep) {
        if (strcmp(cep->name, "db") == 0) {
            char *db_path = strdup(cep->value); // Duplicate the value
            if (!db_path) {
                config_error("%s:%d: Out of memory", cep->file->filename, cep->line_number);
                errors++;
                break;
            }
            // Convert to absolute path
            convert_to_absolute_path(&db_path, NULL);

            // Check if the file exists and is readable
            if (access(db_path, R_OK) != 0) {
                config_error("%s:%d: Cannot access DB file '%s': %s",
                             cep->file->filename, cep->line_number, db_path, strerror(errno));
                errors++;
                free(db_path);
            } else {
                // Store the database path temporarily
                if (citywhois_config.db_path)
                    free(citywhois_config.db_path);
                citywhois_config.db_path = db_path;
            }
        } else {
            config_error("%s:%d: Unknown directive '%s' in %s block",
                         cep->file->filename, cep->line_number, cep->name, MYCONF);
            errors++;
        }
        cep = cep->next;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

// Configuration post-test function
int citywhois_configposttest(int *errs) {
    int errors = 0;

    if (!citywhois_config.db_path) {
        config_error("CityWhois: Missing 'db' directive in %s block", MYCONF);
        errors++;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

// Configuration run function
int citywhois_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || strcmp(ce->name, MYCONF))
        return 0;

    // No need to process again; already handled in configtest
    return 1;
}

// WHOIS hook function
int citywhois_whois(Client *requester, Client *acptr, NameValuePrioList **list) {
    // Only allow IRC operators to see the city information
    if (!IsOper(requester))
        return 0;

    // Ensure the target is a user
    if (!IsUser(acptr))
        return 0;

    // Check if the user has an IP address
    if (acptr->ip && *acptr->ip) {
        // Ensure the database is loaded
        if (!citywhois_config.db_loaded) {
            unreal_log(ULOG_ERROR, "citywhois", "module", NULL, "CityWhois: MaxMind DB not loaded.");
            return 0;
        }

        // Perform the lookup
        int gai_error = 0, mmdb_error = MMDB_SUCCESS;
        MMDB_lookup_result_s result = MMDB_lookup_string(&citywhois_config.mmdb, acptr->ip, &gai_error, &mmdb_error);

        if (gai_error != 0) {
            unreal_log(ULOG_ERROR, "citywhois", "module", NULL, "CityWhois: getaddrinfo error for %s - %s", acptr->ip, gai_strerror(gai_error));
            return 0;
        }

        if (mmdb_error != MMDB_SUCCESS) {
            unreal_log(ULOG_ERROR, "citywhois", "module", NULL, "CityWhois: libmaxminddb error: %s", MMDB_strerror(mmdb_error));
            return 0;
        }

        if (result.found_entry) {
            MMDB_entry_data_s city_data = {0};
            int exit_code = MMDB_get_value(&result.entry, &city_data, "city", "names", "en", NULL);

            if (exit_code == MMDB_SUCCESS && city_data.has_data) {
                char city[256];
                snprintf(city, sizeof(city), "%.*s", (int)city_data.data_size, city_data.utf8_string);

                // Add city information to the WHOIS output
                add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                                        "%s :is connecting from City: %s", acptr->name, city);
            } else {
                // City not found
                add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                                        "%s :is connecting from an unknown city", acptr->name);
            }
        } else {
            // No entry found in the database
            add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                                    "%s :is connecting from an unknown location", acptr->name);
        }
    } else {
        // IP address not available; add "No IP found!!" message
        add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                                "%s :No IP found!!", acptr->name);
    }

    return 0;
}
