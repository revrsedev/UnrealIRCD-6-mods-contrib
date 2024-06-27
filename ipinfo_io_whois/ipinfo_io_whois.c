/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
    documentation "https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/ipinfo_io_whois/README.md";
    troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
    min-unrealircd-version "6.*";
    post-install-text {
        "The module is installed, now all you need to do is add a 'loadmodule' line to your config file:";
        "loadmodule \"third/ipinfo_io_whois.\";";
        "Add the TOKEN from info.io to the block ipinfo_whois in you're config file";
        "Then /rehash the IRCd.";
        "For usage information, refer to the module's documentation found at: https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/ipinfo_io_whois/README.md";
    }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"
#include <jansson.h>
#include <uthash.h>

#define MYCONF "ipinfo_io_whois"
#define API_URL "https://ipinfo.io/"

typedef struct {
    char *apikey;
} cfgstruct;

static cfgstruct muhcfg = {NULL};  // Ensure apikey is initialized to NULL

typedef struct {
    char ip[46]; // Supports both IPv4 and IPv6
    char info[256];
    time_t timestamp;
    UT_hash_handle hh;
} CacheEntry;

CacheEntry *cache = NULL;
time_t cache_duration = 86400; // 24 hours
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

ModuleHeader MOD_HEADER = {
    "third/ipinfo_io_whois",
    "1.0.0",
    "Show IPinfo.io information in WHOIS",
    "reverse",
    "unrealircd-6",
};

int ipinfo_io_whois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int ipinfo_io_whois_configposttest(int *errs);
int ipinfo_io_whois_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int ipinfo_io_whois_whois(Client *requester, Client *acptr, NameValuePrioList **list);
void free_cache();
void save_cache(ModuleInfo *modinfo);
void ipinfo_io_whois_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);

MOD_TEST() {
    memset(&muhcfg, 0, sizeof(muhcfg));
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, ipinfo_io_whois_configtest);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, ipinfo_io_whois_configposttest);
    return MOD_SUCCESS;
}

MOD_INIT() {
    MARK_AS_GLOBAL_MODULE(modinfo);

    // Ensures the module is not unloaded or reloaded to prevent crashes during async operations
    //ModuleSetOptions(modinfo->handle, MOD_OPT_PERM, 1);

    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, ipinfo_io_whois_configrun);
    HookAdd(modinfo->handle, HOOKTYPE_WHOIS, 0, ipinfo_io_whois_whois);

    // Register the web response callback
    RegisterApiCallbackWebResponse(modinfo->handle, "ipinfo_io_whois_callback", ipinfo_io_whois_callback);

    // Load the persistent cache when the module initializes
    LoadPersistentPointer(modinfo, cache, free_cache);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    safe_free(muhcfg.apikey);

    // Save the cache before unloading the module
    save_cache(modinfo);

    free_cache();
    return MOD_SUCCESS;
}

int ipinfo_io_whois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
    int errors = 0;
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    // Reset apikey to NULL before processing to avoid duplicate warnings
    safe_free(muhcfg.apikey);
    muhcfg.apikey = NULL;

    for (cep = ce->items; cep; cep = cep->next) {
        if (!cep->name) {
            config_error("%s:%i: blank %s item", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            continue;
        }

        if (!strcmp(cep->name, "apikey")) {
            if (muhcfg.apikey) {
                config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->file->filename, cep->line_number, MYCONF, cep->name);
                safe_free(muhcfg.apikey); // Free the previously set API key
            }
            safe_strdup(muhcfg.apikey, cep->value);
            continue;
        }
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int ipinfo_io_whois_configposttest(int *errs) {
    int errors = 0;

    if (!muhcfg.apikey) {
        config_error("No API key found for %s::apikey", MYCONF);
        errors++;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int ipinfo_io_whois_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    // Reset apikey to NULL before processing to avoid duplicate warnings
    safe_free(muhcfg.apikey);
    muhcfg.apikey = NULL;

    for (cep = ce->items; cep; cep = cep->next) {
        if (!cep->name)
            continue;

        if (!strcmp(cep->name, "apikey")) {
            if (muhcfg.apikey) {
                safe_free(muhcfg.apikey); // Ensure we free any existing API key to avoid duplicates
            }
            safe_strdup(muhcfg.apikey, cep->value);
            continue;
        }
    }
    return 1;
}

void add_to_cache(const char *ip, const char *info) {
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    strcpy(entry->ip, ip);
    strcpy(entry->info, info);
    entry->timestamp = time(NULL);
    pthread_mutex_lock(&cache_mutex);
    HASH_ADD_STR(cache, ip, entry);
    pthread_mutex_unlock(&cache_mutex);
}

CacheEntry *find_in_cache(const char *ip) {
    CacheEntry *entry;
    pthread_mutex_lock(&cache_mutex);
    HASH_FIND_STR(cache, ip, entry);
    if (entry && (time(NULL) - entry->timestamp) > cache_duration) {
        HASH_DEL(cache, entry);
        free(entry);
        entry = NULL;
    }
    pthread_mutex_unlock(&cache_mutex);
    return entry;
}

void free_cache() {
    CacheEntry *current_entry, *tmp;
    pthread_mutex_lock(&cache_mutex);
    HASH_ITER(hh, cache, current_entry, tmp) {
        HASH_DEL(cache, current_entry);
        free(current_entry);
    }
    pthread_mutex_unlock(&cache_mutex);
}

// Save the cache before unloading the module
void save_cache(ModuleInfo *modinfo) {
    SavePersistentPointer(modinfo, cache);
}

void ipinfo_io_whois_callback(OutgoingWebRequest *request, OutgoingWebResponse *response) {
    Client *acptr = (Client *)request->callback_data;
    if (response->errorbuf || !response->memory) {
        unreal_log(ULOG_INFO, "ipinfo_io_whois", "IPINFO_IO_WHOIS_BAD_RESPONSE", NULL,
                   "Error while trying to get IP info for $ip: $error",
                   log_data_string("ip", acptr->ip),
                   log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
        return;
    }

    json_t *root;
    json_error_t error;
    json_t *city, *region, *country, *org;

    root = json_loads(response->memory, 0, &error);

    if (root) {
        city = json_object_get(root, "city");
        region = json_object_get(root, "region");
        country = json_object_get(root, "country");
        org = json_object_get(root, "org");

        if (json_is_string(city) && json_is_string(region) && json_is_string(country) && json_is_string(org)) {
            char result_info[256];
            snprintf(result_info, sizeof(result_info), "City: %s, Region: %s, Country: %s, Org: %s",
                     json_string_value(city),
                     json_string_value(region),
                     json_string_value(country),
                     json_string_value(org));

            add_to_cache(acptr->ip, result_info);

            // Add the information to the WHOIS response
            Client *requester = (Client *)request->callback_data;
            NameValuePrioList *nvplist = NULL;
            add_nvplist_numeric_fmt(&nvplist, 320, "city", acptr, 320, "%s :is connecting from %s", acptr->name, result_info);
            sendto_one(requester, NULL, ":%s 320 %s %s :is connecting from %s", me.name, requester->name, acptr->name, result_info);
        }

        json_decref(root);
    }
}

int ipinfo_io_whois_whois(Client *requester, Client *acptr, NameValuePrioList **list) {
    if (!IsOper(requester) || IsULine(acptr) || IsServer(acptr)) {
        return 0; // Only opers can see the IP info, and ignore service clients and servers
    }

    CacheEntry *cached = find_in_cache(acptr->ip);
    if (cached) {
        add_nvplist_numeric_fmt(list, 320, "city", acptr, 320, "%s :is connecting from %s", acptr->name, cached->info);
        return 0;
    }

    // Use UnrealIRCd's URL API
    char url[256];
    snprintf(url, sizeof(url), API_URL "%s?token=%s", acptr->ip, muhcfg.apikey);

    OutgoingWebRequest *w = safe_alloc(sizeof(OutgoingWebRequest));
    safe_strdup(w->url, url);
    w->http_method = HTTP_METHOD_GET;
    safe_strdup(w->apicallback, "ipinfo_io_whois_callback");
    w->callback_data = acptr;

    url_start_async(w);

    return 0; // we g00d
}
