/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
    documentation "https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_ipinfo_whois/README.md";
    troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
    min-unrealircd-version "6.*";
    post-install-text {
        "The module is installed, now all you need to do is add a 'loadmodule' line to your config file:";
        "loadmodule \"third/m_ipinfo_whois\";";
        "Add to the TOKEN API to the block ipinfo_whois in you're config file";
        "Then /rehash the IRCd.";
        "For usage information, refer to the module's documentation found at: https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_ipinfo_whois/README.md";
    }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"
#include <curl/curl.h>
#include <jansson.h>
#include <uthash.h>

#define MYCONF "ipinfo_whois"
#define API_URL "https://ipinfo.io/"

typedef struct {
    char *apikey;
} cfgstruct;

static cfgstruct muhcfg;

typedef struct {
    char ip[46]; // Supports both IPv4 and IPv6
    char info[256];
    time_t timestamp;
    UT_hash_handle hh;
} CacheEntry;

CacheEntry *cache = NULL;
time_t cache_duration = 86400; // 24 hours

ModuleHeader MOD_HEADER = {
    "third/m_ipinfo_whois",
    "1.0.0",
    "Show IPinfo.io information in WHOIS",
    "reverse",
    "unrealircd-6",
};

int ipinfo_whois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int ipinfo_whois_configposttest(int *errs);
int ipinfo_whois_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int ipinfo_whois_whois(Client *requester, Client *acptr, NameValuePrioList **list);
void free_cache();

MOD_TEST() {
    memset(&muhcfg, 0, sizeof(muhcfg));
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, ipinfo_whois_configtest);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, ipinfo_whois_configposttest);
    return MOD_SUCCESS;
}

MOD_INIT() {
    MARK_AS_GLOBAL_MODULE(modinfo);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, ipinfo_whois_configrun);
    HookAdd(modinfo->handle, HOOKTYPE_WHOIS, 0, ipinfo_whois_whois);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    safe_free(muhcfg.apikey);
    free_cache();
    return MOD_SUCCESS;
}

int ipinfo_whois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
    int errors = 0;
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    for (cep = ce->items; cep; cep = cep->next) {
        if (!cep->name) {
            config_error("%s:%i: blank %s item", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            continue;
        }

        if (!strcmp(cep->name, "apikey")) {
            if (muhcfg.apikey)
                config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->file->filename, cep->line_number, MYCONF, cep->name);
            safe_strdup(muhcfg.apikey, cep->value);
            continue;
        }
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int ipinfo_whois_configposttest(int *errs) {
    int errors = 0;

    if (!muhcfg.apikey) {
        config_error("No API key found for %s::apikey", MYCONF);
        errors++;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int ipinfo_whois_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    for (cep = ce->items; cep; cep = cep->next) {
        if (!cep->name)
            continue;

        if (!strcmp(cep->name, "apikey")) {
            safe_strdup(muhcfg.apikey, cep->value);
            continue;
        }
    }
    return 1;
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        return 0; // out of memory!
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void add_to_cache(const char *ip, const char *info) {
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    strcpy(entry->ip, ip);
    strcpy(entry->info, info);
    entry->timestamp = time(NULL);
    HASH_ADD_STR(cache, ip, entry);
}

CacheEntry *find_in_cache(const char *ip) {
    CacheEntry *entry;
    HASH_FIND_STR(cache, ip, entry);
    if (entry && (time(NULL) - entry->timestamp) > cache_duration) {
        HASH_DEL(cache, entry);
        free(entry);
        entry = NULL;
    }
    return entry;
}

void free_cache() {
    CacheEntry *current_entry, *tmp;
    HASH_ITER(hh, cache, current_entry, tmp) {
        HASH_DEL(cache, current_entry);
        free(current_entry);
    }
}

int ipinfo_whois_whois(Client *requester, Client *acptr, NameValuePrioList **list) {
    if (!IsOper(requester) || IsULine(acptr) || IsServer(acptr)) {
        return 0; // Only opers can see the IP info, and ignore service clients and servers
    }

    CacheEntry *cached = find_in_cache(acptr->ip);
    if (cached) {
        add_nvplist_numeric_fmt(list, 320, "city", acptr, 320, "%s :is connecting from %s", acptr->name, cached->info);
        return 0;
    }

    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1); // will be grown as needed by the realloc above
    chunk.size = 0; // no data at this point

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();

    if (curl_handle) {
        char url[256];
        snprintf(url, sizeof(url), API_URL "%s?token=%s", acptr->ip, muhcfg.apikey);

        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl_handle);

        if (res == CURLE_OK) {
            json_t *root;
            json_error_t error;
            json_t *city, *region, *country, *org;

            root = json_loads(chunk.memory, 0, &error);

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

                    add_nvplist_numeric_fmt(list, 320, "city", acptr, 320, "%s :is connecting from %s", acptr->name, result_info);
                }

                json_decref(root);
            }
        }

        curl_easy_cleanup(curl_handle);
        free(chunk.memory);
    }

    curl_global_cleanup();

    return 0;
}
