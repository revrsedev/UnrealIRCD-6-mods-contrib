/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
    documentation "https://github.com/revrsedev/unrealircd-mods-contrib/blob/main/m_ipident/README.md";
    troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
    min-unrealircd-version "6.*";
    post-install-text {
        "The module is installed, now all you need to do is add a 'loadmodule' line to your config file:";
        "loadmodule \"third/m_ipident\";";
        "Add the cloak-ident-keys entry to your config file";
        "Then /rehash the IRCd.";
        "For usage information, refer to the module's documentation found at: https://github.com/revrsedev/unrealircd-mods-contrib/blob/main/m_ipident/README.md";
    }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"
#include <openssl/sha.h>

// Config block
#define MYCONF "cloak-ident-keys"
#define MAX_CLOAK_KEYS 5

// Configuration structure to hold the cloak keys
typedef struct {
    char *keys[MAX_CLOAK_KEYS];
    int key_count;
} CloakConfig;

CloakConfig cloak_config;

// Function declarations
void setcfg(void);
void freecfg(void);
int m_ipident_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int m_ipident_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int set_crypto_ip_based_ident(Client *client);

// Dat dere module header
ModuleHeader MOD_HEADER = {
    "third/m_ipident", // Module name
    "1.0.1", // Version
    "Generate ident based on ipv4 and ipv6 + user-defined config cloak-ident-keys", // Description
    "reverse", // Author
    "unrealircd-6", // Modversion
};

// Configuration testing-related hooks go in the testing phase
MOD_TEST() {
    memset(&cloak_config, 0, sizeof(cloak_config)); // Zero-initialise config

    // We have our own config block so we need to check config
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, m_ipident_configtest);
    return MOD_SUCCESS;
}

// Initialisation routine (register hooks, commands and modes or create structs etc)
MOD_INIT() {
    MARK_AS_GLOBAL_MODULE(modinfo);

    setcfg();
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, m_ipident_configrun);
    HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, set_crypto_ip_based_ident);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS; // We good
}

// Called on unload/rehash
MOD_UNLOAD() {
    freecfg();
    return MOD_SUCCESS; // We good
}

// Set config defaults
void setcfg(void) {
    memset(&cloak_config, 0, sizeof(cloak_config));
}

// Free allocated memory on unload/reload
void freecfg(void) {
    for (int i = 0; i < cloak_config.key_count; i++) {
        free(cloak_config.keys[i]);
    }
    setcfg();
}

// Configuration test
int m_ipident_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
    int errors = 0;
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    for (cep = ce->items; cep; cep = cep->next) {
        if (!cep->value) {
            config_error("%s:%i: invalid %s entry", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            continue;
        }

        if (cloak_config.key_count >= MAX_CLOAK_KEYS) {
            config_error("%s:%i: too many keys specified in %s", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            break;
        }

        // Valid key, increment key count
        cloak_config.key_count++;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

// Run the configuration
int m_ipident_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
    ConfigEntry *cep;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || !ce->name)
        return 0;

    if (strcmp(ce->name, MYCONF))
        return 0;

    freecfg();

    for (cep = ce->items; cep; cep = cep->next) {
        if (cloak_config.key_count < MAX_CLOAK_KEYS) {
            cloak_config.keys[cloak_config.key_count++] = strdup(cep->value);
            if (!cloak_config.keys[cloak_config.key_count - 1]) {
                config_error("Memory allocation failed for cloak key");
                freecfg();
                return 0;
            }
        }
    }

    return 1; // We good
}

// Function to determine if the IP address is IPv6
static int is_ipv6_address(const char *ip) {
    return strchr(ip, ':') != NULL;
}

int set_crypto_ip_based_ident(Client *client) {
    if (!client->ip || !client->user) {
        return HOOK_CONTINUE;
    }

    if (cloak_config.key_count == 0) {
        // No cloak keys configured
        return HOOK_CONTINUE;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    char ident[10];

    
    SHA256((unsigned char*)client->ip, strlen(client->ip), hash);

    // Select a cloak key
    const char *cloak_key = cloak_config.keys[rand() % cloak_config.key_count];
    char combined_hash[SHA256_DIGEST_LENGTH + 64 + 1];
    snprintf(combined_hash, sizeof(combined_hash), "%s%s", client->ip, cloak_key);

    for (int i = 0; i < 9; ++i) {
        unsigned char byte = combined_hash[i % (SHA256_DIGEST_LENGTH + 64)];
        if (i < 6) {
            ident[i] = (byte % 2 == 0) ? 'a' + (byte % 26) : 'A' + (byte % 26);
        } else {
            ident[i] = '0' + (byte % 10);
        }
    }
    ident[9] = '\0';
    strlcpy(client->user->username, ident, sizeof(client->user->username));
    return HOOK_CONTINUE;
}
