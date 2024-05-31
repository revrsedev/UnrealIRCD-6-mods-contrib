/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
		documentation "https://github.com/rainfr/musk-unrealircd-6-contrib/blob/main/m_ipident/README.md";
		troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
		min-unrealircd-version "6.*";
		max-unrealircd-version "6.*";
		post-install-text {
				"The module is installed. Now all you need to do is add a loadmodule line:";
				"loadmodule \"third/m_ipident\";";
				"And /REHASH the IRCd.";
		}
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"
#include <openssl/sha.h>

#define MYCONF "cloak-keys"
#define MAX_CLOAK_KEYS 5

ModuleHeader MOD_HEADER = {
    "third/m_ipident", 
    "1.0.1",
    "Generate ident based on ipv4, ipv6 + cloak-key config block.", 
    "reverse",               
    "unrealircd-6",        
};

// Configuration structure to hold the cloak keys
struct {
    char *keys[MAX_CLOAK_KEYS];
    int key_count;
} cloak_config;

// Function declarations
void setcfg(void);
void freecfg(void);
int m_ipident_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int m_ipident_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int set_crypto_ip_based_ident(Client *client);

// Module initialization
MOD_INIT() {
    HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, set_crypto_ip_based_ident);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, m_ipident_configtest);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, m_ipident_configrun);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    freecfg();
    return MOD_SUCCESS;
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
        if (!cep->name || !cep->value) {
            config_error("%s:%i: invalid %s entry", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            continue;
        }

        if (cloak_config.key_count >= MAX_CLOAK_KEYS) {
            config_error("%s:%i: too many keys specified in %s", cep->file->filename, cep->line_number, MYCONF);
            errors++;
            break;
        }
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

// Set ident based on SHA-256 hash of IP and user-defined cloak key
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

    // Compute SHA-256 hash of the IP address
    SHA256((unsigned char*)client->ip, strlen(client->ip), hash);

    // Select a cloak key
    const char *cloak_key = cloak_config.keys[rand() % cloak_config.key_count];

    // Combine the hash and the cloak key
    char combined_hash[SHA256_DIGEST_LENGTH + 64 + 1];
    snprintf(combined_hash, sizeof(combined_hash), "%s%s", client->ip, cloak_key);

    // Generate ident from the combined hash
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
