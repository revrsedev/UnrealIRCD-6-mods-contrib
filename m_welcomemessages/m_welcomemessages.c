/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
    documentation "https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_welcomemessages/README.md";
    troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
    min-unrealircd-version "6.*";
    post-install-text {
        "The module is installed, now all you need to do is add a 'loadmodule' line to your config file:";
        "loadmodule \"third/m_ipident\";";
        "Add channel and custom messages to your config file";
        "Then /rehash the IRCd.";
        "For usage information, refer to the module's documentation found at: https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_welcomemessages/README.md";
    }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"
#define MYCONF "channel-welcome"
#define MAX_WELCOME_MSG 512 // Define the maximum length for the welcome message

// Structure to hold channel-specific messages
typedef struct {
	char channel[CHANNELLEN + 1];
	char message[MAX_WELCOME_MSG];
} ChannelMessage;

// Global array of ChannelMessage structures
ChannelMessage *channel_messages = NULL;
int channel_count = 0;

// Function declarations
void setcfg(void);
void freecfg(void);
int m_channelwelcome_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int m_channelwelcome_configposttest(int *errs);
int m_channelwelcome_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int custom_join(Client *sptr, Channel *chptr, MessageTag *mtags);

// Dat dere module header
ModuleHeader MOD_HEADER = {
	"third/m_channelwelcome", // Module name
	"1.0.1", // Version
	"Sends custom welcome messages for different channels", // Description
	"reverse", // Author
	"unrealircd-6", // Modversion
};

// Configuration testing-related hooks
MOD_TEST() {
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, m_channelwelcome_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, m_channelwelcome_configposttest);
	return MOD_SUCCESS;
}

// Initialisation routine (register hooks, commands and modes or create structs etc)
MOD_INIT() {
	MARK_AS_GLOBAL_MODULE(modinfo);
	setcfg();
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, m_channelwelcome_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_JOIN, 0, custom_join);
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
	// Initialize with no channels
	channel_messages = NULL;
	channel_count = 0;
}

// Free allocated memory on unload/reload
void freecfg(void) {
	if (channel_messages) {
		free(channel_messages);
		channel_messages = NULL;
	}
	channel_count = 0;
}

// Configuration test
int m_channelwelcome_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
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

		if (strlen(cep->name) >= CHANNELLEN) {
			config_error("%s:%i: channel name too long, maximum length is %d characters", cep->file->filename, cep->line_number, CHANNELLEN);
			errors++;
			continue;
		}

		if (strlen(cep->value) >= MAX_WELCOME_MSG) {
			config_error("%s:%i: welcome message too long, maximum length is %d characters", cep->file->filename, cep->line_number, MAX_WELCOME_MSG);
			errors++;
			continue;
		}
	}

	*errs = errors;
	return errors ? -1 : 1;
}

// Post-test configuration
int m_channelwelcome_configposttest(int *errs) {
	return 1;
}

// Run the configuration
int m_channelwelcome_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
	ConfigEntry *cep;

	if (type != CONFIG_MAIN)
		return 0;

	if (!ce || !ce->name)
		return 0;

	if (strcmp(ce->name, MYCONF))
		return 0;

	freecfg();

	for (cep = ce->items; cep; cep = cep->next)
		channel_count++;

	channel_messages = malloc(sizeof(ChannelMessage) * channel_count);

	int i = 0;
	for (cep = ce->items; cep; cep = cep->next) {
		strlcpy(channel_messages[i].channel, cep->name, CHANNELLEN + 1);
		strlcpy(channel_messages[i].message, cep->value, MAX_WELCOME_MSG);
		i++;
	}

	return 1; // We good
}

// Send custom message on join
int custom_join(Client *sptr, Channel *chptr, MessageTag *mtags) {
	if (!IsUser(sptr))
		return HOOK_CONTINUE;

	for (int i = 0; i < channel_count; i++) {
		if (match_simple(channel_messages[i].channel, chptr->name)) {
			sendnotice(sptr, "%s", channel_messages[i].message);  // Use format string properly
			break;
		}
	}
	return HOOK_CONTINUE;
}