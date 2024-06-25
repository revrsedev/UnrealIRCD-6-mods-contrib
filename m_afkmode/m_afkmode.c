#include "unrealircd.h"

#define MAX_AFK_MESSAGE_LENGTH 256

ModuleHeader MOD_HEADER = {
    "third/m_afkmode",
    "1.0",
    "AFK Module for UnrealIRCd 6",
    "reverse",
    "unrealircd-6"
};

CMD_FUNC(cmd_afk_on);
CMD_FUNC(cmd_afk_off);
CMD_FUNC(cmd_afk_message);

typedef struct {
    int afk;
    char *message;
} UserAFKInfo;

ModDataInfo *afkmod;

#define CLIENT_AFK_INFO(client)  ((UserAFKInfo *)moddata_client(client, afkmod).ptr)

static void afk_info_free(ModData *m) {
    UserAFKInfo *info = (UserAFKInfo *)m->ptr;
    if (info) {
        if (info->message) {
            free(info->message);
        }
        free(info);
    }
}

int afkmod_whois(Client *requester, Client *acptr, NameValuePrioList **list);

MOD_INIT() {
    ModDataInfo mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = MODDATATYPE_CLIENT;
    mreq.name = "afk_info";
    mreq.free = afk_info_free;
    afkmod = ModDataAdd(modinfo->handle, mreq);
    if (!afkmod) {
        config_error("Failed to register moddata");
        return MOD_FAILED;
    }

    CommandAdd(modinfo->handle, "AFK-ON", cmd_afk_on, 1, CMD_USER);
    CommandAdd(modinfo->handle, "AFK-OFF", cmd_afk_off, 1, CMD_USER);
    CommandAdd(modinfo->handle, "AFK-MESSAGE", cmd_afk_message, 1, CMD_USER);

    HookAdd(modinfo->handle, HOOKTYPE_WHOIS, 0, afkmod_whois);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    return MOD_SUCCESS;
}

int afkmod_whois(Client *requester, Client *acptr, NameValuePrioList **list) {
    UserAFKInfo *info = CLIENT_AFK_INFO(acptr);
    if (info && info->afk && !IsULine(acptr)) {
        const char *message = info->message ? info->message : "is currently AFK.";
        add_nvplist_numeric_fmt(list, 320, "afk", acptr, 320, "%s :%s", acptr->name, message);
    }
    return 0;
}

CMD_FUNC(cmd_afk_on) {
    if (!MyUser(client) || IsULine(client)) return;
    UserAFKInfo *info = CLIENT_AFK_INFO(client);
    if (!info) {
        info = safe_alloc(sizeof(UserAFKInfo));
        moddata_client(client, afkmod).ptr = info;
    }
    info->afk = 1;
    sendnotice(client, "AFK mode activated.");
}

CMD_FUNC(cmd_afk_off) {
    if (!MyUser(client) || IsULine(client)) return;
    UserAFKInfo *info = CLIENT_AFK_INFO(client);
    if (info) {
        info->afk = 0;
        if (info->message) {
            free(info->message);
            info->message = NULL;
        }
        sendnotice(client, "AFK mode deactivated and message cleared.");
    }
}

CMD_FUNC(cmd_afk_message) {
    if (!MyUser(client) || IsULine(client)) return;
    if (parc < 2) {
        sendnotice(client, "Usage: /afk-message <message>");
        return;
    }
    if (strlen(parv[1]) > MAX_AFK_MESSAGE_LENGTH) {
        sendnotice(client, "AFK message is too long. Please use a message shorter than 256 characters.");
        return;
    }
    UserAFKInfo *info = CLIENT_AFK_INFO(client);
    if (!info) {
        info = safe_alloc(sizeof(UserAFKInfo));
        moddata_client(client, afkmod).ptr = info;
    }
    if (info->message) {
        free(info->message);
    }
    info->message = strdup(parv[1]);
    sendnotice(client, "AFK message set.");
}
