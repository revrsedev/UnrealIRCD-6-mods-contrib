/*
  Licence: GPLv3 or later
  Copyright Ⓒ 2024 Jean Chevronnet
  
*/
/*** <<<MODULE MANAGER START>>>
module
{
    documentation "https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_listsg/README.md";
    troubleshooting "In case of problems, documentation or e-mail me at mike.chevronnet@gmail.com";
    min-unrealircd-version "6.*";
    post-install-text {
        "The module is installed, now all you need to do is add a 'loadmodule' line to your config file:";
        "loadmodule \"third/m_listsg\";";
        "Then /rehash the IRCd.";
        "For usage information, refer to the module's documentation found at: https://github.com/revrsedev/UnrealIRCD-6-mods-contrib/blob/main/m_listsg/README.md";
    }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"

#define MSG_SG "SG"
#define MAX_BUFFER_SIZE 512
#define MAX_NICKNAMES_PER_LINE 10

CMD_FUNC(cmd_sg);

// Forward declarations
void list_security_groups_for_user(Client *client, Client *user);
void list_members_of_security_group(Client *client, const char *groupname);

ModuleHeader MOD_HEADER = {
    "third/m_listsg",   // Module name
    "1.0",              // Version
    "Command /SG to list security groups and their members", // Description
    "reverse",          // Author
    "unrealircd-6",     // UnrealIRCd version
};

MOD_INIT() {
    CommandAdd(modinfo->handle, MSG_SG, cmd_sg, 1, CMD_USER); // Adding the command
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    return MOD_SUCCESS;
}

CMD_FUNC(cmd_sg) {
    if (parc < 2) {
        sendnotice(client, "Usage: /SG <nickname|groupname>");
        return;
    }

    const char *arg = parv[1];
    Client *target_user = find_client(arg, NULL);
    if (target_user) {
        list_security_groups_for_user(client, target_user);
    } else {
        list_members_of_security_group(client, arg);
    }
}

// Function to list security groups a user is part of
void list_security_groups_for_user(Client *client, Client *user) {
    const char *groups = get_security_groups(user);
    if (!groups || *groups == '\0') {
        sendnotice(client, "User %s is not part of any security groups.", user->name);
        return;
    }

    sendnotice(client, "Security groups for user %s:", user->name);
    sendnotice(client, "- %s", groups);
}

// Function to list members of a security group
void list_members_of_security_group(Client *client, const char *groupname) {
    SecurityGroup *group = find_security_group(groupname);
    if (!group) {
        sendnotice(client, "Security group %s does not exist.", groupname);
        return;
    }

    sendnotice(client, "Members of security group %s:", groupname);

    Client *target;
    int member_found = 0;
    char buffer[MAX_BUFFER_SIZE];
    buffer[0] = '\0';
    int nickname_count = 0;

    list_for_each_entry(target, &lclient_list, lclient_node) {
        if (user_allowed_by_security_group_name(target, groupname)) {
            if (nickname_count > 0) {
                strlcat(buffer, ", ", sizeof(buffer));
            }
            strlcat(buffer, target->name, sizeof(buffer));
            nickname_count++;
            member_found = 1;

            // Check if the buffer is near its limit or if we reached the max nicknames per line
            if (strlen(buffer) >= MAX_BUFFER_SIZE - 50 || nickname_count >= MAX_NICKNAMES_PER_LINE) {
                sendnotice(client, "- %s", buffer);
                buffer[0] = '\0'; // Reset buffer
                nickname_count = 0; // Reset nickname count
            }
        }
    }

    // Send any remaining nicknames in the buffer
    if (nickname_count > 0) {
        sendnotice(client, "- %s", buffer);
    }

    if (!member_found) {
        sendnotice(client, "Security group %s has no members.", groupname);
    }
}
