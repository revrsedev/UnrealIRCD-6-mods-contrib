# IPDENT
### Change the ident of the user based on their ips+hash and user-defined cloak key in config.

### GENERATE CLOAK KEYS WITH

```
 ./unrealircd gencloak
```
### ADD to unrealircd.conf max of 5 keys
```
cloak-ident-keys {
    key "yY90gBRfJMSqN45WSLM9ttPQB57cVJbTN3nkDi5ZwGtXwn4pZ9JcJFGNwtJX82W8mBBXzJxUXPxwkMNJaP9fXcrxz7ApihCBp3YUt2TSAWp4TFTRfmQBAvHCc";
    key "8ed78KM7yhyS8E2SDrVX9t7c8CYQ2YKcQrVff5Keg9dpp6BgTzPE4Jk9wA99HcMShmwp3ntZnnunuzUBwtJuQqMaXTBD8XuVRg3eVGgGARqxHy4YfYMXEnbxY";
    key "RcsG6RXNZZitkdtuhvzGVpY6cHEFdvAWunFnbSvEzJhV3zCrSYG56HiQaT3ES5TFc4YywgaZVxepyQBNWcvtD2U3ddG4rCKanZPjV6TMT4jg6YrbQ4dMvHRit";
};

```

## DO NOT USE THIS ONES

## THANKS TO GOTTEM'S TEMPLATES

https://gitgud.malvager.net/Wazakindjes/unrealircd_mods/src/branch/master/templates/conf.c