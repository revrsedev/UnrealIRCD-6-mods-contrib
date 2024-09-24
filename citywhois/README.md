# CITYWHOIS
### ADD THE CITY OF THE USER ON THE WHOIS 320.

### ADD to unrealircd.conf path to database
```

loadmodule "third/citywhois";

citywhois {
    db "/x/GeoLite2-City.mmdb";
}