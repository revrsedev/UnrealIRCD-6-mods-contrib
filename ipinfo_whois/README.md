# IPINFO_WHOIS
### Show IPinfo.io information in /WHOIS - https://ipinfo.io/
### Info:
### add libs required on Ubuntu/Debian you need to 'apt install uthash-dev' (caches usage)
# This module cache's the ip information of the user for 24hs so you're server don't get rate limited or in bigs networks bottleneck's network I/O and processing time for each request.

```
time_t cache_duration = 86400; // 24 hours
```
For 1 hour: time_t cache_duration = 3600;<br>
For 2 hours: time_t cache_duration = 7200;<br>
For 24 hours: time_t cache_duration = 86400;<br>

### Add the Ipinfo.io Token here

```
ipinfo_whois {
    apikey "YOUR_API_KEY";
}
```
## Usage

```
 /whois reverse

 Output:

 * musk is connecting from City: Lyon, Region: Auvergne-Rhône-Alpes, Country: FR, Org: AS1554 Societe Francaise Du Radiotelephone - SFR SA

```
# Obs: Only visible by irc operators.

## THANKS TO GOTTEM'S TEMPLATES

Come and say hi at:<br>
Server: irc.tchatzone.fr:+6697<br> 
Channel: #dev
