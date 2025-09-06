# Exam Tips:

ENSURE I PUT THE DRUPAL NOTES HERE
# Recon

# Passive Information Gathering  

## Whois

```
whois <HOST>
whois <IP>
```
## Google Dorking

```
# Targeted site queries
site:target.com                                  # Limits search results to a specific site
site:*.target.com                                # Includes subdomains in search

# Admin panels and login pages
site:*.target.com inurl:login                    # Find login pages
site:*.target.com inurl:admin                    # Find admin pages
site:*.target.com intitle:admin                  # Pages with "admin" in title

# Directory listings / exposed files
site:*.target.com intitle:"index of"            # Directory listing pages
intitle:"index of" "credentials"                # Directories exposing credentials
site:*.target.com inurl:backup                   # Backup files or directories
site:*.target.com inurl:db                       # Database-related files
site:*.target.com inurl:config                   # Configuration files
site:*.target.com inurl:.git                     # Exposed git repositories
site:*.target.com inurl:.env                     # Exposed environment files

# Sensitive files by type
site:*.target.com filetype:pdf                   # PDF files
site:*.target.com filetype:docx                  # Word documents
site:*.target.com filetype:xlsx                  # Excel files
site:*.target.com filetype:sql                   # SQL database dumps
site:*.target.com filetype:log                   # Log files
site:*.target.com filetype:bak                   # Backup files
site:*.target.com filetype:zip                   # Compressed archives

# Passwords / authentication
site:*.target.com inurl:password                 # Password files
site:*.target.com inurl:auth_user_file.txt       # Exposed password directories

# Employees & internal information
site:*.target.com employees                       # Find employee info
site:*.target.com intitle:"staff"                # Staff pages
site:*.target.com intitle:"team"                 # Team pages

# Sitemap / hidden pages
inurl:"robots.txt"                                # Locate robots.txt for hidden pages
inurl:"sitemap.xml"                               # Sitemap info for site structure

# Misc useful searches
site:*.target.com "admin"                        # Pages mentioning "admin"
site:*.target.com "login"                        # Pages mentioning "login"
site:*.target.com "dashboard"                    # Pages with dashboards
site:*.target.com "contact"                      # Contact pages (sometimes lead to emails)
site:*.target.com "internal"                     # Look for internal info
site:*.target.com "confidential"                 # Search for confidential mentions
```

## Email Harvesting 

Using the Harvestor - attempted to use but not really any use.
```
theharvester -d target.com -b all                  # Harvest emails from all available sources
theharvester -d target.com -b linkedin             # Collect employees/emails from LinkedIn
theharvester -d target.com -b pgp                  # Search PGP key servers for emails
```
## Subdomain Enumeration 

This isn't 100% success as the domains might be unindexed etc. 

However still useful to gather information before actively engaging with the target.

https://github.com/aboul3la/Sublist3r

```
sublist3r -d hackersploit.org 
```

## Typical Sub Directories 

```
/robots.txt
/sitemap.xml
/admin/
/admin.php/
/admin.html/
/admin/login/
/login/
/login.php/
/login.html/
/administrator/
/administrator.php/
/administrator/login/
/adminpanel/
/adminpanel.php/
/controlpanel/
/cp/
/cpanel/
/dashboard/
/dashboard.php/
/useradmin/
/backend/
/manager/
/portal/
/wp-admin/
/administrator/
/user/login/
/admin123/
/phpmyadmin/
/pma/
```

## Website Fingerprinting 

The following two tools are browser extensions that can be used to fingerprint websites. The CLI versions of these can be considered active however. 
https://builtwith.com/
https://www.wappalyzer.com/
- **Extension = Passive**
- **CLI/API = Active**

# Active Information Gathering 

## Ping Sweep

Fping 
```
fping -a -g 10.10.23.0/24 2>/dev/null   # Fping is faster than a standard ping for a subnet sweep
```

Nmap
```
nmap -sn 192.168.1.1      # Pings all IPs within the subnet and shows only those that respond
```
## Host Discovery 

Nmap
```
nmap -sn -v -T4 10.2.4.5   # Only tells you whether the host is up; does NOT scan ports; uses verbose and faster scanning flags
```

```
nmap -sn -PS21,22,25,80,445,3389,8080 -PU137,138 -T4 10.2.4.5   # Quick scan focusing on likely exploitable ports for the exam
```

## Banner Grabbing 

Netcat banner grab
```
nc 192.105.220.2 22   # Connects to port 22 and retrieves the banner (service/version info)
```

Nmap Banner Grab
```
nmap -sV --script=banner 192.8.94.3   # Uses Nmap service/version detection and banner script to get service info
```


## DNS Enumeration

DNS Dumpster - Tool that will finds subdomains, IPs, mail servers, and DNS records of a target domain.
https://dnsdumpster.com/

DNSrecon

```
dnsrecon -d hackersploit.org
```
## Directory Brute Force


Gobuster

```
# Basic directory scan
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt   # Scan directories

# Scan for specific file extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt   # Scan php, html, txt files

# Save results
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt   # Save to file
```

Dirbuster 

```
# Basic directory scan
dirb http://target.com /usr/share/wordlists/dirb/common.txt   # Scan target.com using common wordlist

# Scan for specific file extensions
dirb http://target.com /usr/share/wordlists/dirb/common.txt -X .php,.html,.txt   # Scan php, html, txt files

# Recursive scan (scan discovered directories)
dirb http://target.com /usr/share/wordlists/dirb/common.txt -r   # Recursively scan directories

# Save results to a file
dirb http://target.com /usr/share/wordlists/dirb/common.txt -o dirb_results.txt   # Save output to file
```


## WAF Detection


```
wafw00f hackersploit.org -a   # Detects Web Application Firewalls (WAFs)  "-a" tests for all possible WAF instances
```


## Active Subdomain

Sublister 

```
sublist3r -d target.com -b brute                  # Enable DNS brute force (active)
```

Amass

```
amass enum -active -d target.com                 # Active enumeration with brute force / DNS resolution
```


## DNS Zone Transfer 

Zone transfers may discover internal IP addresses 
You will often find that corporate networks will misconfigure networks and leak internal address space - which can be useful for targeting with malware

```
nmap --script=dns-zone-transfer -p 53 target.com
```

```
fierce -dns zonetransfer.me 
fierce --domain hackersploit.org 
```

Can also perform with host - l   Give the domain name and then the nameserver of the site 
```
host -l  zonetransfer.me nsztm.digi.ninja.  
```

Same can be performed with dig - use this as its most preferred as it doesn't do the brute force 
```
dig axfr @nsztm1.digi.ninja  zonetransfer.me     
```
