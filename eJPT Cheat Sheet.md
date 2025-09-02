# Recon

## Banner Grabbing 

Netcat banner grab
```
nc 192.105.220.2 22
```

NMAP Banner Grab
```
nmap -sV --script=banner 192.8.94.3
```



# Vulnerability Scanning 

Search for NMAP vulnerability scripts
```
ls -al /usr/share/nmap/scripts | grep vuln
```
