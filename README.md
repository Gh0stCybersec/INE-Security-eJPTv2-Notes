<p align="center">
  <img src="https://raw.githubusercontent.com/Gh0stCybersec/INE-Security-eJPTv2-Notes/main/eJPTv2_Logo.png" alt="eJPTv2 Logo" width="200">
</p>

# INE Security eJPTv2 

The eJPT (eLearnSecurity Junior Penetration Tester) is a penetration testing certification that tests practical skills in network and web application security, vulnerability assessment, and exploitation. 

To help clear some confusion around the versioning of this certification, this is the second version of the eJPT (hence eJPT
V2). 

It’s no longer under eLearnSecurity because eLearnSecurity was acquired by INE (Internetwork Expert). INE has rebranded and integrated eLearnSecurity’s certifications under its own platform. The exam and training remain, but they’re now managed and delivered by INE instead of the old eLearnSecurity brand. Hopefully that clears it up :) 

## Blog 

I have written a blog post on the exam including a general review and some tips. 

Please see the blog post at my security blog [Ghost Bit Security](https://ghostbitsecurity.com/)


## eJPTv2 Exam and Training Overview

- 📄 **[MY EJPT Cheat Sheet](https://github.com/Gh0stCybersec/INE-Security-eJPTv2-Notes/blob/main/eJPT%20Cheat%20Sheet.md)**  

The recommeneded training featured on the INE website is the Penetration Testing Student learning path which consists of 153h of video to consume. As well as 108 different labs. Not all of these need to be completed (see below) as some are duplicate labs and some are just flat out not required. The training for the exam is broken up into 4 main sections 

- **Assessment Methodologies** – ⏱️ 25h  
- **Host & Networking Auditing** – ⏱️ 2h  
- **Host & Network Penetration Testing** – ⏱️ 113h  
- **Web Application Penetration Testing** – ⏱️ 9h  

The exam itself has a time limit of 48 hours and a set of 35 different question (multiple choice)

The exam is not meant to be a CTF but to simulate a real penetration test! 

To pass the eJPT, you must receive an overall exam score of at least 70%.

## eJPTv2 Exam and Study Tips

Training to Skip:
If you follow the recommended learning path you can skip the following modules.

- **Phishing with GoPhish** ❌
- **Armitage** ❌ *(pretty much a dead project)*
- **PowerShell Empire** ❌ *(Social Engineering section)*

### General Tips 
- Group all questions together that relate to the same server and answer them before moving on 
- **Use the exclusion method** for Multi-choice questions. You know there’s only one right answer, so the other three must be wrong.
   - crucial to submit the flags as soon as you find it as they change after each reset.
   -  Make yourself familiar with Webdev platforms like "Drupal" and "Wordpress" and how to attack those.
	- Make sure to use WPSCAN
- There are 5–6 machines in DMZ and 1–2 machines in the internal network
- Just make sure you've completed the INE labs and maybe one or two machines to exploit WordPress and Drupal.
- Hydra is important, especially with Rockyou.
- For directory scanning use dirbuster not metasploit with /usr/share/wordlist/dirb/common.txt


## Useful links 

Below are some useful links for the Exam. 

## eJPT Exam Resources

- 📄 **[MY EJPT Cheat Sheet](https://github.com/Gh0stCybersec/INE-Security-eJPTv2-Notes/blob/main/eJPT%20Cheat%20Sheet.md)**  
  Collection of most of the useful commands and tricks needed to pass. 
  
- 📄 **[Lab Guidelines](https://drive.google.com/file/d/1KN7pB3trLNSk1jhUMrUAEkmbmyJsuJz0/view)**  
  Learn how the exam lab works, including troubleshooting tips and setup instructions.

- ✉️ **[Letter of Engagement](https://drive.google.com/file/d/1Kc2pcgJgTJDQMiToYMJk21fNOQHykjL3/view)**  
  Overview of the scope of engagement, exam objectives, and recommended tools.


## Try Hack Me Machines 

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


## Other Reasources 

List of Useful websites 
- [**CrackStation**](https://crackstation.net/)
- [**CyberChef**](https://cyberchef.org/)
- [**GTFOBins**](https://gtfobins.github.io/)  - great for privledge escalation
- [**HackTricks**](https://book.hacktricks.xyz/)
- [**Hash Analyzer**](https://www.tunnelsup.com/hash-analyzer/)
- [**Nmap NSE Doc**](https://nmap.org/nsedoc/scripts/)
- [**PayLoadAllTheThing**s](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [**Reverse Shell Generator**](https://www.revshells.com/)
- [**Upgrade a Linux reverse shell to a fully usable TTY shell**](https://zweilosec.github.io/posts/upgrade-linux-shell/)
