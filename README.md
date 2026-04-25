# ReconX — All-in-One Bug Bounty Recon Tool

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Termux-lightgrey.svg)](#)

**ReconX** is a modular, threaded reconnaissance scanner for **ethical hacking, bug bounty, and authorized penetration testing**.  
It automates subdomain discovery, port scanning, web fingerprinting, directory fuzzing, sensitive file checks, and basic vulnerability detection (SQLi, XSS) — all from a single command.

---

## ⚠️ LEGAL NOTICE
Use this tool **only on systems you own or have explicit written permission to test**.  
Unauthorized scanning is illegal under the **Computer Fraud and Abuse Act (CFAA)** and similar laws worldwide.  
**The author assumes no liability for misuse or damage.**  
**Do not run this against domains you don't own or haven't been authorized to test.**

---

## Features

- **WHOIS Lookup** — Registrant, dates, name servers.
- **DNS Enumeration** — A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV.
- **Subdomain Brute-force** — Built‑in wordlist (100+ entries) + custom file support.
- **Port Scanner** — 45 common ports with basic banner grab & SSL certificate extraction.
- **Tech Fingerprinting** — Detects frameworks, CMS, server headers, missing security headers, insecure cookies.
- **Directory & File Fuzzing** — Over 120 built‑in paths; respects `robots.txt` (optional); status‑code filtering.
- **Nikto‑like Sensitive Checks** — `.git/config`, `.env`, `phpinfo.php`, `backup.sql`, admin panels, and more.
- **Database Error Detection** — Triggers SQL errors and fingerprints backend DBMS.
- **SQL Injection Scanner** — Error‑based + optional **blind (time‑based)** detection.
- **Reflected XSS Scanner** — Multiple payloads for classic reflected cross‑site scripting.
- **Broken Link Checker** — Identifies dead links on the target page.
- **JSON Report** — All findings saved to a timestamped JSON file.
- **Performance & Safety** — Configurable threads, random request delay, proxy support, custom cookies, scope control, SSL verification toggle.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Wolfnation01/Reconx-tool.git
cd Reconx-tool

# Install dependencies
pip install -r requirements.txt

# Quickstart
# Full scan on a domain
python reconx.py -t example.com

# Scan with GET parameters (enables SQLi + XSS)
python reconx.py -t "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Run only specific modules
python reconx.py -t example.com --only-ports --ports 22,80,443

# Skip slow modules for faster recon
python reconx.py -t example.com --skip-sub --skip-links

# Use proxy + random delay to avoid WAF bans
python reconx.py -t example.com --proxy http://127.0.0.1:8080 --delay 0.5

# Respect robots.txt and set scope
python reconx.py -t example.com --robots --scope "example.com,*.dev.example.com"

# Save a JSON report
python reconx.py -t example.com -o myreport.json

#For termux users
pkg install python clang libxml2 libxslt
pip install -r requirements.txt

