usage: reconx [-h] -t TARGET [-o OUTPUT] [--threads THREADS] [--timeout TIMEOUT] [--delay DELAY] [--ports PORTS] [--verify-ssl] [--proxy PROXY] [--cookies COOKIES]
              [--user-agent USER_AGENT] [--verbose] [--progress] [--scope SCOPE] [--robots] [--dir-status DIR_STATUS] [--sub-wordlist SUB_WORDLIST]
              [--dir-wordlist DIR_WORDLIST] [--sqli-blind] [--skip-whois] [--skip-dns] [--skip-sub] [--skip-ports] [--skip-tech] [--skip-dirs] [--skip-links]
              [--skip-nikto] [--skip-db] [--skip-sqli] [--skip-xss] [--only-whois] [--only-ports] [--only-sub] [--only-dirs] [--only-sqli] [--only-xss] [--only-nikto]

ReconX — All-in-One Bug Bounty & Recon Scanner

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Domain or URL (e.g., example.com or http://example.com)
  -o, --output OUTPUT   Save JSON report to file (auto-named if omitted)
  --threads THREADS     Concurrent threads (default: 30)
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  --delay DELAY         Random delay between requests (0‑N seconds)
  --ports PORTS         Comma-separated ports to scan
  --verify-ssl          Enable SSL verification
  --proxy PROXY         Proxy URL (http://127.0.0.1:8080)
  --cookies COOKIES     Cookies (semicolon‑separated)
  --user-agent USER_AGENT                                                                                                                                                                         Custom User‑Agent
  --verbose             Show detailed error messages
  --progress            Show progress bars (needs tqdm)                                                                                                                     --scope SCOPE         Comma‑separated list of in‑scope domains/IPs
  --robots              Respect robots.txt disallowed paths                                                                                                                 --dir-status DIR_STATUS
                        Filter HTTP status codes for dir brute (comma‑separated)                                                                                            --sub-wordlist SUB_WORDLIST
                        Additional subdomain wordlist file                                                                                                                  --dir-wordlist DIR_WORDLIST
                        Additional directory wordlist file                                                                                                                  --sqli-blind          Enable time‑based SQLi detection
                                                                                                                                                                          skip modules:
  --skip-whois
  --skip-dns
  --skip-sub
  --skip-ports
  --skip-tech
  --skip-dirs
  --skip-links
  --skip-nikto
  --skip-db
  --skip-sqli
  --skip-xss

only (run specific module, skip all others):
  --only-whois
  --only-ports
  --only-sub
  --only-dirs
  --only-sqli
  --only-xss
  --only-nikto

Examples:
  Full scan:          python reconx.py -t example.com
  With params:        python reconx.py -t "http://example.com?id=1"
  Custom ports:       python reconx.py -t example.com --only-ports --ports 22,80,443
  Skip slow modules:  python reconx.py -t example.com --skip-sub --skip-links
  Save report:        python reconx.py -t example.com -o results.json
Legal: Only test systems you own or have written authorization to test.
      Unauthorised use is illegal.

