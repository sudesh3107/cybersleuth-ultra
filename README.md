# 🔍 CyberSleuth Ultra v4.0

> Advanced Multi-Source OSINT & Vulnerability Assessment Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Version](https://img.shields.io/badge/Version-4.0-purple)

---

⚠️ **For authorized security testing only. Never scan targets without explicit written permission.**

---

## What changed in v4.0

v3.0 had accuracy problems that are fixed here:

| Problem in v3 | Fix in v4 |
|---|---|
| Banner grab for TLS ports returned the fake literal `[HTTPS]` | Real TLS handshake + HTTP banner is pulled (status line + Server header) |
| `.env` check flagged any page containing `=` (nearly every HTML page) | `.env` bodies are validated as real `KEY=VALUE` files with secret-like keys |
| Sensitive-file discovery trusted `HEAD 200` (false positives on any server answering HEAD) | High-signal files (`.git/HEAD`, `.env`, `.htpasswd`, `phpinfo.php`…) are GET-verified with content checks; soft-404 HTML pages are rejected |
| `.git` / `.env` / WAF checks only tried `http://` (missed https-only sites) | All checks try both schemes |
| ASN lookup crashed on IPv6 addresses | IPv6 support via `origin6.asn.cymru.com` |
| Open redirect / TRACE (XST) not tested | Two new vulnerability-engine checks |
| Brute-forced subdomains polluted by wildcard DNS zones | Wildcard DNS detection — brute force is skipped when a wildcard resolves |
| No passive subdomain source beyond crt.sh/HackerTarget | Wayback Machine CDX index added |
| HTML report only showed vulns/ports/subs/files | Full report: DNS, security headers, tech stack, WAF, email security, ASN, Shodan, VirusTotal, admin panels, takeover candidates |
| Report interpolation was raw HTML (XSS-unsafe) | All dynamic content is HTML-escaped |
| Duplicate vulnerabilities possible | Engine de-duplicates by (name, evidence) |
| No way to control load | `--threads`, `--timeout`, `--passive`, `--quick`, `--max-subdomains` flags |

---

## Features

| Module | Capability |
|--------|-----------|
| 🌐 DNS | Full record enumeration (A, AAAA, MX, NS, TXT, CAA, DNSSEC, Zone Transfer test) |
| 🔎 Subdomains | Brute-force (wildcard-aware) + **crt.sh** + HackerTarget + **Wayback Machine** |
| 🚪 Ports | Common / Top-100 profiles with real banner grabbing (TLS-aware) and risk classification |
| 🔒 SSL/TLS | Grade A–F, expiry, SANs, weak ciphers, TLS version |
| 🛡️ Headers | 9-point security header audit with per-header remediation |
| 🧱 WAF | Detects 13 WAF vendors (Cloudflare, Akamai, Imperva, AWS WAF, etc.) |
| 🕵️ Tech Stack | CMS, frameworks, analytics, CDN via header + body fingerprinting |
| 📧 Email Security | SPF, DKIM, DMARC validation with vulnerability reporting |
| 🎣 Subdomain Takeover | 29 service fingerprints (GitHub Pages, Heroku, Netlify, AWS S3, Flywheel, OVH, etc.) |
| 📂 File Discovery | 60+ sensitive paths — GET-verified to avoid false positives, robots.txt Disallow entries folded in |
| 🔑 Admin Panels | Common admin/login/dashboard path discovery |
| 👤 Contact Harvesting | Email & phone number extraction from web pages |
| 🌍 ASN / BGP | Team Cymru DNS-based ASN, prefix, country, RIR lookup (IPv4 + IPv6) |
| 📡 WHOIS + RDAP | Registrar, dates, nameservers via both classic WHOIS and modern RDAP |
| ☁️ Shodan | Open ports, CVEs, OS, org, banner data (requires API key) |
| 🦠 VirusTotal | Reputation, malicious/suspicious scores (requires API key) |
| ⚡ Vuln Engine | 17 automated checks with CVSS scores, CWE mappings, de-duplication |
| 📊 Reports | Rich terminal output + dark-mode **HTML report** + JSON + **CSV** export |

---

## Installation

```bash
git clone https://github.com/sudesh3107/cybersleuth-ultra
cd cybersleuth-ultra
pip install -r requirements.txt
```

### Optional API Keys (set as environment variables)

```bash
export SHODAN_API_KEY=your_shodan_key
export VIRUSTOTAL_API_KEY=your_vt_key
```

Free keys available at [shodan.io](https://shodan.io) and [virustotal.com](https://virustotal.com).

---

## Usage

```bash
# Basic scan
python3 cybersleuth_ultra.py example.com

# Full scan with top 100 ports, save JSON + HTML + CSV report
python3 cybersleuth_ultra.py example.com --ports top100 --output report

# Scan an IP address
python3 cybersleuth_ultra.py 93.184.216.34 --ports common

# Passive-only scan (no requests to the target — DNS/WHOIS/RDAP/subdomains/APIs)
python3 cybersleuth_ultra.py example.com --passive

# Quick scan (skip contacts crawl, takeover, sitemap, brute-force)
python3 cybersleuth_ultra.py example.com --quick

# Tune load for slow targets
python3 cybersleuth_ultra.py example.com --threads 50 --timeout 10 --max-subdomains 200
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Domain or IP address to scan |
| `--ports common` | Scan ~25 most common ports (default) |
| `--ports top100` | Scan top 100 service ports |
| `--output BASENAME` | Save `BASENAME.json`, `BASENAME.csv` and `BASENAME.html` |
| `--json-only` | Skip HTML report |
| `--passive` | Passive-only: DNS, WHOIS, RDAP, subdomains (crt.sh/HackerTarget/Wayback), Shodan, VirusTotal — no active requests to the target |
| `--quick` | Skip heavy checks (contacts crawl, takeover check, sitemap, brute-force subs) |
| `--threads N` | Max concurrent workers (default 30) |
| `--timeout N` | Per-request timeout in seconds (default 8) |
| `--max-subdomains N` | Max subdomains to test for takeover (default 100) |
| `-v / --verbose` | Enable debug logging |

---

## Usage with exploit_integration

```bash
# 1. Feed the scan results into the exploit integration module
python3 exploit_integration.py --scan my_scan.json --output exploit_plan

# 2. Launch the auto-generated Metasploit script
msfconsole -r exploit_plan.rc

# 3. Or run SQLMap directly
sqlmap -u "http://192.168.1.100/?id=1" --batch --dbs

# 4. Or run Nikto
nikto -h 192.168.1.100 -p 80 -C all -output nikto_report.html

# Non-interactive (skip the confirmation prompt)
python3 exploit_integration.py --scan my_scan.json --yes
```

---

## Tests

```bash
pip install pytest
pytest tests/
```

---

## Sample Output

```
Target   : example.com
IP       : 93.184.216.34
ASN      : AS15133 — Edgecast Inc.
Network  : 93.184.216.0/24
WAF      : Cloudflare

Vulnerabilities: 2 Critical  |  4 High  |  6 Medium  |  3 Low

[High]  Missing Security Header: Strict-Transport-Security (CVSS 5.3)
[High]  Exposed .git Directory (CVSS 7.5) — CWE-538
[Medium] CORS Wildcard Origin (CVSS 5.4) — CWE-942
...
```

---

## Vulnerability Checks

- Exposed `.git` directory (GET-verified content)
- Environment file (`.env`) disclosure (KEY=VALUE content verified — no HTML false positives)
- Directory listing enabled
- CORS misconfiguration (wildcard, reflection, credential-wildcard)
- Missing security headers (HSTS, CSP, X-Frame-Options, COEP, COOP, etc.)
- SSL/TLS issues (expired, self-signed, weak ciphers, old TLS versions)
- Dangerous services exposed (Redis, MongoDB, Elasticsearch, RDP, etc.)
- Insecure cookie flags
- DNS zone transfer (AXFR)
- Clickjacking vulnerability
- Server version disclosure
- Missing SPF/DMARC email security records
- **HTTP TRACE enabled (XST)**
- **Open redirect**
- Shodan-reported CVEs
- VirusTotal malicious reputation
- Subdomain takeover candidates

---

## Legal Disclaimer

This tool is provided for **educational purposes and authorized security testing only**.  
Using this tool against systems you do not have explicit permission to test may violate:
- The Computer Fraud and Abuse Act (CFAA) — USA
- The Computer Misuse Act — UK
- Similar laws in your jurisdiction

The authors assume no liability for misuse.