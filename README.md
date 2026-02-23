# 🔍 CyberSleuth Ultra v3.0

> Advanced Multi-Source OSINT & Vulnerability Assessment Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.0-purple)

---

⚠️ **For authorized security testing only. Never scan targets without explicit written permission.**

---

## Features

| Module | Capability |
|--------|-----------|
| 🌐 DNS | Full record enumeration (A, AAAA, MX, NS, TXT, CAA, DNSSEC, Zone Transfer test) |
| 🔎 Subdomains | Brute-force + **crt.sh** Certificate Transparency + HackerTarget API |
| 🚪 Ports | Common / Top-100 profiles with banner grabbing and risk classification |
| 🔒 SSL/TLS | Grade A–F, expiry, SANs, weak ciphers, TLS version |
| 🛡️ Headers | 9-point security header audit with per-header remediation |
| 🧱 WAF | Detects 11 WAF vendors (Cloudflare, Akamai, Imperva, AWS WAF, etc.) |
| 🕵️ Tech Stack | CMS, frameworks, analytics, CDN via header + body fingerprinting |
| 📧 Email Security | SPF, DKIM, DMARC validation with vulnerability reporting |
| 🎣 Subdomain Takeover | 20 service fingerprints (GitHub Pages, Heroku, Netlify, AWS S3, etc.) |
| 📂 File Discovery | 50+ sensitive file paths (.env, .git, backups, configs, logs) |
| 🔑 Admin Panels | Common admin/login/dashboard path discovery |
| 👤 Contact Harvesting | Email & phone number extraction from web pages |
| 🌍 ASN / BGP | Team Cymru DNS-based ASN, prefix, country, RIR lookup |
| 📡 WHOIS + RDAP | Registrar, dates, nameservers via both classic WHOIS and modern RDAP |
| ☁️ Shodan | Open ports, CVEs, OS, org, banner data (requires API key) |
| 🦠 VirusTotal | Reputation, malicious/suspicious scores (requires API key) |
| ⚡ Vuln Engine | 15+ automated checks with CVSS scores and CWE mappings |
| 📊 Reports | Rich terminal output + dark-mode **HTML report** + JSON export |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/cybersleuth-ultra.git
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
python cybersleuth_ultra.py example.com

# Full scan with top 100 ports, save JSON + HTML report
python cybersleuth_ultra.py example.com --ports top100 --output report

# Scan an IP address
python cybersleuth_ultra.py 93.184.216.34 --ports common

# Save JSON only
python cybersleuth_ultra.py example.com --output results --json-only
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Domain or IP address to scan |
| `--ports common` | Scan ~25 most common ports (default) |
| `--ports top100` | Scan top 100 service ports |
| `--output BASENAME` | Save `BASENAME.json` and `BASENAME.html` |
| `--json-only` | Skip HTML report |
| `-v / --verbose` | Enable debug logging |

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

## Requirements

- Python 3.10+
- See `requirements.txt` for full dependency list

Core dependencies: `requests`, `rich`, `dnspython`  
Optional (for full functionality): `python-whois`, `shodan`, `builtwith`, `beautifulsoup4`

---

## Vulnerability Checks

- Exposed `.git` directory
- Environment file (`.env`) disclosure
- Directory listing enabled
- CORS misconfiguration (wildcard, reflection, credential-wildcard)
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS issues (expired, self-signed, weak ciphers, old TLS versions)
- Dangerous services exposed (Redis, MongoDB, Elasticsearch, RDP, etc.)
- Insecure cookie flags
- DNS zone transfer (AXFR)
- Clickjacking vulnerability
- Server version disclosure
- Missing SPF/DMARC email security records
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

---

## License

MIT License — see [LICENSE](LICENSE) for details.
