#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          CyberSleuth Ultra - Advanced OSINT & VA Scanner      ║
║   Version 3.0 | Author: github.com/sudesh3107/cybersleuth     ║
║  ⚠  FOR AUTHORIZED SECURITY TESTING ONLY - USE RESPONSIBLY   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import ssl
import json
import time
import socket
import asyncio
import logging
import hashlib
import ipaddress
import argparse
import threading
from datetime import datetime, timezone
from typing import Optional, Union
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from functools import wraps
from collections import defaultdict

# ── Third-party imports ─────────────────────────────────────────
try:
    import requests
    import requests.adapters
    from requests.packages.urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] Missing: pip install requests")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.align import Align
except ImportError:
    sys.exit("[!] Missing: pip install rich")

try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    import dns.exception
except ImportError:
    sys.exit("[!] Missing: pip install dnspython")

# Optional imports (graceful degradation)
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import OpenSSL.crypto
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

import warnings
warnings.filterwarnings("ignore")

# ── Console & Logging Setup ──────────────────────────────────────
console = Console(highlight=True)
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log = logging.getLogger("cybersleuth")


# ═══════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════

@dataclass
class Vulnerability:
    name: str
    severity: str          # Critical / High / Medium / Low / Info
    cvss: float
    description: str
    evidence: str
    remediation: str
    cwe: str = ""
    references: list = field(default_factory=list)

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    banner: str = ""
    version: str = ""

@dataclass
class SSLInfo:
    valid: bool
    issuer: str = ""
    subject: str = ""
    expiry: str = ""
    days_remaining: int = 0
    self_signed: bool = False
    weak_cipher: bool = False
    tls_version: str = ""
    san_domains: list = field(default_factory=list)
    grade: str = ""

@dataclass
class HeaderAudit:
    present: bool
    value: str = ""
    secure: bool = False
    recommendation: str = ""

@dataclass
class ScanResults:
    target: str
    ip_address: str = ""
    asn_info: dict = field(default_factory=dict)
    whois_info: dict = field(default_factory=dict)
    rdap_info: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    ssl_info: dict = field(default_factory=dict)
    http_headers: dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)
    technologies: dict = field(default_factory=dict)
    waf_detected: str = ""
    emails: list = field(default_factory=list)
    phone_numbers: list = field(default_factory=list)
    sensitive_files: list = field(default_factory=list)
    admin_panels: list = field(default_factory=list)
    robots_txt: str = ""
    sitemap_urls: list = field(default_factory=list)
    spf_record: str = ""
    dkim_record: str = ""
    dmarc_record: str = ""
    shodan_data: dict = field(default_factory=dict)
    virustotal_data: dict = field(default_factory=dict)
    subdomain_takeover: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    scan_metadata: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

class Config:
    """Centralized, environment-aware configuration."""

    # API Keys — loaded from env vars, NEVER hardcoded
    SHODAN_KEY: str    = os.getenv("SHODAN_API_KEY", "")
    VT_KEY: str        = os.getenv("VIRUSTOTAL_API_KEY", "")

    USER_AGENT: str    = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
    TIMEOUT: int       = 8
    MAX_WORKERS: int   = 30          # Controlled concurrency (not cpu*2 everywhere)
    MAX_RETRIES: int   = 2
    RATE_LIMIT_DELAY: float = 0.05   # Seconds between requests per host
    VERIFY_SSL: bool   = False        # Skip SSL verification for targets (intentional)
    FOLLOW_REDIRECTS: bool = True
    MAX_CRAWL_DEPTH: int = 2
    MAX_CRAWL_PAGES: int = 20

    # Port lists
    TOP_100_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 135, 139, 143, 389,
        443, 445, 465, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723,
        2049, 2181, 3000, 3306, 3389, 3690, 4000, 4443, 4848, 5000, 5432,
        5601, 5900, 5984, 6379, 6443, 7001, 7443, 7474, 8000, 8001, 8008,
        8080, 8081, 8082, 8088, 8090, 8161, 8181, 8443, 8444, 8888, 8983,
        9000, 9090, 9200, 9300, 9418, 9443, 10000, 11211, 15672, 27017,
        27018, 28017, 50000, 50070, 61616,
    ]

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    ]

    # Wordlists
    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
        "app", "cdn", "cloud", "db", "demo", "git", "m", "mobile", "new",
        "old", "secure", "shop", "beta", "vpn", "web", "ns1", "ns2",
        "smtp", "pop", "imap", "static", "assets", "media", "img", "video",
        "docs", "help", "support", "portal", "dashboard", "login", "auth",
        "sso", "sts", "remote", "internal", "intranet", "corp", "office",
        "store", "checkout", "payment", "gateway", "proxy", "relay",
        "autodiscover", "autoconfig", "cpanel", "whm", "phpmyadmin",
        "mysql", "postgres", "redis", "mongo", "elastic", "kibana",
        "grafana", "jenkins", "ci", "cd", "deploy", "prod", "production",
        "uat", "qa", "sandbox", "preview", "stage", "preprod",
        "backup", "archive", "legacy", "old2", "v2", "v3", "api2",
        "download", "upload", "files", "data", "reports", "analytics",
        "tracking", "metrics", "monitoring", "status", "health",
    ]

    SENSITIVE_FILES = [
        # Config files
        ".env", ".env.local", ".env.production", ".env.backup",
        ".htaccess", ".htpasswd", "web.config", "config.php",
        "config.yml", "config.yaml", "configuration.php",
        "settings.php", "settings.py", "application.properties",
        "database.yml", "database.php", "db.php",
        # Credentials
        "credentials.txt", "credentials.json", "secrets.json",
        "password.txt", "passwords.txt", "keys.txt",
        # Source control
        ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
        ".svn/entries", ".hg/hgrc",
        # Server info
        "phpinfo.php", "info.php", "server-status", "server-info",
        "test.php", "debug.php",
        # Backups
        "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
        "database.sql", "db.sql", "site.zip", "www.zip",
        # CMS
        "wp-config.php", "wp-config.php.bak", "wp-login.php",
        "xmlrpc.php", "joomla.xml", "configuration.php",
        # Common disclosure
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "clientaccesspolicy.xml", "security.txt", ".well-known/security.txt",
        "CHANGELOG.txt", "CHANGELOG.md", "VERSION", "README.md",
        "composer.json", "package.json", "requirements.txt",
        "Gemfile", "Dockerfile", "docker-compose.yml",
        # Logs
        "debug.log", "error.log", "access.log", "app.log",
        "laravel.log", "application.log",
    ]

    ADMIN_PATHS = [
        "admin", "admin/", "admin/login", "admin/index.php",
        "administrator", "administrator/", "wp-admin", "wp-login.php",
        "backend", "manager", "cms", "login", "signin",
        "controlpanel", "cp", "dashboard", "console",
        "panel", "manage", "management", "user/login",
        "phpmyadmin", "pma", "dbadmin", "myadmin",
        "joomla/administrator", "typo3", "django-admin",
        "rails/info", "admin.php", "admincp", "moderator",
    ]

    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF":    ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai":     ["akamai", "akamai-ghost", "x-akamai-transformed"],
        "Sucuri":     ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "Incapsula":  ["incap_ses", "visid_incap", "x-iinfo"],
        "ModSecurity":["mod_security", "modsecurity", "x-modsec"],
        "F5 BIG-IP":  ["bigip", "f5-", "x-wa-info"],
        "Imperva":    ["imperva", "x-cdn"],
        "Barracuda":  ["barracuda_", "barra_counter_session"],
        "Nginx":      ["x-nginx-proxy"],
        "Wordfence":  ["wordfence"],
    }

    TAKEOVER_FINGERPRINTS = {
        "GitHub Pages":       "There isn't a GitHub Pages site here",
        "Heroku":             "No such app",
        "Shopify":            "Sorry, this shop is currently unavailable",
        "Fastly":             "Fastly error: unknown domain",
        "Ghost":              "The thing you were looking for is no longer here",
        "Surge":              "project not found",
        "Bitbucket":          "Repository not found",
        "Azure":              "404 Web Site not found",
        "Netlify":            "Not Found - Request ID",
        "Pantheon":           "The gods are wise",
        "WordPress.com":      "Do you want to register",
        "Tumblr":             "Whatever you were looking for doesn't live here",
        "AWS S3":             "NoSuchBucket",
        "Cargo":              "If you're moving your domain away from Cargo",
        "Readme.io":          "Project doesnt exist... yet",
        "Helpjuice":          "We could not find what you're looking for",
        "HelpScout":          "No settings were found for this company",
        "UserVoice":          "This UserVoice subdomain is currently available",
        "Zendesk":            "Help Center Closed",
    }


# ═══════════════════════════════════════════════════════════════
# HTTP SESSION FACTORY  (retry + rate-limiter built in)
# ═══════════════════════════════════════════════════════════════

class RateLimiter:
    """Per-host token-bucket rate limiter."""
    def __init__(self, rate: float = Config.RATE_LIMIT_DELAY):
        self._rate = rate
        self._last: dict = defaultdict(float)
        self._lock = threading.Lock()

    def wait(self, host: str):
        with self._lock:
            elapsed = time.monotonic() - self._last[host]
            if elapsed < self._rate:
                time.sleep(self._rate - elapsed)
            self._last[host] = time.monotonic()


_rate_limiter = RateLimiter()


def build_session(retries: int = Config.MAX_RETRIES) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET"],
        raise_on_status=False,
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry, pool_maxsize=50)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = Config.USER_AGENT
    session.verify = Config.VERIFY_SSL
    return session


# ═══════════════════════════════════════════════════════════════
# HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════

def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def sanitize_target(target: str) -> str:
    """Strip protocol & trailing slashes from user input."""
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]

def severity_color(sev: str) -> str:
    return {
        "Critical": "bold red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "cyan",
        "Info":     "dim",
    }.get(sev, "white")

def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score >= 0.1: return "Low"
    return "Info"

def retry(times=2, delay=0.3):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt == times - 1:
                        log.debug(f"{fn.__name__} failed after {times} attempts: {e}")
                    time.sleep(delay * (attempt + 1))
            return None
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════
# INDIVIDUAL SCANNER MODULES
# ═══════════════════════════════════════════════════════════════

class IPResolver:
    @staticmethod
    def resolve(target: str) -> tuple[str, list[str]]:
        """Returns (primary_ip, all_ips)."""
        if is_valid_ip(target):
            return target, [target]
        try:
            primary = socket.gethostbyname(target)
            all_ips = list({info[4][0] for info in socket.getaddrinfo(target, None)})
            return primary, all_ips
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve {target}: {e}")


class ASNLookup:
    """Retrieve ASN/BGP info from Team Cymru."""
    @staticmethod
    @retry(times=2)
    def lookup(ip: str) -> dict:
        try:
            resolver = dns.resolver.Resolver()
            reversed_ip = ".".join(reversed(ip.split(".")))
            ans = resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
            raw = str(ans[0]).strip('"')
            parts = [p.strip() for p in raw.split("|")]
            asn_result = {
                "asn":    parts[0] if len(parts) > 0 else "",
                "prefix": parts[1] if len(parts) > 1 else "",
                "cc":     parts[2] if len(parts) > 2 else "",
                "rir":    parts[3] if len(parts) > 3 else "",
                "date":   parts[4] if len(parts) > 4 else "",
            }
            # Resolve ASN description
            try:
                asn_num = asn_result["asn"].replace("AS", "").strip()
                desc_ans = resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                asn_result["description"] = str(desc_ans[0]).strip('"').split("|")[-1].strip()
            except Exception:
                pass
            return asn_result
        except Exception:
            return {}


class WhoisScanner:
    @staticmethod
    def scan(target: str) -> dict:
        if not WHOIS_AVAILABLE:
            return {"error": "python-whois not installed"}
        if is_valid_ip(target):
            return {"info": "IP address — use ASN lookup"}
        try:
            w = python_whois.whois(target)
            def safe_str(val):
                if isinstance(val, list):
                    return [str(v) for v in val]
                return str(val) if val else ""
            return {
                "registrar":       safe_str(w.registrar),
                "creation_date":   safe_str(w.creation_date),
                "expiration_date": safe_str(w.expiration_date),
                "updated_date":    safe_str(w.updated_date),
                "name_servers":    safe_str(w.name_servers),
                "status":          safe_str(w.status),
                "registrant":      safe_str(getattr(w, "org", "")),
                "country":         safe_str(getattr(w, "country", "")),
                "dnssec":          safe_str(getattr(w, "dnssec", "")),
                "emails":          safe_str(w.emails),
            }
        except Exception as e:
            return {"error": str(e)}


class RDAPScanner:
    """RDAP (modern WHOIS replacement) via IANA bootstrap."""
    @staticmethod
    @retry(times=2)
    def scan(target: str, session: requests.Session) -> dict:
        if is_valid_ip(target):
            url = f"https://rdap.org/ip/{target}"
        else:
            url = f"https://rdap.org/domain/{target}"
        try:
            r = session.get(url, timeout=Config.TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                result = {
                    "handle":       data.get("handle", ""),
                    "status":       data.get("status", []),
                    "object_class": data.get("objectClassName", ""),
                }
                for event in data.get("events", []):
                    result[f"event_{event.get('eventAction','').replace(' ','_')}"] = event.get("eventDate", "")
                # Extract entities
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    vcards = entity.get("vcardArray", [])
                    if vcards and len(vcards) > 1:
                        for vcard in vcards[1]:
                            if vcard[0] == "fn":
                                result[f"entity_{'_'.join(roles)}_name"] = vcard[3]
                return result
        except Exception:
            pass
        return {}


class DNSScanner:
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV",
                    "CAA", "DNSKEY", "DS", "NAPTR", "PTR", "TLSA"]

    @staticmethod
    def scan(target: str, ip: str) -> dict:
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 8

        for rtype in DNSScanner.RECORD_TYPES:
            try:
                lookup = target if not is_valid_ip(target) else str(dns.reversename.from_address(target))
                if is_valid_ip(target) and rtype != "PTR":
                    continue
                if rtype == "PTR" and not is_valid_ip(target):
                    # Forward PTR from IP
                    try:
                        rev = dns.reversename.from_address(ip)
                        answers = resolver.resolve(rev, "PTR")
                        records["PTR"] = [str(r) for r in answers]
                    except Exception:
                        pass
                    continue
                answers = resolver.resolve(lookup, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception:
                pass

        # Zone Transfer attempt (AXFR)
        records["zone_transfer_vulnerable"] = False
        if not is_valid_ip(target) and "NS" in records:
            for ns in records["NS"][:3]:
                try:
                    ns_ip = socket.gethostbyname(ns.rstrip("."))
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=5))
                    if zone:
                        records["zone_transfer_vulnerable"] = True
                        records["zone_transfer_ns"] = ns
                        break
                except Exception:
                    pass

        return records

    @staticmethod
    def check_email_security(target: str) -> tuple[str, str, str]:
        """Returns (SPF, DKIM, DMARC) records."""
        resolver = dns.resolver.Resolver()
        spf = dkim = dmarc = ""
        try:
            ans = resolver.resolve(target, "TXT")
            for r in ans:
                txt = str(r).strip('"')
                if txt.startswith("v=spf1"):
                    spf = txt
        except Exception:
            pass
        try:
            ans = resolver.resolve(f"default._domainkey.{target}", "TXT")
            dkim = str(ans[0]).strip('"')
        except Exception:
            pass
        try:
            ans = resolver.resolve(f"_dmarc.{target}", "TXT")
            dmarc = str(ans[0]).strip('"')
        except Exception:
            pass
        return spf, dkim, dmarc


class SubdomainScanner:
    """Multi-source subdomain enumeration."""

    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
        self.found: set[str] = set()

    def brute_force(self) -> set:
        found = set()
        def check(sub):
            fqdn = f"{sub}.{self.target}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            for result in pool.map(check, Config.SUBDOMAIN_WORDLIST):
                if result:
                    found.add(result)
        return found

    def certificate_transparency(self) -> set:
        """Query crt.sh for subdomain enumeration (passive, no scan needed)."""
        found = set()
        try:
            r = self.session.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                timeout=15
            )
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(self.target) and n != self.target:
                            found.add(n)
        except Exception:
            pass
        return found

    def hackertarget_api(self) -> set:
        """HackerTarget free API for subdomain lookup."""
        found = set()
        try:
            r = self.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
                timeout=10
            )
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip()
                        if sub.endswith(self.target):
                            found.add(sub)
        except Exception:
            pass
        return found

    def scan(self) -> list[dict]:
        all_subs: set[str] = set()

        # Run sources in parallel
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_brute = pool.submit(self.brute_force)
            f_crt   = pool.submit(self.certificate_transparency)
            f_ht    = pool.submit(self.hackertarget_api)
            all_subs |= f_brute.result()
            all_subs |= f_crt.result()
            all_subs |= f_ht.result()

        results = []
        for sub in sorted(all_subs):
            try:
                ip = socket.gethostbyname(sub)
                results.append({"subdomain": sub, "ip": ip, "private": is_private_ip(ip)})
            except Exception:
                results.append({"subdomain": sub, "ip": "unresolvable", "private": False})

        return results


class PortScanner:
    SERVICE_MAP = {
        21: "FTP",        22: "SSH",        23: "Telnet",     25: "SMTP",
        53: "DNS",        67: "DHCP",       68: "DHCP",       69: "TFTP",
        80: "HTTP",       81: "HTTP-Alt",   88: "Kerberos",   110: "POP3",
        111: "RPC",       119: "NNTP",      135: "MSRPC",     139: "NetBIOS-SSN",
        143: "IMAP",      161: "SNMP",      162: "SNMP-Trap", 194: "IRC",
        389: "LDAP",      443: "HTTPS",     445: "SMB",       465: "SMTPS",
        587: "Submission",636: "LDAPS",      993: "IMAPS",     995: "POP3S",
        1080: "SOCKS",    1194: "OpenVPN",  1433: "MSSQL",    1521: "Oracle",
        1723: "PPTP",     2049: "NFS",      2181: "ZooKeeper",3000: "Dev-HTTP",
        3306: "MySQL",    3389: "RDP",      3690: "SVN",      4443: "HTTPS-Alt",
        5000: "Dev-HTTP", 5432: "PostgreSQL",5601: "Kibana",  5900: "VNC",
        5984: "CouchDB",  6379: "Redis",    6443: "K8s-API",  7001: "WebLogic",
        7474: "Neo4j",    8000: "HTTP-Dev", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
        8081: "HTTP-Alt", 8088: "HTTP-Alt", 8161: "ActiveMQ", 8443: "HTTPS-Alt",
        8888: "Jupyter",  8983: "Solr",     9000: "SonarQube",9090: "Prometheus",
        9200: "Elasticsearch",9300:"ES-Cluster",9418: "Git", 9443: "HTTPS-Alt",
        10000: "Webmin",  11211: "Memcached",15672: "RabbitMQ",27017: "MongoDB",
        27018: "MongoDB", 28017: "MongoDB-Web",50000:"SAP",  50070: "HDFS",
        61616: "ActiveMQ",
    }

    DANGEROUS_SERVICES = {
        23:    ("Telnet",      "Transmits data in plaintext"),
        21:    ("FTP",         "Often allows anonymous access or transmits credentials in plaintext"),
        161:   ("SNMP",        "May expose system info; default community strings are common"),
        3389:  ("RDP",         "Common target for brute-force & exploitation (BlueKeep, DejaBlue)"),
        5900:  ("VNC",         "Remote desktop, often misconfigured with weak auth"),
        1433:  ("MSSQL",       "Database exposure; common target for SA brute-force"),
        3306:  ("MySQL",       "Database exposure; should never be internet-facing"),
        5432:  ("PostgreSQL",  "Database exposure; should never be internet-facing"),
        27017: ("MongoDB",     "Often runs without authentication — critical exposure"),
        6379:  ("Redis",       "Frequently unauthenticated — RCE via SLAVEOF / config"),
        9200:  ("Elasticsearch","Often unauthenticated — full data exposure"),
        11211: ("Memcached",   "DDoS amplification vector; no auth by default"),
        5984:  ("CouchDB",     "Admin panel exposed; CVE-2017-12635"),
        2181:  ("ZooKeeper",   "Often unauthenticated — exposes cluster config"),
        5601:  ("Kibana",      "Dashboard often exposed without authentication"),
        8161:  ("ActiveMQ",    "CVE-2023-46604 — critical RCE vulnerability"),
        7001:  ("WebLogic",    "Frequent RCE vulnerabilities (CVE-2020-14882 etc.)"),
        61616: ("ActiveMQ",    "Message broker; remote code execution risks"),
    }

    @staticmethod
    def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[PortInfo]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = PortScanner.SERVICE_MAP.get(port, "unknown")
                banner = PortScanner._grab_banner(sock, port)
                return PortInfo(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    banner=banner,
                )
        except Exception:
            pass
        finally:
            sock.close()
        return None

    @staticmethod
    def _grab_banner(sock: socket.socket, port: int) -> str:
        """Attempt to grab service banner."""
        try:
            # Send HTTP probe for web ports
            if port in (80, 8080, 8000, 8008, 8081, 8088):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (443, 8443, 4443, 9443):
                return "[HTTPS]"
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200]
        except Exception:
            return ""

    @staticmethod
    def scan(ip: str, port_list: list[int]) -> list[PortInfo]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            futures = {pool.submit(PortScanner.scan_port, ip, p): p for p in port_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x.port)


class SSLScanner:
    @staticmethod
    def scan(host: str, port: int = 443) -> SSLInfo:
        info = SSLInfo(valid=False)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=Config.TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info.tls_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    info.weak_cipher = SSLScanner._is_weak_cipher(cipher[0] if cipher else "")

                    if cert:
                        info.valid = True
                        info.subject = dict(x[0] for x in cert.get("subject", []))
                        info.issuer  = dict(x[0] for x in cert.get("issuer",  []))
                        info.self_signed = info.subject == info.issuer

                        not_after = cert.get("notAfter", "")
                        if not_after:
                            info.expiry = not_after
                            try:
                                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                exp = exp.replace(tzinfo=timezone.utc)
                                info.days_remaining = (exp - datetime.now(timezone.utc)).days
                            except Exception:
                                pass

                        # SANs
                        san_list = cert.get("subjectAltName", [])
                        info.san_domains = [v for t, v in san_list if t == "DNS"]

                        # Grade heuristic
                        info.grade = SSLScanner._grade(info)

        except ssl.SSLError as e:
            info.valid = False
            info.subject = {"error": str(e)}
        except Exception:
            pass
        return info

    @staticmethod
    def _is_weak_cipher(cipher_name: str) -> bool:
        weak = ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"]
        return any(w.lower() in cipher_name.lower() for w in weak)

    @staticmethod
    def _grade(info: SSLInfo) -> str:
        if info.self_signed:                  return "F (Self-Signed)"
        if info.days_remaining <= 0:          return "F (Expired)"
        if info.weak_cipher:                  return "C (Weak Cipher)"
        if info.tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"): return "C (Old TLS)"
        if info.days_remaining < 30:          return "B (Expiring Soon)"
        if info.tls_version == "TLSv1.2":     return "B"
        if info.tls_version == "TLSv1.3":     return "A"
        return "B"


class HTTPHeaderScanner:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "name":  "HSTS",
            "desc":  "Forces HTTPS connections",
            "check": lambda v: "max-age" in v.lower(),
        },
        "Content-Security-Policy": {
            "name":  "CSP",
            "desc":  "Mitigates XSS and injection attacks",
            "check": lambda v: len(v) > 10,
        },
        "X-Frame-Options": {
            "name":  "X-Frame-Options",
            "desc":  "Prevents clickjacking attacks",
            "check": lambda v: any(x in v.upper() for x in ["DENY", "SAMEORIGIN"]),
        },
        "X-Content-Type-Options": {
            "name":  "X-Content-Type-Options",
            "desc":  "Prevents MIME sniffing",
            "check": lambda v: "nosniff" in v.lower(),
        },
        "Referrer-Policy": {
            "name":  "Referrer-Policy",
            "desc":  "Controls referrer information leakage",
            "check": lambda v: len(v) > 2,
        },
        "Permissions-Policy": {
            "name":  "Permissions-Policy",
            "desc":  "Controls browser feature access",
            "check": lambda v: len(v) > 2,
        },
        "X-XSS-Protection": {
            "name":  "X-XSS-Protection",
            "desc":  "Legacy XSS filter (deprecated but still useful)",
            "check": lambda v: "1" in v,
        },
        "Cross-Origin-Embedder-Policy": {
            "name":  "COEP",
            "desc":  "Prevents cross-origin resource leakage",
            "check": lambda v: len(v) > 2,
        },
        "Cross-Origin-Opener-Policy": {
            "name":  "COOP",
            "desc":  "Prevents cross-origin window access",
            "check": lambda v: len(v) > 2,
        },
    }

    @staticmethod
    def scan(target: str, session: requests.Session) -> tuple[dict, dict]:
        raw_headers = {}
        audit = {}

        for scheme in ["https", "http"]:
            try:
                _rate_limiter.wait(target)
                r = session.get(
                    f"{scheme}://{target}/",
                    timeout=Config.TIMEOUT,
                    allow_redirects=Config.FOLLOW_REDIRECTS,
                )
                raw_headers = dict(r.headers)
                break
            except Exception:
                continue

        for header, meta in HTTPHeaderScanner.SECURITY_HEADERS.items():
            val = raw_headers.get(header, "")
            present = bool(val)
            audit[header] = asdict(HeaderAudit(
                present=present,
                value=val,
                secure=present and meta["check"](val),
                recommendation=meta["desc"],
            ))

        return raw_headers, audit


class WAFDetector:
    @staticmethod
    def detect(target: str, session: requests.Session) -> str:
        detected = []
        try:
            # Probe with XSS payload to trigger WAF
            test_url = f"http://{target}/?test=<script>alert(1)</script>"
            _rate_limiter.wait(target)
            r = session.get(test_url, timeout=Config.TIMEOUT, allow_redirects=False)
            headers_str = str(r.headers).lower()
            body_str    = r.text.lower()
            combined    = headers_str + body_str

            for waf_name, signatures in Config.WAF_SIGNATURES.items():
                if any(sig.lower() in combined for sig in signatures):
                    detected.append(waf_name)

            # Check for WAF-specific status codes
            if r.status_code in (406, 419, 501, 999):
                detected.append("Unknown WAF (blocked)")

        except Exception:
            pass
        return ", ".join(detected) if detected else "None detected"


class TechFingerprinter:
    # Header-based fingerprints
    SERVER_PATTERNS = {
        r"Apache/(\d+\.\d+)":       "Apache",
        r"nginx/(\d+\.\d+)":        "Nginx",
        r"Microsoft-IIS/(\d+\.\d+)":"IIS",
        r"LiteSpeed":               "LiteSpeed",
        r"cloudflare":              "Cloudflare",
        r"openresty":               "OpenResty",
        r"gunicorn/(\d+\.\d+)":     "Gunicorn",
        r"Kestrel":                 "ASP.NET Kestrel",
        r"Jetty/(\d+)":             "Jetty",
        r"Tomcat/(\d+)":            "Tomcat",
    }

    HEADER_TECH = {
        "X-Powered-By":     lambda v: v,
        "X-Generator":      lambda v: v,
        "X-Drupal-Cache":   lambda _: "Drupal",
        "X-Wordpress-Cache":lambda _: "WordPress",
        "X-Shopify-Stage":  lambda _: "Shopify",
        "X-Magento-Cache":  lambda _: "Magento",
        "X-Laravel":        lambda _: "Laravel",
        "X-AspNet-Version": lambda v: f"ASP.NET {v}",
        "X-AspNetMvc-Version": lambda v: f"ASP.NET MVC {v}",
    }

    @staticmethod
    def fingerprint(target: str, session: requests.Session) -> dict:
        techs: dict = {"server": [], "cms": [], "frameworks": [], "analytics": [],
                       "cdn": [], "languages": [], "other": []}
        try:
            _rate_limiter.wait(target)
            r = session.get(f"https://{target}", timeout=Config.TIMEOUT,
                            allow_redirects=True)

            server = r.headers.get("Server", "")
            for pattern, name in TechFingerprinter.SERVER_PATTERNS.items():
                if re.search(pattern, server, re.IGNORECASE):
                    techs["server"].append(name)

            for header, extractor in TechFingerprinter.HEADER_TECH.items():
                val = r.headers.get(header, "")
                if val:
                    techs["frameworks"].append(extractor(val))

            # Body-based detection
            body = r.text
            body_lower = body.lower()
            BODY_SIGS = {
                "WordPress":       ["/wp-content/", "/wp-includes/", "wp-json"],
                "Drupal":          ["drupal.js", "drupal.min.js", "Drupal.settings"],
                "Joomla":          ["/components/com_", "Joomla!"],
                "Magento":         ["Mage.Cookies", "/skin/frontend/", "Magento"],
                "Shopify":         ["cdn.shopify.com", "shopify.com/s/files"],
                "React":           ["__REACT_DEVTOOLS", "react-root", "data-reactroot"],
                "Next.js":         ["__NEXT_DATA__", "_next/static"],
                "Vue.js":          ["__vue__", "data-v-"],
                "Angular":         ["ng-version", "ng-scope", "_nghost-"],
                "jQuery":          ["jquery.min.js", "jquery-"],
                "Bootstrap":       ["bootstrap.min.css", "bootstrap.min.js"],
                "Google Analytics":["google-analytics.com/analytics.js", "gtag/js", "UA-"],
                "Google Tag Mgr":  ["googletagmanager.com/gtm.js"],
                "Cloudflare":      ["cloudflare-static", "__cf_bm"],
                "reCAPTCHA":       ["recaptcha", "www.google.com/recaptcha"],
                "Stripe":          ["js.stripe.com"],
            }
            for tech_name, patterns in BODY_SIGS.items():
                if any(p.lower() in body_lower for p in patterns):
                    cat = "analytics" if "Analytics" in tech_name or "Tag" in tech_name \
                          else "cdn" if tech_name in ("Cloudflare",) \
                          else "cms" if tech_name in ("WordPress","Drupal","Joomla","Magento","Shopify") \
                          else "frameworks"
                    techs[cat].append(tech_name)

        except Exception:
            pass

        # Use builtwith if available
        if BUILTWITH_AVAILABLE:
            try:
                bw = builtwith.parse(f"https://{target}")
                for cat, items in bw.items():
                    techs.setdefault(cat, []).extend(items)
            except Exception:
                pass

        return {k: list(set(v)) for k, v in techs.items() if v}


class ContentScanner:
    """Email, phone, file, and admin panel discovery."""

    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session

    def _get(self, path: str, scheme: str = "https") -> Optional[requests.Response]:
        try:
            _rate_limiter.wait(self.target)
            return self.session.get(
                f"{scheme}://{self.target}/{path.lstrip('/')}",
                timeout=Config.TIMEOUT,
                allow_redirects=Config.FOLLOW_REDIRECTS,
            )
        except Exception:
            return None

    def _head(self, url: str) -> Optional[requests.Response]:
        try:
            _rate_limiter.wait(self.target)
            return self.session.head(url, timeout=Config.TIMEOUT, allow_redirects=True)
        except Exception:
            return None

    def harvest_contacts(self) -> tuple[list, list]:
        """Scrape emails and phone numbers from main page + linked pages."""
        emails: set = set()
        phones: set = set()

        EMAIL_RE = re.compile(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        )
        PHONE_RE = re.compile(
            r'(?:(?:\+|00)\d{1,3}[\s\-.]?)?'
            r'(?:\(?\d{1,4}\)?[\s\-.]?){2,4}\d{2,4}'
        )

        pages_to_scrape = ["", "contact", "about", "team", "contact-us"]
        scraped_urls: set = set()

        for path in pages_to_scrape:
            for scheme in ["https", "http"]:
                r = self._get(path, scheme)
                if not r or r.status_code != 200:
                    continue
                url_key = f"{scheme}://{self.target}/{path}"
                if url_key in scraped_urls:
                    continue
                scraped_urls.add(url_key)
                text = r.text

                for e in EMAIL_RE.findall(text):
                    if not e.endswith((".png", ".jpg", ".gif", ".svg", ".css")):
                        emails.add(e.lower())

                for p in PHONE_RE.findall(text):
                    cleaned = re.sub(r'[\s\-\(\)]', '', p)
                    if 7 <= len(cleaned) <= 15:
                        phones.add(p.strip())

                break  # Got a response, move to next path

        return sorted(emails), sorted(phones)

    def find_sensitive_files(self) -> list[dict]:
        found = []

        def check_url(url: str) -> Optional[dict]:
            r = self._head(url)
            if r and r.status_code == 200:
                ctype = r.headers.get("Content-Type", "")
                size  = r.headers.get("Content-Length", "unknown")
                return {"url": url, "status": 200, "content_type": ctype, "size": size}
            return None

        urls = []
        for scheme in ["https", "http"]:
            for f in Config.SENSITIVE_FILES:
                urls.append(f"{scheme}://{self.target}/{f}")

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            for result in pool.map(check_url, urls):
                if result:
                    found.append(result)

        # Deduplicate by path
        seen = set()
        deduped = []
        for item in found:
            key = urlparse(item["url"]).path
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    def find_admin_panels(self) -> list[str]:
        found = []

        def check_url(url: str) -> Optional[str]:
            r = self._head(url)
            if r and r.status_code in (200, 301, 302, 401, 403):
                return url
            return None

        urls = [f"{scheme}://{self.target}/{path}"
                for scheme in ["https", "http"]
                for path in Config.ADMIN_PATHS]

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            for result in pool.map(check_url, urls):
                if result:
                    found.append(result)

        # Deduplicate
        seen, deduped = set(), []
        for u in found:
            k = urlparse(u).path
            if k not in seen:
                seen.add(k)
                deduped.append(u)
        return deduped

    def get_robots_txt(self) -> str:
        r = self._get("robots.txt")
        return r.text[:3000] if r and r.status_code == 200 else ""

    def get_sitemap_urls(self) -> list[str]:
        urls = []
        r = self._get("sitemap.xml")
        if r and r.status_code == 200 and BS4_AVAILABLE:
            soup = BeautifulSoup(r.text, "html.parser")
            for loc in soup.find_all("loc"):
                urls.append(loc.text.strip())
        return urls[:50]


class SubdomainTakeoverDetector:
    @staticmethod
    def check(subdomains: list[dict], session: requests.Session) -> list[dict]:
        vulnerable = []
        def check_one(sub_info: dict) -> Optional[dict]:
            sub = sub_info["subdomain"]
            for scheme in ["https", "http"]:
                try:
                    _rate_limiter.wait(sub)
                    r = session.get(f"{scheme}://{sub}", timeout=5, allow_redirects=True)
                    body = r.text
                    for service, fingerprint in Config.TAKEOVER_FINGERPRINTS.items():
                        if fingerprint.lower() in body.lower():
                            return {
                                "subdomain":   sub,
                                "service":     service,
                                "fingerprint": fingerprint,
                                "url":         f"{scheme}://{sub}",
                            }
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=15) as pool:
            for result in pool.map(check_one, subdomains[:100]):
                if result:
                    vulnerable.append(result)
        return vulnerable


class ShodanScanner:
    @staticmethod
    def scan(ip: str) -> dict:
        if not SHODAN_AVAILABLE:
            return {"error": "shodan package not installed"}
        if not Config.SHODAN_KEY:
            return {"error": "SHODAN_API_KEY env var not set"}
        try:
            api = shodan.Shodan(Config.SHODAN_KEY)
            host = api.host(ip)
            return {
                "ip":           host.get("ip_str", ""),
                "org":          host.get("org", ""),
                "asn":          host.get("asn", ""),
                "hostnames":    host.get("hostnames", []),
                "os":           host.get("os", ""),
                "ports":        host.get("ports", []),
                "tags":         host.get("tags", []),
                "vulns":        list(host.get("vulns", [])),
                "last_update":  host.get("last_update", ""),
                "country":      host.get("country_name", ""),
                "city":         host.get("city", ""),
                "services": [
                    {
                        "port":    s.get("port", ""),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "cpe":     s.get("cpe23", []),
                    }
                    for s in host.get("data", [])
                ],
            }
        except shodan.APIError as e:
            return {"error": str(e)}


class VirusTotalScanner:
    @staticmethod
    def scan(target: str, session: requests.Session) -> dict:
        if not Config.VT_KEY:
            return {"error": "VIRUSTOTAL_API_KEY env var not set"}
        try:
            resource = target if is_valid_ip(target) else target
            url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if is_valid_ip(target) else 'domains'}/{resource}"
            r = session.get(url, headers={"x-apikey": Config.VT_KEY}, timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "harmless":    stats.get("harmless", 0),
                    "undetected":  stats.get("undetected", 0),
                    "reputation":  data.get("reputation", "N/A"),
                    "categories":  data.get("categories", {}),
                    "tags":        data.get("tags", []),
                }
        except Exception as e:
            return {"error": str(e)}
        return {}


# ═══════════════════════════════════════════════════════════════
# VULNERABILITY ENGINE
# ═══════════════════════════════════════════════════════════════

class VulnerabilityEngine:
    def __init__(self, results: ScanResults, session: requests.Session):
        self.r = results
        self.session = session
        self.vulns: list[Vulnerability] = []

    def _check(self, url: str) -> Optional[requests.Response]:
        try:
            _rate_limiter.wait(self.r.target)
            return self.session.get(url, timeout=Config.TIMEOUT, allow_redirects=False)
        except Exception:
            return None

    def _head(self, url: str) -> Optional[requests.Response]:
        try:
            _rate_limiter.wait(self.r.target)
            return self.session.head(url, timeout=Config.TIMEOUT, allow_redirects=False)
        except Exception:
            return None

    def _add(self, **kwargs):
        self.vulns.append(Vulnerability(**kwargs))

    # ── Individual Checks ────────────────────────────────────

    def check_git_exposure(self):
        r = self._check(f"http://{self.r.target}/.git/HEAD")
        if r and r.status_code == 200 and "ref:" in r.text:
            self._add(
                name="Exposed .git Directory",
                severity="High",
                cvss=7.5,
                description="The .git directory is publicly accessible, potentially exposing full source code, "
                            "commit history, credentials embedded in code, and internal architecture.",
                evidence=f"/.git/HEAD returned HTTP 200. Content: {r.text[:80]}",
                remediation="Block access via web server config (e.g., 'deny from all' in .htaccess). "
                            "Use git-dumper to assess exposure and rotate any leaked credentials.",
                cwe="CWE-538",
                references=["https://owasp.org/www-community/Source_Code_Management_Exposure"],
            )

    def check_env_exposure(self):
        for path in [".env", ".env.local", ".env.production"]:
            r = self._check(f"http://{self.r.target}/{path}")
            if r and r.status_code == 200 and ("=" in r.text or "DB_" in r.text or "SECRET" in r.text.upper()):
                self._add(
                    name="Environment File Exposed",
                    severity="Critical",
                    cvss=9.8,
                    description=f"The file /{path} is publicly accessible and appears to contain "
                                "sensitive configuration including database credentials, API keys, "
                                "and application secrets.",
                    evidence=f"/{path} returned HTTP 200 with credential-like content",
                    remediation="Remove the file from the web root immediately. Move secrets to a "
                                "secrets manager (Vault, AWS Secrets Manager). Rotate ALL credentials.",
                    cwe="CWE-200",
                    references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                )
                break

    def check_directory_listing(self):
        test_dirs = ["images", "assets", "uploads", "static", "files", "media", "css", "js"]
        for directory in test_dirs:
            for scheme in ["http", "https"]:
                r = self._check(f"{scheme}://{self.r.target}/{directory}/")
                if r and r.status_code == 200 and (
                    "Index of /" in r.text or
                    "Directory listing for" in r.text or
                    "<title>Index of" in r.text
                ):
                    self._add(
                        name="Directory Listing Enabled",
                        severity="Medium",
                        cvss=5.3,
                        description=f"Web server directory listing is enabled at /{directory}/, "
                                    "exposing the full directory structure and file names to attackers.",
                        evidence=f"/{directory}/ returned a file listing",
                        remediation="Disable directory listing: 'Options -Indexes' (Apache) or "
                                    "'autoindex off;' (Nginx).",
                        cwe="CWE-548",
                    )
                    return  # Report once

    def check_cors_misconfiguration(self):
        for scheme in ["https", "http"]:
            try:
                r = self.session.get(
                    f"{scheme}://{self.r.target}",
                    headers={"Origin": "https://evil.attacker.com"},
                    timeout=Config.TIMEOUT,
                )
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" and acac.lower() == "true":
                    self._add(
                        name="CORS: Wildcard with Credentials",
                        severity="High",
                        cvss=8.1,
                        description="CORS policy sets Access-Control-Allow-Origin: * together with "
                                    "Access-Control-Allow-Credentials: true, allowing any origin to "
                                    "make authenticated cross-origin requests.",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Never combine wildcard origin with credentials. Whitelist specific origins.",
                        cwe="CWE-942",
                    )
                elif acao == "https://evil.attacker.com":
                    self._add(
                        name="CORS: Origin Reflection",
                        severity="High",
                        cvss=7.4,
                        description="Server reflects the arbitrary Origin header back in "
                                    "Access-Control-Allow-Origin, allowing any domain to make CORS requests.",
                        evidence=f"Reflected attacker origin: {acao}",
                        remediation="Validate allowed origins against an explicit whitelist, not reflection.",
                        cwe="CWE-942",
                    )
                elif acao == "*":
                    self._add(
                        name="CORS: Wildcard Origin",
                        severity="Medium",
                        cvss=5.4,
                        description="CORS policy allows any origin to access resources, "
                                    "which may expose sensitive API endpoints.",
                        evidence=f"ACAO: {acao}",
                        remediation="Restrict CORS to known, trusted origins.",
                        cwe="CWE-942",
                    )
                break
            except Exception:
                continue

    def check_security_headers(self):
        for header, audit_dict in self.r.security_headers.items():
            if not audit_dict.get("present"):
                sev_map = {
                    "Strict-Transport-Security":    ("Medium", 5.3),
                    "Content-Security-Policy":      ("Medium", 6.1),
                    "X-Frame-Options":              ("Medium", 4.3),
                    "X-Content-Type-Options":       ("Low",    3.7),
                    "Referrer-Policy":              ("Low",    3.1),
                    "Permissions-Policy":           ("Low",    2.0),
                }
                if header in sev_map:
                    sev, cvss = sev_map[header]
                    meta = HTTPHeaderScanner.SECURITY_HEADERS[header]
                    self._add(
                        name=f"Missing Security Header: {header}",
                        severity=sev,
                        cvss=cvss,
                        description=f"The {header} security header is absent. {meta['desc']}.",
                        evidence=f"Header not present in HTTP response",
                        remediation=f"Add the {header} header to all HTTP responses from your web server.",
                        cwe="CWE-693",
                    )

    def check_ssl_issues(self):
        ssl = self.r.ssl_info
        if not ssl:
            return
        if not ssl.get("valid"):
            self._add(
                name="SSL/TLS Certificate Invalid",
                severity="High",
                cvss=7.4,
                description="The SSL/TLS certificate could not be validated.",
                evidence="SSL connection failed or certificate error returned",
                remediation="Obtain a valid certificate from a trusted CA. Consider Let's Encrypt.",
                cwe="CWE-295",
            )
            return
        if ssl.get("self_signed"):
            self._add(
                name="Self-Signed SSL Certificate",
                severity="Medium",
                cvss=5.9,
                description="The SSL certificate is self-signed. Browsers display security warnings and "
                            "MITM attacks become trivially undetectable.",
                evidence=f"Issuer equals Subject: {ssl.get('subject', {})}",
                remediation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt — free).",
                cwe="CWE-295",
            )
        days = ssl.get("days_remaining", 999)
        if 0 < days < 30:
            self._add(
                name="SSL Certificate Expiring Soon",
                severity="Medium",
                cvss=5.0,
                description=f"SSL certificate expires in {days} days. Expiry causes full service disruption.",
                evidence=f"Expiry date: {ssl.get('expiry','')}",
                remediation="Renew certificate immediately. Automate renewal with certbot or ACME.",
                cwe="CWE-298",
            )
        elif days <= 0:
            self._add(
                name="SSL Certificate Expired",
                severity="High",
                cvss=7.5,
                description="SSL certificate has expired. All connections show browser security warnings.",
                evidence=f"Expiry date: {ssl.get('expiry','')}",
                remediation="Renew certificate immediately.",
                cwe="CWE-298",
            )
        if ssl.get("weak_cipher"):
            self._add(
                name="Weak SSL/TLS Cipher Suite",
                severity="Medium",
                cvss=5.9,
                description="Server supports weak cipher suites (RC4, 3DES, NULL, EXPORT) that can "
                            "be exploited by BEAST, SWEET32, or similar attacks.",
                evidence=f"TLS version: {ssl.get('tls_version','')}",
                remediation="Disable weak ciphers. Use Mozilla SSL Configuration Generator.",
                cwe="CWE-326",
                references=["https://ssl-config.mozilla.org/"],
            )

    def check_dangerous_ports(self):
        for port_info in self.r.open_ports:
            p = port_info["port"] if isinstance(port_info, dict) else port_info.port
            if p in PortScanner.DANGEROUS_SERVICES:
                svc, reason = PortScanner.DANGEROUS_SERVICES[p]
                self._add(
                    name=f"Dangerous Service Exposed: {svc} (port {p})",
                    severity="High" if p in (3389, 22, 21, 6379, 27017, 9200) else "Medium",
                    cvss=7.8 if p in (3389, 6379, 27017, 9200, 8161) else 5.5,
                    description=f"Port {p} ({svc}) is publicly accessible. {reason}.",
                    evidence=f"Port {p}/tcp open",
                    remediation=f"Restrict {svc} to trusted IPs via firewall rules. "
                                "Never expose database/admin services to the internet.",
                    cwe="CWE-732",
                )

    def check_insecure_cookies(self):
        for scheme in ["https", "http"]:
            try:
                r = self.session.get(
                    f"{scheme}://{self.r.target}",
                    timeout=Config.TIMEOUT
                )
                set_cookie = r.headers.get("Set-Cookie", "")
                if not set_cookie:
                    break
                issues = []
                if "Secure" not in set_cookie and scheme == "https":
                    issues.append("missing Secure flag")
                if "HttpOnly" not in set_cookie:
                    issues.append("missing HttpOnly flag")
                if "SameSite" not in set_cookie:
                    issues.append("missing SameSite attribute")
                if issues:
                    self._add(
                        name="Insecure Cookie Configuration",
                        severity="Medium",
                        cvss=4.3,
                        description=f"Cookies are set with security issues: {', '.join(issues)}. "
                                    "This can lead to session hijacking, CSRF, or XSS-based theft.",
                        evidence=f"Set-Cookie: {set_cookie[:200]}",
                        remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict on all authentication cookies.",
                        cwe="CWE-614",
                    )
                break
            except Exception:
                continue

    def check_zone_transfer(self):
        if self.r.dns_records.get("zone_transfer_vulnerable"):
            ns = self.r.dns_records.get("zone_transfer_ns", "unknown NS")
            self._add(
                name="DNS Zone Transfer Permitted",
                severity="High",
                cvss=7.5,
                description="The DNS server allows unauthenticated zone transfer (AXFR) requests, "
                            "exposing the complete list of subdomains, internal hosts, and network topology.",
                evidence=f"Zone transfer succeeded via {ns}",
                remediation="Restrict AXFR to authorized secondary DNS servers only.",
                cwe="CWE-200",
            )

    def check_clickjacking(self):
        xfo = self.r.security_headers.get("X-Frame-Options", {}).get("present", False)
        csp_val = self.r.security_headers.get("Content-Security-Policy", {}).get("value", "")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()
        if not xfo and not has_frame_ancestors:
            self._add(
                name="Clickjacking Vulnerability",
                severity="Medium",
                cvss=4.3,
                description="No X-Frame-Options or CSP frame-ancestors directive is set, "
                            "allowing the page to be embedded in a malicious iframe for UI redress attacks.",
                evidence="X-Frame-Options and CSP frame-ancestors both absent",
                remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none;' header.",
                cwe="CWE-1021",
            )

    def check_information_disclosure(self):
        for scheme in ["https", "http"]:
            try:
                r = self.session.get(f"{scheme}://{self.r.target}", timeout=Config.TIMEOUT)
                server = r.headers.get("Server", "")
                x_powered = r.headers.get("X-Powered-By", "")
                if re.search(r'\d+\.\d+', server):
                    self._add(
                        name="Server Version Disclosed",
                        severity="Low",
                        cvss=2.7,
                        description=f"The Server header reveals the exact software version: '{server}'. "
                                    "This helps attackers identify known CVEs for this version.",
                        evidence=f"Server: {server}",
                        remediation="Configure your web server to omit or genericize the Server header.",
                        cwe="CWE-200",
                    )
                if x_powered:
                    self._add(
                        name="Technology Stack Disclosed via X-Powered-By",
                        severity="Low",
                        cvss=2.7,
                        description=f"The X-Powered-By header reveals the backend technology: '{x_powered}'.",
                        evidence=f"X-Powered-By: {x_powered}",
                        remediation="Remove X-Powered-By header from responses.",
                        cwe="CWE-200",
                    )
                break
            except Exception:
                continue

    def check_email_security(self):
        if not is_valid_ip(self.r.target):
            spf = self.r.spf_record
            dmarc = self.r.dmarc_record
            if not spf:
                self._add(
                    name="Missing SPF Record",
                    severity="Medium",
                    cvss=5.3,
                    description="No SPF DNS record found. Attackers can spoof emails from this domain "
                                "without detection, enabling phishing and business email compromise.",
                    evidence="No TXT record with v=spf1 found",
                    remediation="Add an SPF TXT record: 'v=spf1 include:your-mail-provider.com ~all'",
                    cwe="CWE-290",
                )
            if not dmarc:
                self._add(
                    name="Missing DMARC Record",
                    severity="Medium",
                    cvss=5.3,
                    description="No DMARC policy found. Without DMARC, spoofed emails pass through "
                                "and mail providers cannot take action on unauthorized senders.",
                    evidence="No TXT record at _dmarc subdomain",
                    remediation="Add a DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'",
                    cwe="CWE-290",
                )

    def check_shodan_vulns(self):
        shodan_vulns = self.r.shodan_data.get("vulns", [])
        for cve in shodan_vulns:
            self._add(
                name=f"Known CVE Detected: {cve}",
                severity="High",
                cvss=8.0,
                description=f"Shodan reports that {cve} has been observed for this host. "
                            "This is a known vulnerability with a public CVE identifier.",
                evidence=f"Source: Shodan intelligence data for {self.r.ip_address}",
                remediation="Check NVD/NIST for patch details and apply immediately: "
                            f"https://nvd.nist.gov/vuln/detail/{cve}",
                cwe="CWE-1035",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            )

    def check_virustotal(self):
        vt = self.r.virustotal_data
        malicious = vt.get("malicious", 0)
        if malicious > 0:
            self._add(
                name="Malicious Reputation: VirusTotal",
                severity="Critical",
                cvss=9.0,
                description=f"VirusTotal reports {malicious} security vendor(s) flagged this target "
                            "as malicious. The host may be serving malware or be compromised.",
                evidence=f"Malicious: {malicious}, Suspicious: {vt.get('suspicious',0)}",
                remediation="Investigate the host immediately. Check for malware, unauthorized files, "
                            "and compromised accounts. Contact your hosting provider.",
                cwe="CWE-912",
            )

    def check_subdomain_takeover(self):
        for vuln in self.r.subdomain_takeover:
            self._add(
                name=f"Subdomain Takeover: {vuln['subdomain']}",
                severity="High",
                cvss=8.1,
                description=f"The subdomain {vuln['subdomain']} appears to be a candidate for takeover "
                            f"via {vuln['service']}. The CNAME points to an unclaimed/deleted resource.",
                evidence=f"Fingerprint matched: '{vuln['fingerprint']}'",
                remediation=f"Remove the dangling DNS record for {vuln['subdomain']} or reclaim the "
                            f"resource on {vuln['service']} immediately.",
                cwe="CWE-350",
            )

    def run_all(self) -> list[Vulnerability]:
        checks = [
            self.check_git_exposure,
            self.check_env_exposure,
            self.check_directory_listing,
            self.check_cors_misconfiguration,
            self.check_security_headers,
            self.check_ssl_issues,
            self.check_dangerous_ports,
            self.check_insecure_cookies,
            self.check_zone_transfer,
            self.check_clickjacking,
            self.check_information_disclosure,
            self.check_email_security,
            self.check_shodan_vulns,
            self.check_virustotal,
            self.check_subdomain_takeover,
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda fn: fn(), checks))

        # Sort by CVSS score
        self.vulns.sort(key=lambda v: v.cvss, reverse=True)
        return self.vulns


# ═══════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class CyberSleuthUltra:
    def __init__(self, target: str, port_mode: str = "common"):
        self.target = sanitize_target(target)
        self.port_mode = port_mode
        self.session = build_session()
        self.results = ScanResults(target=self.target)

    def run(self, verbose: bool = False) -> ScanResults:
        console.print(Panel.fit(
            Text.assemble(
                ("╔══════════════════════════════════════════╗\n", "bold blue"),
                ("║   CyberSleuth Ultra v3.0                 ║\n", "bold cyan"),
                ("║   Advanced OSINT & Vulnerability Scanner  ║\n", "bold cyan"),
                ("╚══════════════════════════════════════════╝\n", "bold blue"),
                (f"\n  Target  : ", "bold"), (self.target, "bold green"),
                (f"\n  Mode    : ", "bold"), (self.port_mode, "yellow"),
                (f"\n  Started : ", "bold"), (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "dim"),
            ),
            border_style="blue"
        ))

        start = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            main_task = progress.add_task("[cyan]Overall Progress", total=15)

            def step(label: str, fn, *args, **kwargs):
                t = progress.add_task(f"  {label}", total=1)
                result = fn(*args, **kwargs)
                progress.update(t, completed=1)
                progress.update(main_task, advance=1)
                return result

            # ── 1. IP Resolution ──────────────────────────────
            try:
                ip, all_ips = step("Resolving target", IPResolver.resolve, self.target)
                self.results.ip_address = ip
            except ValueError as e:
                console.print(f"[bold red][!] {e}[/]")
                sys.exit(1)

            # ── 2. ASN Lookup ─────────────────────────────────
            self.results.asn_info = step("ASN / BGP lookup", ASNLookup.lookup, ip)

            # ── 3. WHOIS ──────────────────────────────────────
            self.results.whois_info = step("WHOIS lookup", WhoisScanner.scan, self.target)

            # ── 4. RDAP ───────────────────────────────────────
            self.results.rdap_info = step("RDAP lookup", RDAPScanner.scan, self.target, self.session)

            # ── 5. DNS Enumeration ────────────────────────────
            self.results.dns_records = step("DNS enumeration", DNSScanner.scan, self.target, ip)

            # ── 6. Email Security ─────────────────────────────
            if not is_valid_ip(self.target):
                spf, dkim, dmarc = step("Email security (SPF/DKIM/DMARC)",
                                         DNSScanner.check_email_security, self.target)
                self.results.spf_record  = spf
                self.results.dkim_record = dkim
                self.results.dmarc_record = dmarc
            else:
                progress.update(main_task, advance=1)

            # ── 7. Subdomain Enumeration ──────────────────────
            if not is_valid_ip(self.target):
                scanner = SubdomainScanner(self.target, self.session)
                self.results.subdomains = step("Subdomain enumeration", scanner.scan)
            else:
                progress.update(main_task, advance=1)

            # ── 8. Port Scanning ──────────────────────────────
            ports = (Config.TOP_100_PORTS if self.port_mode == "top100"
                     else Config.COMMON_PORTS)
            port_results = step("Port scanning", PortScanner.scan, ip, ports)
            self.results.open_ports = [asdict(p) for p in port_results]

            # ── 9. SSL/TLS Analysis ───────────────────────────
            ssl_port = 443
            if any(p["port"] == 443 for p in self.results.open_ports):
                info = step("SSL/TLS analysis", SSLScanner.scan, self.target, ssl_port)
                self.results.ssl_info = asdict(info)
            else:
                step("SSL/TLS analysis (skipped - port 443 closed)", lambda: {})

            # ── 10. HTTP Headers ──────────────────────────────
            raw_hdrs, audit = step("HTTP security headers", HTTPHeaderScanner.scan,
                                   self.target, self.session)
            self.results.http_headers    = raw_hdrs
            self.results.security_headers = audit

            # ── 11. WAF Detection ─────────────────────────────
            self.results.waf_detected = step("WAF detection", WAFDetector.detect,
                                              self.target, self.session)

            # ── 12. Technology Fingerprinting ─────────────────
            self.results.technologies = step("Technology fingerprinting",
                                              TechFingerprinter.fingerprint,
                                              self.target, self.session)

            # ── 13. Content Discovery ─────────────────────────
            content = ContentScanner(self.target, self.session)
            emails, phones = step("Contact harvesting", content.harvest_contacts)
            self.results.emails        = emails
            self.results.phone_numbers = phones

            sens_task = progress.add_task("  Sensitive file discovery", total=1)
            self.results.sensitive_files = content.find_sensitive_files()
            progress.update(sens_task, completed=1)

            admin_task = progress.add_task("  Admin panel discovery", total=1)
            self.results.admin_panels = content.find_admin_panels()
            progress.update(admin_task, completed=1)

            self.results.robots_txt    = content.get_robots_txt()
            self.results.sitemap_urls  = content.get_sitemap_urls()

            # ── 14. Subdomain Takeover ────────────────────────
            if self.results.subdomains:
                self.results.subdomain_takeover = step(
                    "Subdomain takeover check",
                    SubdomainTakeoverDetector.check,
                    self.results.subdomains, self.session
                )
            else:
                progress.update(main_task, advance=1)

            # ── 15. External Intel ────────────────────────────
            shodan_task = progress.add_task("  Shodan intelligence", total=1)
            self.results.shodan_data = ShodanScanner.scan(ip)
            progress.update(shodan_task, completed=1)

            vt_task = progress.add_task("  VirusTotal lookup", total=1)
            self.results.virustotal_data = VirusTotalScanner.scan(self.target, self.session)
            progress.update(vt_task, completed=1)
            progress.update(main_task, advance=1)

        # ── Vulnerability Engine ──────────────────────────────
        console.print("\n[bold yellow]⚡ Running vulnerability engine...[/]")
        engine = VulnerabilityEngine(self.results, self.session)
        vulns = engine.run_all()
        self.results.vulnerabilities = [asdict(v) for v in vulns]

        self.results.scan_metadata = {
            "scan_duration_seconds": round(time.time() - start, 2),
            "scan_timestamp":        datetime.now(timezone.utc).isoformat(),
            "scanner_version":       "3.0",
            "port_mode":             self.port_mode,
            "total_checks":          len(engine.vulns),
        }

        return self.results


# ═══════════════════════════════════════════════════════════════
# RICH REPORTING
# ═══════════════════════════════════════════════════════════════

class Reporter:
    @staticmethod
    def print_results(results: ScanResults):
        c = console

        c.print(Rule("[bold cyan]SCAN RESULTS[/]", style="cyan"))

        # ── Overview Panel ────────────────────────────────────
        asn = results.asn_info
        overview = Table.grid(padding=(0, 2))
        overview.add_column(style="bold", width=22)
        overview.add_column()
        overview.add_row("Target",          f"[bold green]{results.target}[/]")
        overview.add_row("IP Address",       results.ip_address or "N/A")
        overview.add_row("ASN",              f"{asn.get('asn','')} — {asn.get('description','')}" if asn else "N/A")
        overview.add_row("Network",          asn.get("prefix", "N/A"))
        overview.add_row("Country/RIR",      f"{asn.get('cc','?')} / {asn.get('rir','?')}")
        overview.add_row("WAF",              results.waf_detected or "None detected")
        c.print(Panel(overview, title="[bold]Target Overview[/]", border_style="green"))

        # ── Vulnerability Summary ─────────────────────────────
        sev_counts: dict = defaultdict(int)
        for v in results.vulnerabilities:
            sev_counts[v["severity"]] += 1

        vuln_table = Table(title="Vulnerabilities", box=box.ROUNDED,
                           border_style="red", show_header=True)
        vuln_table.add_column("Critical", style="bold red",    justify="center")
        vuln_table.add_column("High",     style="red",         justify="center")
        vuln_table.add_column("Medium",   style="yellow",      justify="center")
        vuln_table.add_column("Low",      style="cyan",        justify="center")
        vuln_table.add_column("Total",    style="bold white",  justify="center")
        total = sum(sev_counts.values())
        vuln_table.add_row(
            str(sev_counts.get("Critical", 0)),
            str(sev_counts.get("High",     0)),
            str(sev_counts.get("Medium",   0)),
            str(sev_counts.get("Low",      0)),
            str(total)
        )
        c.print(vuln_table)

        # ── Detailed Vulnerabilities ──────────────────────────
        if results.vulnerabilities:
            c.print(Rule("[bold red]⚠  VULNERABILITIES[/]", style="red"))
            for i, vuln in enumerate(results.vulnerabilities, 1):
                sev   = vuln["severity"]
                color = severity_color(sev)
                cvss  = vuln.get("cvss", 0.0)
                panel_content = Table.grid(padding=(0, 1))
                panel_content.add_column(style="bold dim", width=14)
                panel_content.add_column()
                panel_content.add_row("Severity",     f"[{color}]{sev}[/] (CVSS {cvss:.1f})")
                panel_content.add_row("CWE",          vuln.get("cwe", "—"))
                panel_content.add_row("Description",  vuln["description"])
                panel_content.add_row("Evidence",     f"[dim]{vuln.get('evidence','')}[/]")
                panel_content.add_row("Remediation",  f"[green]{vuln['remediation']}[/]")
                if vuln.get("references"):
                    panel_content.add_row("References",   "\n".join(vuln["references"]))
                c.print(Panel(
                    panel_content,
                    title=f"[{color}]  {i}. {vuln['name']}[/]",
                    border_style=color.replace("bold ", ""),
                ))

        # ── DNS Records ───────────────────────────────────────
        if results.dns_records:
            dns_tree = Tree("[bold cyan]DNS Records[/]")
            for rtype, vals in results.dns_records.items():
                if rtype == "zone_transfer_vulnerable": continue
                if isinstance(vals, list):
                    branch = dns_tree.add(f"[yellow]{rtype}[/]")
                    for v in vals[:8]:
                        branch.add(f"[dim]{v}[/]")
                else:
                    dns_tree.add(f"[yellow]{rtype}[/]: {vals}")
            c.print(Panel(dns_tree, title="DNS Enumeration", border_style="cyan"))

        # ── Open Ports ────────────────────────────────────────
        if results.open_ports:
            port_table = Table(title="Open Ports", box=box.SIMPLE_HEAD, border_style="yellow")
            port_table.add_column("Port",    style="bold yellow", justify="right", width=8)
            port_table.add_column("Proto",   width=6)
            port_table.add_column("Service", style="cyan",   width=16)
            port_table.add_column("Risk",    width=10)
            port_table.add_column("Banner",  style="dim",    max_width=50)
            for p in results.open_ports:
                port = p["port"] if isinstance(p, dict) else p.port
                svc  = p["service"] if isinstance(p, dict) else p.service
                ban  = (p["banner"] if isinstance(p, dict) else p.banner)[:60]
                risk = "[red]HIGH[/]" if port in PortScanner.DANGEROUS_SERVICES else "[green]LOW[/]"
                port_table.add_row(str(port), "tcp", svc, risk, ban)
            c.print(port_table)

        # ── SSL Info ──────────────────────────────────────────
        ssl = results.ssl_info
        if ssl and ssl.get("valid"):
            ssl_grid = Table.grid(padding=(0, 2))
            ssl_grid.add_column(style="bold", width=18)
            ssl_grid.add_column()
            grade = ssl.get("grade", "?")
            grade_color = "green" if grade.startswith("A") else "yellow" if grade.startswith("B") else "red"
            ssl_grid.add_row("Grade",         f"[{grade_color}]{grade}[/]")
            ssl_grid.add_row("TLS Version",   ssl.get("tls_version", "?"))
            ssl_grid.add_row("Expires",       f"{ssl.get('expiry','')} ({ssl.get('days_remaining',0)} days)")
            ssl_grid.add_row("Self-Signed",   str(ssl.get("self_signed", False)))
            ssl_grid.add_row("Weak Cipher",   str(ssl.get("weak_cipher", False)))
            if ssl.get("san_domains"):
                ssl_grid.add_row("SANs", ", ".join(ssl["san_domains"][:8]))
            c.print(Panel(ssl_grid, title="SSL/TLS Certificate", border_style="green"))

        # ── Security Headers ──────────────────────────────────
        if results.security_headers:
            hdr_table = Table(title="Security Headers Audit", box=box.SIMPLE_HEAD)
            hdr_table.add_column("Header", width=38)
            hdr_table.add_column("Status", width=12, justify="center")
            hdr_table.add_column("Purpose", style="dim")
            for header, audit in results.security_headers.items():
                present = audit.get("present", False)
                secure  = audit.get("secure",  False)
                status  = "[green]✓ Secure[/]" if secure else "[yellow]⚠ Present[/]" if present else "[red]✗ Missing[/]"
                meta    = HTTPHeaderScanner.SECURITY_HEADERS.get(header, {})
                hdr_table.add_row(header, status, meta.get("desc", ""))
            c.print(hdr_table)

        # ── Technologies ──────────────────────────────────────
        if results.technologies:
            tech_items = []
            for cat, items in results.technologies.items():
                if items:
                    tech_items.append(f"[bold]{cat.title()}:[/] {', '.join(items)}")
            if tech_items:
                c.print(Panel("\n".join(tech_items), title="Technology Stack",
                              border_style="magenta"))

        # ── Subdomains ────────────────────────────────────────
        if results.subdomains:
            sub_table = Table(title=f"Subdomains ({len(results.subdomains)} found)",
                              box=box.SIMPLE_HEAD, border_style="cyan")
            sub_table.add_column("Subdomain", style="cyan")
            sub_table.add_column("IP",        style="dim")
            sub_table.add_column("Private",   justify="center")
            for s in results.subdomains[:50]:
                sub_table.add_row(
                    s["subdomain"], s["ip"],
                    "[yellow]Yes[/]" if s.get("private") else ""
                )
            c.print(sub_table)

        # ── Contact Info ──────────────────────────────────────
        if results.emails or results.phone_numbers:
            contact_grid = Table.grid(padding=(0, 2))
            contact_grid.add_column(style="bold", width=14)
            contact_grid.add_column()
            if results.emails:
                contact_grid.add_row("Emails", "\n".join(results.emails))
            if results.phone_numbers:
                contact_grid.add_row("Phones", "\n".join(results.phone_numbers))
            c.print(Panel(contact_grid, title="Harvested Contact Info", border_style="blue"))

        # ── Sensitive Files ───────────────────────────────────
        if results.sensitive_files:
            sf_table = Table(title="Sensitive Files Found", box=box.SIMPLE_HEAD,
                             border_style="red")
            sf_table.add_column("URL",          style="red")
            sf_table.add_column("Content-Type", style="dim")
            sf_table.add_column("Size",         style="dim", justify="right")
            for f in results.sensitive_files:
                sf_table.add_row(f["url"], f.get("content_type",""), f.get("size",""))
            c.print(sf_table)

        # ── Admin Panels ──────────────────────────────────────
        if results.admin_panels:
            c.print(Panel(
                "\n".join(f"[yellow]→[/] {p}" for p in results.admin_panels),
                title="[bold]Admin Panels Discovered[/]",
                border_style="yellow"
            ))

        # ── Email Security ────────────────────────────────────
        if any([results.spf_record, results.dkim_record, results.dmarc_record]):
            em_grid = Table.grid(padding=(0, 2))
            em_grid.add_column(style="bold", width=8)
            em_grid.add_column(style="dim")
            em_grid.add_row("SPF",   results.spf_record or "[red]NOT FOUND[/]")
            em_grid.add_row("DKIM",  results.dkim_record or "[red]NOT FOUND[/]")
            em_grid.add_row("DMARC", results.dmarc_record or "[red]NOT FOUND[/]")
            c.print(Panel(em_grid, title="Email Security (SPF/DKIM/DMARC)", border_style="blue"))

        # ── Shodan Intelligence ───────────────────────────────
        if results.shodan_data and "error" not in results.shodan_data:
            sh = results.shodan_data
            sh_grid = Table.grid(padding=(0, 2))
            sh_grid.add_column(style="bold", width=16)
            sh_grid.add_column()
            sh_grid.add_row("Organization", sh.get("org",""))
            sh_grid.add_row("OS",           sh.get("os","Unknown"))
            sh_grid.add_row("Location",     f"{sh.get('city','')}, {sh.get('country','')}")
            sh_grid.add_row("Open Ports",   ", ".join(str(p) for p in sh.get("ports",[])))
            sh_grid.add_row("Tags",         ", ".join(sh.get("tags",[])))
            if sh.get("vulns"):
                sh_grid.add_row("CVEs",
                    f"[bold red]{', '.join(sh['vulns'][:10])}[/]")
            c.print(Panel(sh_grid, title="Shodan Intelligence", border_style="blue"))

        # ── Subdomain Takeover ────────────────────────────────
        if results.subdomain_takeover:
            to_table = Table(title="⚠  Subdomain Takeover Candidates",
                             box=box.SIMPLE_HEAD, border_style="red")
            to_table.add_column("Subdomain",   style="red")
            to_table.add_column("Service",     style="yellow")
            to_table.add_column("Fingerprint", style="dim")
            for vuln in results.subdomain_takeover:
                to_table.add_row(vuln["subdomain"], vuln["service"], vuln["fingerprint"][:60])
            c.print(to_table)

        # ── Metadata ──────────────────────────────────────────
        meta = results.scan_metadata
        c.print(Rule(style="dim"))
        c.print(
            f"[dim]Scan completed in [bold]{meta.get('scan_duration_seconds','?')}s[/] "
            f"| {total} vulnerabilities found "
            f"| {len(results.open_ports)} open ports "
            f"| {len(results.subdomains)} subdomains[/]"
        )
        c.print(
            "[bold yellow]\n⚠  Always use this tool with explicit written authorization. "
            "Unauthorized scanning may violate laws including the CFAA.\n[/]"
        )

    @staticmethod
    def save_json(results: ScanResults, filepath: str):
        """Serialize full results to JSON with custom serializer."""
        def serializer(obj):
            if isinstance(obj, (datetime,)):
                return obj.isoformat()
            return str(obj)
        data = asdict(results) if hasattr(results, "__dataclass_fields__") else results.__dict__
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=serializer)
        console.print(f"[green][+] JSON results saved → {filepath}[/]")

    @staticmethod
    def save_html(results: ScanResults, filepath: str):
        """Generate a self-contained HTML report."""
        vulns_html = ""
        sev_colors = {
            "Critical": "#FF3B30", "High": "#FF9500",
            "Medium":   "#FFCC00", "Low":  "#34C759", "Info": "#636366"
        }
        for vuln in results.vulnerabilities:
            color = sev_colors.get(vuln["severity"], "#999")
            refs_html = "".join(f'<a href="{r}" target="_blank">{r}</a><br>' for r in vuln.get("references", []))
            vulns_html += f"""
            <div class="vuln">
              <div class="vuln-header" style="border-left: 5px solid {color};">
                <span class="badge" style="background:{color}">{vuln["severity"]}</span>
                <strong>{vuln["name"]}</strong>
                <span class="cvss">CVSS {vuln.get("cvss",0):.1f}</span>
                {f'<span class="cwe">{vuln.get("cwe","")}</span>' if vuln.get("cwe") else ""}
              </div>
              <div class="vuln-body">
                <p><strong>Description:</strong> {vuln["description"]}</p>
                <p><strong>Evidence:</strong> <code>{vuln.get("evidence","")}</code></p>
                <p><strong>Remediation:</strong> <span class="fix">{vuln["remediation"]}</span></p>
                {f'<p><strong>References:</strong> {refs_html}</p>' if refs_html else ""}
              </div>
            </div>"""

        sev_count = defaultdict(int)
        for v in results.vulnerabilities:
            sev_count[v["severity"]] += 1

        ports_rows = "".join(
            f"<tr><td>{p['port']}</td><td>tcp</td><td>{p['service']}</td>"
            f"<td>{'<span class=\"high\">HIGH</span>' if p['port'] in PortScanner.DANGEROUS_SERVICES else '<span class=\"low\">LOW</span>'}</td>"
            f"<td>{p.get('banner','')[:80]}</td></tr>"
            for p in results.open_ports
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSleuth Ultra Report — {results.target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
         background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
  h2 {{ color: var(--accent); margin: 2rem 0 1rem; font-size: 1.1rem; text-transform: uppercase;
       letter-spacing: .1em; border-bottom: 1px solid var(--border); padding-bottom:.5rem; }}
  .meta {{ color: var(--dim); font-size:.85rem; margin-top:.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(4,1fr); gap:1rem; margin:1.5rem 0; }}
  .sev-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
               padding:1.2rem; text-align:center; }}
  .sev-card .num {{ font-size:2.5rem; font-weight:700; }}
  .sev-card .label {{ color:var(--dim); font-size:.8rem; margin-top:.3rem; }}
  .vuln {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
           margin:1rem 0; overflow:hidden; }}
  .vuln-header {{ padding:1rem 1.2rem; display:flex; align-items:center; gap:.8rem;
                  background: rgba(255,255,255,.02); }}
  .vuln-body {{ padding:1.2rem; line-height:1.7; font-size:.9rem; }}
  .vuln-body p {{ margin:.5rem 0; }}
  .vuln-body a {{ color:var(--accent); }}
  .badge {{ padding:.2rem .7rem; border-radius:12px; font-size:.75rem; font-weight:700;
            color: #000; }}
  .cvss {{ margin-left:auto; color:var(--dim); font-size:.8rem; }}
  .cwe {{ color:var(--dim); font-size:.8rem; }}
  .fix {{ color: #3fb950; }}
  code {{ background:#1c2128; padding:.1rem .4rem; border-radius:4px; font-size:.85rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--surface);
           border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  th {{ background:#1c2128; padding:.7rem 1rem; text-align:left; color:var(--dim);
        font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  td {{ padding:.6rem 1rem; border-top:1px solid var(--border); font-size:.85rem; }}
  .high {{ color: #FF9500; font-weight:700; }}
  .low  {{ color: #3fb950; }}
  .disclaimer {{ margin-top:3rem; padding:1rem; border:1px solid #FF9500;
                 border-radius:8px; color:#FF9500; font-size:.85rem; }}
</style>
</head>
<body>
<h1>🔍 CyberSleuth Ultra v3.0 — Security Report</h1>
<p class="meta">
  Target: <strong>{results.target}</strong> ({results.ip_address}) |
  Scanned: {results.scan_metadata.get("scan_timestamp","")[:19]} |
  Duration: {results.scan_metadata.get("scan_duration_seconds","?")}s
</p>

<h2>Vulnerability Summary</h2>
<div class="summary">
  <div class="sev-card"><div class="num" style="color:#FF3B30">{sev_count.get("Critical",0)}</div>
    <div class="label">Critical</div></div>
  <div class="sev-card"><div class="num" style="color:#FF9500">{sev_count.get("High",0)}</div>
    <div class="label">High</div></div>
  <div class="sev-card"><div class="num" style="color:#FFCC00">{sev_count.get("Medium",0)}</div>
    <div class="label">Medium</div></div>
  <div class="sev-card"><div class="num" style="color:#34C759">{sev_count.get("Low",0)}</div>
    <div class="label">Low</div></div>
</div>

<h2>Vulnerabilities ({len(results.vulnerabilities)} Found)</h2>
{vulns_html if vulns_html else '<p style="color:var(--dim)">No vulnerabilities detected.</p>'}

<h2>Open Ports ({len(results.open_ports)})</h2>
<table>
  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Risk</th><th>Banner</th></tr>
  {ports_rows if ports_rows else '<tr><td colspan="5" style="color:var(--dim)">No open ports detected.</td></tr>'}
</table>

<h2>Subdomains ({len(results.subdomains)} Found)</h2>
<table>
  <tr><th>Subdomain</th><th>IP</th></tr>
  {"".join(f'<tr><td>{s["subdomain"]}</td><td>{s["ip"]}</td></tr>' for s in results.subdomains[:100])
   or '<tr><td colspan="2" style="color:var(--dim)">No subdomains found.</td></tr>'}
</table>

{'<h2>Sensitive Files (' + str(len(results.sensitive_files)) + ' Found)</h2><table><tr><th>URL</th><th>Type</th><th>Size</th></tr>' + "".join(f'<tr><td>{f["url"]}</td><td>{f.get("content_type","")}</td><td>{f.get("size","")}</td></tr>' for f in results.sensitive_files) + '</table>' if results.sensitive_files else ''}

<div class="disclaimer">
  ⚠ This report is intended for authorized security testing only.
  All findings should be disclosed responsibly to the system owner.
  Unauthorized scanning may violate applicable laws.
</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green][+] HTML report saved → {filepath}[/]")


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CyberSleuth Ultra v3.0 — Advanced OSINT & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cybersleuth_ultra.py example.com
  python cybersleuth_ultra.py example.com --ports top100 --output report
  python cybersleuth_ultra.py 93.184.216.34 --ports common
  
API Keys (set as environment variables):
  export SHODAN_API_KEY=your_key_here
  export VIRUSTOTAL_API_KEY=your_key_here

⚠  Always obtain written authorization before scanning any target.
""")
    parser.add_argument("target",
                        help="Domain name or IP address to scan")
    parser.add_argument("--ports", choices=["common", "top100"],
                        default="common",
                        help="Port scan profile (default: common)")
    parser.add_argument("--output", metavar="BASENAME",
                        help="Save results to BASENAME.json and BASENAME.html")
    parser.add_argument("--json-only", action="store_true",
                        help="Skip HTML report generation")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("cybersleuth").setLevel(logging.DEBUG)

    # Run scan
    scanner = CyberSleuthUltra(target=args.target, port_mode=args.ports)
    results = scanner.run(verbose=args.verbose)

    # Print to terminal
    Reporter.print_results(results)

    # Save outputs
    if args.output:
        Reporter.save_json(results, f"{args.output}.json")
        if not args.json_only:
            Reporter.save_html(results, f"{args.output}.html")


if __name__ == "__main__":
    main()
