"""Unit tests for CyberSleuth Ultra v4.0 — pure logic, no network."""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cybersleuth_ultra import (
    Config, VulnerabilityEngine, ScanResults, PortScanner,
    sanitize_target, cvss_to_severity, severity_color,
    is_valid_ip, is_private_ip, is_html, looks_like_env, soft_404,
    esc, ContentScanner, SubdomainScanner,
)
from dataclasses import dataclass, field


# ── Target sanitization ─────────────────────────────────────────

class TestSanitize:
    def test_strips_https(self):
        assert sanitize_target("https://example.com") == "example.com"

    def test_strips_http_and_path(self):
        assert sanitize_target("http://example.com/foo/bar") == "example.com"

    def test_plain_domain(self):
        assert sanitize_target("example.com") == "example.com"

    def test_ip_kept(self):
        assert sanitize_target("93.184.216.34") == "93.184.216.34"


# ── IP helpers ──────────────────────────────────────────────────

class TestIPHelpers:
    def test_valid_ip(self):
        assert is_valid_ip("93.184.216.34")
        assert not is_valid_ip("example.com")

    def test_private_ip(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert not is_private_ip("8.8.8.8")


# ── Severity mapping ────────────────────────────────────────────

class TestSeverity:
    def test_cvss_to_severity(self):
        assert cvss_to_severity(9.8) == "Critical"
        assert cvss_to_severity(7.5) == "High"
        assert cvss_to_severity(5.3) == "Medium"
        assert cvss_to_severity(2.7) == "Low"
        assert cvss_to_severity(0.0) == "Info"

    def test_severity_colors_exist(self):
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            assert severity_color(sev)  # non-empty


# ── HTML / .env / soft-404 heuristics (accuracy fixes) ─────────

class TestContentHeuristics:
    def test_is_html_detects_pages(self):
        assert is_html("<!DOCTYPE html><html><body>hi</body></html>")
        assert is_html("<div class='x'>stuff</div>")
        assert not is_html("DB_PASSWORD=supersecret123")

    def test_looks_like_env_accepts_real_env(self):
        body = "DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=hunter2\nAPI_KEY=abc123\n"
        assert looks_like_env(body)

    def test_looks_like_env_accepts_multiline_no_hints(self):
        body = "foo=1\nbar=2\nbaz=3\nqux=4\n"
        assert looks_like_env(body)

    def test_looks_like_env_rejects_html_page(self):
        # v3 bug: any page containing '=' was flagged as an .env leak
        body = "<html><body>a = b and c = d, welcome to our site</body></html>"
        assert not looks_like_env(body)

    def test_looks_like_env_rejects_plain_sentence(self):
        body = "This is a sentence with an equals sign = and nothing else."
        assert not looks_like_env(body)

    def test_soft_404_detection(self):
        assert soft_404("<html><title>404 Not Found</title></html>", "text/html")
        assert not soft_404("<html><title>Welcome</title></html>", "text/html")
        assert not soft_404("404", "text/plain")


# ── HTML escaping ───────────────────────────────────────────────

class TestEscaping:
    def test_escapes_html(self):
        assert esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_escapes_quotes(self):
        assert '"' not in esc('say "hi"')
        assert "&quot;" in esc('say "hi"')

    def test_none_safe(self):
        assert esc(None) == ""


# ── Config sanity ───────────────────────────────────────────────

class TestConfig:
    def test_no_duplicate_ports(self):
        assert len(Config.TOP_100_PORTS) == len(set(Config.TOP_100_PORTS))
        assert len(Config.COMMON_PORTS) == len(set(Config.COMMON_PORTS))

    def test_ports_within_range(self):
        assert all(1 <= p <= 65535 for p in Config.TOP_100_PORTS)

    def test_takeover_fingerprints_nonempty(self):
        assert len(Config.TAKEOVER_FINGERPRINTS) >= 20

    def test_waf_signatures_nonempty(self):
        assert len(Config.WAF_SIGNATURES) >= 10

    def test_sensitive_verifiers_keyed_to_files(self):
        for path in Config.SENSITIVE_VERIFIERS:
            assert path in Config.SENSITIVE_FILES or path in (
                ".env", ".env.local", ".env.production", ".env.backup",
            )


# ── Vulnerability deduplication ─────────────────────────────────

class TestVulnDedupe:
    def _engine(self):
        res = ScanResults(target="example.com")
        return VulnerabilityEngine(res, session=None)

    def test_dedupe_removes_exact_duplicates(self):
        eng = self._engine()
        eng._add(name="A", severity="High", cvss=7.5, description="d",
                 evidence="same", remediation="r", cwe="CWE-200")
        eng._add(name="A", severity="High", cvss=7.5, description="d",
                 evidence="same", remediation="r", cwe="CWE-200")
        eng._dedupe()
        assert len(eng.vulns) == 1

    def test_dedupe_keeps_distinct_evidence(self):
        eng = self._engine()
        eng._add(name="A", severity="High", cvss=7.5, description="d",
                 evidence="one", remediation="r")
        eng._add(name="A", severity="High", cvss=7.5, description="d",
                 evidence="two", remediation="r")
        eng._dedupe()
        assert len(eng.vulns) == 2

    def test_sort_by_cvss(self):
        eng = self._engine()
        # neutralise email-security / header checks so only our 3 vulns exist
        eng.r.spf_record = "v=spf1 -all"
        eng.r.dmarc_record = "v=DMARC1; p=reject"
        eng.r.security_headers = {
            "X-Frame-Options": {"present": True, "value": "DENY", "secure": True},
            "Content-Security-Policy": {"present": True, "value": "frame-ancestors 'none'", "secure": True},
        }
        eng._add(name="low", severity="Low", cvss=2.7, description="d",
                 evidence="a", remediation="r")
        eng._add(name="crit", severity="Critical", cvss=9.8, description="d",
                 evidence="b", remediation="r")
        eng._add(name="med", severity="Medium", cvss=5.3, description="d",
                 evidence="c", remediation="r")
        out = eng.run_all()
        assert [v.name for v in out] == ["crit", "med", "low"]


# ── Subdomain validation (passive-source garbage filter) ───────

class TestSubdomainValidation:
    def test_accepts_real_subdomain(self):
        assert SubdomainScanner._valid_subdomain("api.example.com", "example.com")

    def test_rejects_apex(self):
        assert not SubdomainScanner._valid_subdomain("example.com", "example.com")

    def test_rejects_email_junk(self):
        # seen in crt.sh / HackerTarget output in the wild
        assert not SubdomainScanner._valid_subdomain("user@example.com", "example.com")
        assert not SubdomainScanner._valid_subdomain("subjectname@example.com", "example.com")

    def test_rejects_cn_strings_with_spaces(self):
        assert not SubdomainScanner._valid_subdomain("as207960 test intermediate - example.com", "example.com")

    def test_rejects_wildcard(self):
        assert not SubdomainScanner._valid_subdomain("*.example.com", "example.com")

    def test_rejects_unrelated_domain(self):
        assert not SubdomainScanner._valid_subdomain("api.other.com", "example.com")

    def test_rejects_underscore(self):
        assert not SubdomainScanner._valid_subdomain("_dmarc.example.com", "example.com")


# ── robots.txt parsing ──────────────────────────────────────────

class TestRobotsParsing:
    def test_parse_disallow(self):
        cs = ContentScanner("example.com", session=None)
        robots = """User-agent: *
Disallow: /admin
Disallow: /backup/*
Allow: /public
# comment
"""
        paths = cs.parse_robots_disallow(robots)
        assert "admin" in paths
        assert "backup" in paths
        assert "public" in paths

    def test_parse_empty(self):
        cs = ContentScanner("example.com", session=None)
        assert cs.parse_robots_disallow("") == []

    def test_parse_ignores_root(self):
        cs = ContentScanner("example.com", session=None)
        assert cs.parse_robots_disallow("Disallow: /\n") == []


# ── Missing headers are hardening, not vulnerabilities ─────────

class TestHeaderPosture:
    def test_missing_headers_not_counted_as_vulns(self):
        res = ScanResults(target="example.com")
        res.security_headers = {
            "Strict-Transport-Security": {"present": False, "value": "", "secure": False},
            "Content-Security-Policy":   {"present": False, "value": "", "secure": False},
        }
        eng = VulnerabilityEngine(res, session=None)
        eng.r.spf_record = "v=spf1 -all"
        eng.r.dmarc_record = "v=DMARC1; p=reject"
        out = eng.run_all()
        assert not any("Security Header" in v.name for v in out)
        names = [h["name"] for h in res.hardening_recommendations]
        assert "Missing Security Header: Strict-Transport-Security" in names
        assert all(h["severity"] == "Info" for h in res.hardening_recommendations)

    def test_present_secure_header_produces_no_recommendation(self):
        res = ScanResults(target="example.com")
        res.security_headers = {
            "Strict-Transport-Security": {"present": True, "value": "max-age=31536000", "secure": True},
        }
        eng = VulnerabilityEngine(res, session=None)
        eng.r.spf_record = "v=spf1 -all"
        eng.r.dmarc_record = "v=DMARC1; p=reject"
        eng.run_all()
        assert res.hardening_recommendations == []


# ── JSON schema stability (exploit_integration depends on it) ──

class TestJsonSchema:
    def test_results_serialize(self):
        res = ScanResults(target="example.com", ip_address="1.2.3.4")
        res.open_ports = [{"port": 443, "protocol": "tcp", "state": "open",
                           "service": "HTTPS", "banner": ""}]
        data = json.loads(json.dumps(res.__dict__, default=str))
        assert data["target"] == "example.com"
        assert data["open_ports"][0]["port"] == 443
        assert "vulnerabilities" in data