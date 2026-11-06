"""Security rules. Each rule yields Finding objects; run_checks() merges them."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, Iterator, List
from urllib.parse import urlsplit

from .har import Entry
from .redact import find_sensitive_fields, looks_sensitive, mask, redact_url

RANK = {"high": 3, "medium": 2, "low": 1}
_LOCAL = {"localhost", "127.0.0.1", "::1"}
_SESSIONISH = re.compile(r"sess|sid$|auth|token|jwt", re.IGNORECASE)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    url: str
    remediation: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def is_local(host: str) -> bool:
    return host in _LOCAL or host.endswith(".localhost")


def is_document(e: Entry) -> bool:
    return e.mime in ("text/html", "application/xhtml+xml") and 200 <= e.status < 300


def check_headers(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL001: missing or weak security headers, once per origin."""
    seen = set()
    for e in entries:
        if not is_document(e) or e.origin in seen:
            continue
        seen.add(e.origin)
        u = redact_url(e.url)
        csp = e.resp("content-security-policy")
        if csp is None:
            yield Finding("HL001", "medium", "Missing Content-Security-Policy",
                          f"{e.origin} served an HTML page without a CSP, so injected scripts are not restricted.",
                          u, "Send a Content-Security-Policy header, starting from default-src 'self'.")
        if e.resp("x-frame-options") is None and "frame-ancestors" not in (csp or "").lower():
            yield Finding("HL001", "medium", "No clickjacking protection",
                          f"{e.origin} can be embedded in a frame on any site.",
                          u, "Add CSP frame-ancestors 'self' (or X-Frame-Options: DENY).")
        if (e.resp("x-content-type-options") or "").lower() != "nosniff":
            yield Finding("HL001", "low", "Missing X-Content-Type-Options: nosniff",
                          f"{e.origin} lets browsers guess content types.",
                          u, "Send X-Content-Type-Options: nosniff.")
        if e.resp("referrer-policy") is None:
            yield Finding("HL001", "low", "Missing Referrer-Policy",
                          f"{e.origin} sends full URLs as the Referer header to other sites by default.",
                          u, "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).")
        if e.scheme == "https" and not is_local(e.host):
            hsts = e.resp("strict-transport-security")
            if hsts is None:
                yield Finding("HL001", "medium", "Missing Strict-Transport-Security",
                              f"{e.origin} does not tell browsers to insist on HTTPS.",
                              u, "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.")
            else:
                m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                if not m or int(m.group(1)) < 15552000:
                    yield Finding("HL001", "low", "Short Strict-Transport-Security lifetime",
                                  f"{e.origin} sets HSTS for less than 180 days.",
                                  u, "Raise max-age to at least 15552000 (180 days); 31536000 is common.")


def _parse_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), attrs


def check_cookies(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL002: cookie flags. Values are never read into findings."""
    seen = set()
    for e in entries:
        for raw in e.resp_all("set-cookie"):
            name, attrs = _parse_cookie(raw)
            if not name or (e.host, name) in seen:
                continue
            seen.add((e.host, name))
            u = redact_url(e.url)
            where = f"Cookie '{name}' from {e.host}"
            if e.scheme == "https" and "secure" not in attrs:
                yield Finding("HL002", "medium", "Cookie without Secure flag",
                              f"{where} can be sent over plain HTTP.", u, "Add the Secure attribute.")
            if "httponly" not in attrs:
                sev = "high" if _SESSIONISH.search(name) else "medium"
                yield Finding("HL002", sev, "Cookie without HttpOnly flag",
                              f"{where} is readable by page scripts, so XSS can steal it.", u,
                              "Add the HttpOnly attribute unless scripts truly need the cookie.")
            samesite = attrs.get("samesite", "").lower()
            if not samesite:
                yield Finding("HL002", "low", "Cookie without SameSite attribute",
                              f"{where} relies on browser defaults for cross-site behaviour.", u,
                              "Set SameSite=Lax (or Strict) explicitly.")
            elif samesite == "none" and "secure" not in attrs:
                yield Finding("HL002", "high", "SameSite=None without Secure",
                              f"{where} will be rejected by modern browsers.", u,
                              "SameSite=None requires the Secure attribute.")


def check_mixed_content(entries: List[Entry]) -> Iterator[Finding]:
    """HL003: http:// requests in a capture that loaded https pages."""
    if not any(is_document(e) and e.scheme == "https" for e in entries):
        return
    seen = set()
    for e in entries:
        if e.scheme != "http" or is_local(e.host):
            continue
        location = e.resp("location") or ""
        if 300 <= e.status < 400 and location.lower().startswith("https://"):
            continue  # a normal HTTP-to-HTTPS upgrade
        key = (e.host, e.path)
        if key in seen:
            continue
        seen.add(key)
        active = any(t in e.mime for t in ("javascript", "css", "html"))
        yield Finding("HL003", "high" if active else "medium",
                      "Active mixed content" if active else "Mixed content",
                      f"An HTTPS page requested {e.host}{e.path} over plain HTTP.",
                      redact_url(e.url), "Load this resource over HTTPS.")


def check_url_secrets(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL004: credentials or secrets inside URLs."""
    seen = set()
    for e in entries:
        try:
            parts = urlsplit(e.url)
            userinfo = parts.username or parts.password
        except ValueError:
            continue
        if userinfo and (e.host, "userinfo") not in seen:
            seen.add((e.host, "userinfo"))
            yield Finding("HL004", "high", "Credentials embedded in URL",
                          f"A request to {e.host} puts a username or password in the URL itself.",
                          redact_url(e.url), "Send credentials in an Authorization header or request body.")
        for name, value in e.query:
            key = (e.host, e.path, name)
            if value and looks_sensitive(name) and key not in seen:
                seen.add(key)
                cleartext = e.scheme == "http" and not is_local(e.host)
                yield Finding("HL004", "high" if cleartext else "medium", "Secret in URL query string",
                              f"Parameter '{name}' carries a value ({mask(value)}). URLs end up in logs, "
                              "browser history and Referer headers.",
                              redact_url(e.url), "Move secrets to headers or the request body.")


def check_cleartext_credentials(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL005: credentials sent in headers or bodies over plain HTTP."""
    seen = set()
    for e in entries:
        if e.scheme != "http" or is_local(e.host) or (e.host, e.path) in seen:
            continue
        kinds = [h for h in ("Authorization", "Proxy-Authorization", "Cookie") if e.req(h)]
        fields = find_sensitive_fields(e.post_text, e.post_params, e.post_mime)
        if fields:
            kinds.append("body field(s): " + ", ".join(fields))
        if kinds:
            seen.add((e.host, e.path))
            yield Finding("HL005", "high", "Credentials sent over plain HTTP",
                          f"{e.method} {e.host}{e.path} sent {'; '.join(kinds)} without encryption.",
                          redact_url(e.url), "Serve this endpoint over HTTPS only and redirect HTTP to it.")


def check_cors(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL006: risky CORS configuration."""
    seen = set()
    for e in entries:
        origin = e.resp("access-control-allow-origin")
        if origin is None or e.origin in seen:
            continue
        creds = (e.resp("access-control-allow-credentials") or "").lower() == "true"
        if origin.strip() == "*" and creds:
            seen.add(e.origin)
            yield Finding("HL006", "high", "Wildcard CORS origin with credentials",
                          f"{e.origin} allows any origin and credentials; browsers reject it, which signals a broken policy.",
                          redact_url(e.url), "Return an explicit allow-listed origin instead of *.")
        elif origin.strip().lower() == "null":
            seen.add(e.origin)
            yield Finding("HL006", "medium", "CORS allows the 'null' origin",
                          f"{e.origin} trusts sandboxed and local documents.",
                          redact_url(e.url), "Remove 'null' from the allowed origins.")


def check_disclosure(entries: Iterable[Entry]) -> Iterator[Finding]:
    """HL007: headers that reveal software versions."""
    seen = set()
    for e in entries:
        if e.origin in seen:
            continue
        server, powered = e.resp("server") or "", e.resp("x-powered-by")
        if re.search(r"\d+\.\d+", server) or powered:
            seen.add(e.origin)
            shown = ", ".join(x for x in (f"Server: {server}" if server else "",
                                          f"X-Powered-By: {powered}" if powered else "") if x)
            yield Finding("HL007", "low", "Software details exposed in headers",
                          f"{e.origin} reveals {shown}.", redact_url(e.url),
                          "Remove X-Powered-By and strip version numbers from Server.")


RULES = [check_headers, check_cookies, check_mixed_content, check_url_secrets,
         check_cleartext_credentials, check_cors, check_disclosure]


def run_checks(entries: List[Entry]) -> List[Finding]:
    findings = [f for rule in RULES for f in rule(entries)]
    findings.sort(key=lambda f: (-RANK[f.severity], f.rule, f.url, f.title))
    return findings


def summarize(findings: Iterable[Finding]) -> Dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity] += 1
    return out
