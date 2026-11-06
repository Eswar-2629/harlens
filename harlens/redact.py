"""Helpers that find, mask and remove sensitive values."""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit

REDACTED = "[REDACTED]"
URL_REDACTED = "REDACTED"

_SENSITIVE = re.compile(
    r"(^|[^a-z])(token|password|passwd|pwd|secret|api[-_]?key|apikey|auth|authorization|"
    r"session|sessionid|sid|jwt|signature|credential|credentials)s?([^a-z]|$)",
    re.IGNORECASE,
)
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
}


def looks_sensitive(name: str) -> bool:
    return bool(_SENSITIVE.search(name or ""))


def mask(value: str) -> str:
    """Show just enough of a secret to recognise it, never the whole thing."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return f"{value[:2]}***({len(value)} chars)"


def redact_url(url: str) -> str:
    """Remove credentials, sensitive query values and the fragment from a URL."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "[unparseable URL]"
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    pairs = []
    for chunk in parts.query.split("&") if parts.query else []:
        name, sep, value = chunk.partition("=")
        if sep and value and looks_sensitive(name):
            value = URL_REDACTED
        pairs.append(f"{name}{sep}{value}")
    query = "&".join(pairs)
    out = f"{parts.scheme}://{netloc}{parts.path}"
    return out + (f"?{query}" if query else "")


def _walk_json(obj: Any, found: List[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if looks_sensitive(str(k)) and isinstance(v, (str, int, float)) and v not in ("", None):
                found.append(str(k))
            _walk_json(v, found)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json(v, found)


def find_sensitive_fields(text: str, params: List[Tuple[str, str]], mime: str) -> List[str]:
    """Names of sensitive-looking, non-empty fields in a request body."""
    names = [k for k, v in params if v and looks_sensitive(k)]
    if text and "json" in mime:
        try:
            _walk_json(json.loads(text), names)
        except ValueError:
            pass
    elif text and "x-www-form-urlencoded" in mime:
        names += [k for k, v in parse_qsl(text, keep_blank_values=True) if v and looks_sensitive(k)]
    return sorted(set(names))


def _redact_json(obj: Any, count: List[int]) -> Any:
    if isinstance(obj, dict):
        for k in list(obj):
            v = obj[k]
            if looks_sensitive(str(k)) and isinstance(v, (str, int, float)) and v not in ("", None):
                obj[k] = REDACTED
                count[0] += 1
            else:
                _redact_json(v, count)
    elif isinstance(obj, list):
        for v in obj:
            _redact_json(v, count)
    return obj


def _redact_text_body(text: str, mime: str, count: List[int]) -> str:
    if "json" in mime:
        try:
            return json.dumps(_redact_json(json.loads(text), count))
        except ValueError:
            return text
    if "x-www-form-urlencoded" in mime:
        out = []
        for chunk in text.split("&"):
            name, sep, value = chunk.partition("=")
            if sep and value and looks_sensitive(name):
                value = URL_REDACTED
                count[0] += 1
            out.append(f"{name}{sep}{value}")
        return "&".join(out)
    return text


def _redact_cookie_header(value: str, is_set_cookie: bool) -> str:
    """Hide cookie values but keep names and attributes so the file stays auditable."""
    parts = [p.strip() for p in value.split(";")]
    if is_set_cookie:
        name = parts[0].partition("=")[0]
        return "; ".join([f"{name}={REDACTED}"] + parts[1:])
    return "; ".join(f"{p.partition('=')[0]}={REDACTED}" if "=" in p else p for p in parts)


def sanitize_har(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Return (sanitised copy, number of redactions). The input is not modified."""
    clean = copy.deepcopy(data)
    count = [0]

    def headers(items):
        for h in items if isinstance(items, list) else []:
            if not (isinstance(h, dict) and str(h.get("name", "")).lower() in SENSITIVE_HEADERS and h.get("value")):
                continue
            kind = str(h["name"]).lower()
            if kind in ("cookie", "set-cookie"):
                h["value"] = _redact_cookie_header(str(h["value"]), kind == "set-cookie")
            else:
                h["value"] = REDACTED
            count[0] += 1

    def cookies(items):
        for c in items if isinstance(items, list) else []:
            if isinstance(c, dict) and c.get("value"):
                c["value"] = REDACTED
                count[0] += 1

    def url_field(holder, key):
        if isinstance(holder.get(key), str) and holder[key]:
            new = redact_url(holder[key])
            if new != holder[key]:
                count[0] += 1
            holder[key] = new

    for entry in (clean.get("log", {}).get("entries", []) if isinstance(clean.get("log"), dict) else []):
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        headers(req.get("headers")); headers(resp.get("headers"))
        cookies(req.get("cookies")); cookies(resp.get("cookies"))
        url_field(req, "url"); url_field(resp, "redirectURL")
        for q in req.get("queryString", []) if isinstance(req.get("queryString"), list) else []:
            if isinstance(q, dict) and looks_sensitive(str(q.get("name", ""))) and q.get("value"):
                q["value"] = URL_REDACTED
                count[0] += 1
        post = req.get("postData") if isinstance(req.get("postData"), dict) else None
        if post:
            for p in post.get("params", []) if isinstance(post.get("params"), list) else []:
                if isinstance(p, dict) and looks_sensitive(str(p.get("name", ""))) and p.get("value"):
                    p["value"] = REDACTED
                    count[0] += 1
            if isinstance(post.get("text"), str):
                post["text"] = _redact_text_body(post["text"], str(post.get("mimeType", "")).lower(), count)
        content = resp.get("content") if isinstance(resp.get("content"), dict) else None
        if content and isinstance(content.get("text"), str) and "base64" not in str(content.get("encoding", "")):
            content["text"] = _redact_text_body(content["text"], str(content.get("mimeType", "")).lower(), count)
    return clean, count[0]
