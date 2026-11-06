"""Load and normalise HAR (HTTP Archive) files."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

MAX_BYTES = 256 * 1024 * 1024
Pairs = List[Tuple[str, str]]


class HarError(Exception):
    """Raised for input problems that the user can fix."""


def _pairs(items) -> Pairs:
    out: Pairs = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                out.append((item["name"], str(item.get("value", ""))))
    return out


def _int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Entry:
    index: int
    method: str
    url: str
    scheme: str
    host: str
    path: str
    status: int
    mime: str
    req_headers: Pairs = field(default_factory=list)
    resp_headers: Pairs = field(default_factory=list)
    query: Pairs = field(default_factory=list)
    post_text: str = ""
    post_params: Pairs = field(default_factory=list)
    post_mime: str = ""

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}"

    def req(self, name: str) -> Optional[str]:
        vals = [v for k, v in self.req_headers if k.lower() == name.lower()]
        return vals[0] if vals else None

    def resp_all(self, name: str) -> List[str]:
        return [v for k, v in self.resp_headers if k.lower() == name.lower()]

    def resp(self, name: str) -> Optional[str]:
        vals = self.resp_all(name)
        return vals[0] if vals else None


def _entry(index: int, raw) -> Optional[Entry]:
    if not isinstance(raw, dict):
        return None
    req = raw.get("request") if isinstance(raw.get("request"), dict) else {}
    resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
    url = req.get("url")
    if not isinstance(url, str) or not url:
        return None
    try:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
    post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
    return Entry(
        index=index,
        method=str(req.get("method", "GET")).upper(),
        url=url,
        scheme=parts.scheme.lower(),
        host=parts.hostname.lower(),
        path=parts.path or "/",
        status=_int(resp.get("status")),
        mime=str(content.get("mimeType", "")).split(";")[0].strip().lower(),
        req_headers=_pairs(req.get("headers")),
        resp_headers=_pairs(resp.get("headers")),
        query=query,
        post_text=str(post.get("text", "")) if post.get("text") else "",
        post_params=_pairs(post.get("params")),
        post_mime=str(post.get("mimeType", "")).split(";")[0].strip().lower(),
    )


def parse_har(data) -> Tuple[List[Entry], int]:
    """Return (entries, skipped_count). Raise HarError if not a usable HAR."""
    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise HarError("Not a HAR file: expected a top-level 'log' object with an 'entries' list.")
    raw_entries = log["entries"]
    if not raw_entries:
        raise HarError("The HAR file contains no entries; record some traffic and export again.")
    entries, skipped = [], 0
    for i, raw in enumerate(raw_entries):
        e = _entry(i, raw)
        if e is None:
            skipped += 1
        else:
            entries.append(e)
    if not entries:
        raise HarError("None of the entries had a usable request URL.")
    return entries, skipped


def load_json(path: str):
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise HarError(f"Cannot read '{path}': {exc.strerror or exc}.")
    if size == 0:
        raise HarError(f"'{path}' is empty.")
    if size > MAX_BYTES:
        raise HarError(f"'{path}' is larger than {MAX_BYTES // (1024 * 1024)} MB; refusing to load it.")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except UnicodeDecodeError:
        raise HarError(f"'{path}' is not UTF-8 text.")
    except json.JSONDecodeError as exc:
        raise HarError(f"'{path}' is not valid JSON (line {exc.lineno}, column {exc.colno}).")
    except OSError as exc:
        raise HarError(f"Cannot read '{path}': {exc.strerror or exc}.")


def load_har(path: str) -> Tuple[List[Entry], int]:
    return parse_har(load_json(path))
