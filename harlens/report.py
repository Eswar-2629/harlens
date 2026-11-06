"""Render audit results as text or a self-contained, accessible HTML page."""
from __future__ import annotations

from html import escape
from typing import Dict, List

from .checks import Finding, summarize


def render_text(source: str, entries: int, skipped: int, findings: List[Finding]) -> str:
    s = summarize(findings)
    lines = [f"HARLens audit: {source}",
             f"Requests analysed: {entries}" + (f" ({skipped} unusable entries skipped)" if skipped else ""),
             f"Findings: {s['high']} high, {s['medium']} medium, {s['low']} low", ""]
    if not findings:
        lines.append("No findings. This only means the 7 built-in rules found nothing in this capture.")
    for f in findings:
        lines += [f"[{f.severity.upper()}] {f.rule} {f.title}", f"  {f.url}", f"  {f.detail}", f"  Fix: {f.remediation}", ""]
    return "\n".join(lines).rstrip() + "\n"


def to_json_dict(source: str, entries: int, skipped: int, findings: List[Finding]) -> Dict:
    return {"source": source, "entries": entries, "skipped": skipped,
            "summary": summarize(findings), "findings": [f.to_dict() for f in findings]}


_CSS = """
:root{--bg:#f2f5f7;--panel:#fff;--text:#14212b;--muted:#4b5d6a;--rule:#c9d4db;--high:#a61b1b;--medium:#8a5200;--low:#1d5f8f;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0e1a21;--panel:#15252e;--text:#dce8ee;--muted:#9bb0bc;--rule:#2b4250;--high:#ff8c84;--medium:#f0b455;--low:#7cc0f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:1rem/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:56rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.6rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin:2rem 0 .75rem}h3{font-size:1rem;margin:0}
.src{color:var(--muted);margin:0 0 1.25rem;overflow-wrap:anywhere}
.bar{display:flex;height:.9rem;border-radius:.2rem;overflow:hidden;background:var(--rule)}
.bar span{display:block}.b-high{background:var(--high)}.b-medium{background:var(--medium)}.b-low{background:var(--low)}
.tally{display:flex;flex-wrap:wrap;gap:.5rem 1.5rem;list-style:none;padding:0;margin:.75rem 0 0;font-weight:600}
.tally .n{font-size:1.4rem}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
article{background:var(--panel);border:1px solid var(--rule);border-left:.35rem solid var(--rule);padding:.8rem 1rem;margin:0 0 .75rem;border-radius:.25rem}
article.high{border-left-color:var(--high)}article.medium{border-left-color:var(--medium)}article.low{border-left-color:var(--low)}
.sev{font-weight:700;margin-right:.5rem}.rule{color:var(--muted);font-size:.85rem;margin-left:.5rem}
code{font:.85rem ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;display:block;margin:.35rem 0}
p{margin:.35rem 0}.fix{color:var(--muted)}.empty{background:var(--panel);border:1px dashed var(--rule);padding:1rem;border-radius:.25rem}
@media (max-width:30rem){h1{font-size:1.3rem}}
"""


def render_html(source: str, entries: int, skipped: int, findings: List[Finding]) -> str:
    s = summarize(findings)
    total = max(sum(s.values()), 1)
    bar = "".join(f'<span class="b-{k}" style="width:{s[k] * 100 / total:.1f}%"></span>' for k in s if s[k])
    tally = "".join(f'<li class="{k}"><span class="n">{s[k]}</span> {k}</li>' for k in ("high", "medium", "low"))
    body = []
    for f in findings:
        body.append(
            f'<article class="{escape(f.severity)}"><h3><span class="sev {escape(f.severity)}">{escape(f.severity.capitalize())}</span>'
            f'{escape(f.title)}<span class="rule">{escape(f.rule)}</span></h3><code>{escape(f.url)}</code>'
            f'<p>{escape(f.detail)}</p><p class="fix"><strong>Fix:</strong> {escape(f.remediation)}</p></article>')
    if not body:
        body.append('<p class="empty">No findings. This only means the 7 built-in rules found nothing in this '
                    "capture; it is not a guarantee that the site is secure.</p>")
    skipped_note = f" ({skipped} unusable entries skipped)" if skipped else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>HARLens report: {escape(source)}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>HARLens report</h1><p class=\"src\">{escape(source)}: {entries} requests analysed{escape(skipped_note)}</p>"
        f'<div class="bar" role="img" aria-label="{s["high"]} high, {s["medium"]} medium, {s["low"]} low findings">{bar}</div>'
        f'<ul class="tally">{tally}</ul><h2>Findings</h2>{"".join(body)}'
        "<p class=\"fix\">URLs in this report have credentials and sensitive query values removed.</p></main></body></html>\n")
