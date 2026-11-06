import json
import os
import tempfile


def entry(url, status=200, mime="text/html", method="GET", req=None, resp=None, post=None):
    request = {"method": method, "url": url, "headers": [{"name": k, "value": v} for k, v in (req or {}).items()]}
    if post:
        request["postData"] = post
    return {
        "request": request,
        "response": {"status": status, "headers": [{"name": k, "value": v} for k, v in (resp or [])],
                     "content": {"mimeType": mime}},
    }


def har(*entries):
    return {"log": {"version": "1.2", "entries": list(entries)}}


def write_tmp(test, data, raw=False):
    fd, path = tempfile.mkstemp(suffix=".har")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data if raw else json.dumps(data))
    test.addCleanup(os.remove, path)
    return path
