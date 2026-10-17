#!/usr/bin/env python3
"""Read-only original cross-repository public Actions Job log access diagnostic.

No credentials are logged; this cannot verify signing or create a PASS receipt.
Probe one numerically pinned public original Job. The optional pre-existing
GitHub App read-only token is only passed to api.github.com, never redirects.
"""
from __future__ import annotations
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener, urlopen

URL = "https://api.github.com/repos/pgextwin/pg_bigm/actions/jobs/114079409006/logs"
ALLOW = frozenset(("api.github.com", "github.com"))
LIMIT = 16 * 1024 * 1024


class StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def is_github_delivery(url):
    u = urlsplit(url)
    h = u.hostname or ""
    return u.scheme == "https" and (h in ALLOW or any(
        h.endswith(s) for s in (".actions.githubusercontent.com",
                                ".blob.core.windows.net", ".githubusercontent.com")))


def initial_get(token=""):
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "pgextwin-issue112-original-job-log-readonly/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = Request(URL, headers=headers, method="GET")
    try:
        with build_opener(StopRedirect()).open(req, timeout=30) as response:
            code, redirect = response.status, None
    except HTTPError as error:
        code = error.code
        redirect = error.headers.get("Location") if code in (301, 302, 303, 307, 308) else None
    except (OSError, URLError, TimeoutError) as error:
        return {"first": type(error).__name__, "redirect": "unavailable", "bytes": 0}
    info = {"first": code, "redirect": "absent", "bytes": 0}
    if redirect is not None:
        if not is_github_delivery(redirect):
            info["redirect"] = "unapproved"
            return info
        info["redirect"] = "allowed_https"
        try:
            # No Authorization header is ever forwarded to a signed redirect.
            with urlopen(Request(redirect, method="GET", headers={
                "User-Agent": "pgextwin-issue112-public-log-readonly/1",
            }), timeout=45) as response:
                info["delivery_http"] = response.status
                raw = response.read(LIMIT + 1)
                info["bytes"] = len(raw)
                info["bounded"] = 0 < len(raw) <= LIMIT
        except HTTPError as error:
            info["delivery_http"] = error.code
        except (OSError, URLError, TimeoutError) as error:
            info["delivery_error"] = type(error).__name__
    return info


def main():
    # Never print error URLs, request headers, access tokens, or original logs.
    results = {"schema": "pgextwin-issue112-log-access-diagnostic/v1",
               "probe": "public-original-pg_bigm-PG15-job-114079409006",
               "anonymous": initial_get(),
               "preexisting_app": {"status": "not_available"}}
    app = os.getenv("ISSUE112_READONLY_APP_TOKEN", "")
    if app:
        results["preexisting_app"] = initial_get(app)
    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
