"""
mitmproxy allowlist filter — controls what the VM can access.

All network access is governed by allowlist.txt.  Each non-blank,
non-comment line must be:

    METHOD https://hostname/path/pattern

Wildcards (*) are allowed only in the path, not in the hostname.
The filter reloads the file automatically when it changes.
"""

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http

# ── Paths ───────────────────────────────────────────────────────────
ALLOWLIST_PATH = Path(__file__).parent / "allowlist.txt"
BLOCKED_LOG = Path(__file__).parent / ".vm" / "blocked.jsonl"

# ── Cached state ────────────────────────────────────────────────────
_rules: list[tuple[str, str]] = []
_mtime: float = 0.0


def parse_allowlist(path: Path) -> list[tuple[str, str]]:
    """Parse *path* into a list of ``(METHOD, url_pattern)`` tuples.

    Lines that are blank or start with ``#`` are skipped.  Every other line
    must be ``METHOD https://host/path...`` — bare domains and wildcard
    hostnames are rejected with a warning printed to the mitmproxy log.
    """
    rules: list[tuple[str, str]] = []
    if not path.exists():
        return rules
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"[filter] {path.name}:{lineno}: expected 'METHOD URL', got: {raw!r}")
            continue
        method, url_pattern = parts
        method = method.upper()
        parsed = urlparse(url_pattern)
        if not parsed.scheme or not parsed.hostname:
            print(f"[filter] {path.name}:{lineno}: invalid URL: {url_pattern!r}")
            continue
        if "*" in parsed.hostname:
            print(
                f"[filter] {path.name}:{lineno}: wildcards not allowed in domain:"
                f" {parsed.hostname!r}"
            )
            continue
        rules.append((method, url_pattern))
    return rules


def _maybe_reload() -> None:
    """Re-read allowlist.txt if it has been modified since last check."""
    global _rules, _mtime
    try:
        mt = ALLOWLIST_PATH.stat().st_mtime
    except FileNotFoundError:
        if _rules or _mtime:
            _rules, _mtime = [], 0.0
        return
    if mt != _mtime:
        _rules = parse_allowlist(ALLOWLIST_PATH)
        _mtime = mt


def is_allowed(
    rules: list[tuple[str, str]],
    method: str,
    host: str,
    url: str,
) -> bool:
    """Return True if the request is permitted.

    A ``GET`` rule implicitly allows ``HEAD`` requests to the same URL
    pattern.
    """
    req_path = urlparse(url).path or "/"

    for rule_method, url_pattern in rules:
        check = "GET" if method == "HEAD" and rule_method == "GET" else method
        if rule_method != check:
            continue
        parsed = urlparse(url_pattern)
        if parsed.hostname != host:
            continue
        pat_path = parsed.path or "/"
        path_re = re.escape(pat_path).replace(r"\*", ".*")
        if re.fullmatch(path_re, req_path):
            return True
    return False


def _log_blocked(flow: http.HTTPFlow) -> None:
    """Append a JSON line to the blocked-requests log."""
    try:
        BLOCKED_LOG.parent.mkdir(parents=True, exist_ok=True)
        with BLOCKED_LOG.open("a") as f:
            json.dump(
                {
                    "ts": time.time(),
                    "method": flow.request.method,
                    "host": flow.request.pretty_host,
                    "url": flow.request.pretty_url,
                },
                f,
            )
            f.write("\n")
    except OSError:
        pass


BLOCKED_STATUS = 418


def _blocked_body(method: str, url: str) -> str:
    """Build the response body for a blocked request."""
    parsed = urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return (
        "================================================================\n"
        "PROXY BLOCK — HTTP 418 (not a remote server error)\n"
        "================================================================\n"
        "\n"
        f"Blocked:  {method} {url}\n"
        "\n"
        "This VM's outbound traffic is filtered by an allowlist proxy\n"
        'to prevent the "lethal trifecta" (code execution + internet\n'
        "access + autonomy without human oversight).  A 418 response\n"
        "means the proxy blocked this request — it never left the VM.\n"
        "\n"
        "STOP.  Do not retry or try to work around this block.\n"
        "\n"
        "Instead, ask the user to approve this request by adding a\n"
        "rule to allowlist.txt on the host machine.  Suggest a\n"
        "narrowly-scoped rule and justify any wildcards:\n"
        "\n"
        f"    {method} {clean_url}\n"
        "\n"
        "Changes to allowlist.txt take effect on the next request.\n"
        "================================================================\n"
    )


class AllowlistAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        _maybe_reload()
        if is_allowed(
            _rules, flow.request.method, flow.request.pretty_host, flow.request.pretty_url
        ):
            return
        method = flow.request.method
        url = flow.request.pretty_url
        print(f"[filter] BLOCKED {method} {url}")
        _log_blocked(flow)
        flow.response = http.Response.make(
            BLOCKED_STATUS,
            _blocked_body(method, url),
            {"Content-Type": "text/plain"},
        )


addons = [AllowlistAddon()]
