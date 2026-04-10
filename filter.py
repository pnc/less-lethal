"""
mitmproxy allowlist filter — controls what the VM can access.

By default, all requests are blocked. Add domains or patterns to ALLOWED to
permit them. Edit this file freely; mitmproxy reloads it on change.

Pattern syntax: exact hostname string, or a regex (fullmatch against hostname).
"""

import re
from mitmproxy import http

# Domains the VM is allowed to reach.
# Examples:
#   "pypi.org"             — exact hostname match
#   r".*\.debian\.org"     — regex: any debian.org subdomain
ALLOWED: list[str] = [
    r".*\.debian\.org",
    "deb.debian.org",
    "security.debian.org",
    r".*\.ubuntu\.com",
    "pypi.org",
    r".*\.pypi\.org",
    "files.pythonhosted.org",
    "claude.ai",
    "storage.googleapis.com",
    "platform.claude.com",
    "api.anthropic.com",
    # mitmproxy's magic domain that serves the CA cert
    "mitm.it",
]

_patterns = [re.compile(p) for p in ALLOWED]


class AllowlistAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if any(p.fullmatch(host) for p in _patterns):
            return
        print(f"[filter] BLOCKED {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(
            403,
            f"Blocked by filter.py: {host!r} is not in the allowlist.\n"
            f"Edit filter.py to allow it.\n",
            {"Content-Type": "text/plain"},
        )


addons = [AllowlistAddon()]
