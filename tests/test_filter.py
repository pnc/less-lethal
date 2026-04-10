"""
Unit tests for filter.py allowlist logic.

These run entirely on the host (no VM required) and exercise:
  - parse_allowlist()  — file parsing
  - is_allowed()       — rule matching
  - AllowlistAddon     — mitmproxy integration + blocked.jsonl logging
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# filter.py lives at the repo root, not inside tests/
sys.path.insert(0, str(Path(__file__).parent.parent))
import filter as fm  # "filter" shadows the builtin — alias keeps it clear


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _write_allowlist(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "allowlist"
    p.write_text(content)
    return p


def _make_flow(method: str, host: str, url: str) -> MagicMock:
    flow = MagicMock()
    flow.request.method = method
    flow.request.pretty_host = host
    flow.request.pretty_url = url
    flow.response = None
    return flow


@pytest.fixture()
def filter_env(monkeypatch, tmp_path):
    """
    Redirect filter.py's module-level paths and reset cached state.
    Returns (allowlist_path, blocked_log_path).
    """
    allowlist = tmp_path / "allowlist"
    blocked = tmp_path / "blocked.jsonl"
    monkeypatch.setattr(fm, "ALLOWLIST_PATH", allowlist)
    monkeypatch.setattr(fm, "BLOCKED_LOG", blocked)
    monkeypatch.setattr(fm, "_rules", [])
    monkeypatch.setattr(fm, "_mtime", 0.0)
    return allowlist, blocked


# ---------------------------------------------------------------------------
# parse_allowlist
# ---------------------------------------------------------------------------

class TestParseAllowlist:
    def test_method_url_rule(self, tmp_path):
        rules = fm.parse_allowlist(
            _write_allowlist(tmp_path, "GET https://api.example.com/*\n")
        )
        assert rules == [("GET", "https://api.example.com/*")]

    def test_method_url_rule_case_insensitive(self, tmp_path):
        rules = fm.parse_allowlist(_write_allowlist(tmp_path, "post https://x.com/\n"))
        assert rules == [("POST", "https://x.com/")]

    def test_bare_domain_rejected(self, tmp_path):
        rules = fm.parse_allowlist(_write_allowlist(tmp_path, "example.com\n"))
        assert rules == []

    def test_wildcard_domain_rejected(self, tmp_path):
        rules = fm.parse_allowlist(
            _write_allowlist(tmp_path, "GET https://*.example.com/path\n")
        )
        assert rules == []

    def test_skips_comments(self, tmp_path):
        rules = fm.parse_allowlist(
            _write_allowlist(tmp_path, "# comment\nGET https://example.com/*\n")
        )
        assert rules == [("GET", "https://example.com/*")]

    def test_skips_blank_lines(self, tmp_path):
        rules = fm.parse_allowlist(
            _write_allowlist(tmp_path, "\n  \nGET https://example.com/*\n\n")
        )
        assert rules == [("GET", "https://example.com/*")]

    def test_multiple_rules(self, tmp_path):
        rules = fm.parse_allowlist(
            _write_allowlist(tmp_path, "GET https://a.com/*\nPOST https://b.com/api\n")
        )
        assert rules == [("GET", "https://a.com/*"), ("POST", "https://b.com/api")]

    def test_missing_file_returns_empty(self, tmp_path):
        rules = fm.parse_allowlist(tmp_path / "nonexistent")
        assert rules == []


# ---------------------------------------------------------------------------
# is_allowed — pure function, no fixture needed
# ---------------------------------------------------------------------------

class TestIsAllowed:
    def test_trusted_domain_allows_any_method(self):
        assert fm.is_allowed([], "GET", "pypi.org", "https://pypi.org/simple/")
        assert fm.is_allowed([], "POST", "pypi.org", "https://pypi.org/")

    def test_trusted_domain_regex(self):
        assert fm.is_allowed([], "GET", "ftp.debian.org", "http://ftp.debian.org/")
        assert fm.is_allowed([], "GET", "security.debian.org", "http://security.debian.org/")

    def test_non_trusted_domain_blocked(self):
        assert not fm.is_allowed([], "GET", "example.com", "http://example.com/")

    def test_method_url_rule_matching(self):
        rules = [("GET", "https://api.example.com/*")]
        assert fm.is_allowed(
            rules, "GET", "api.example.com", "https://api.example.com/v1/users"
        )

    def test_method_url_rule_wrong_method(self):
        rules = [("GET", "https://api.example.com/*")]
        assert not fm.is_allowed(
            rules, "POST", "api.example.com", "https://api.example.com/v1/users"
        )

    def test_method_url_rule_wrong_host(self):
        rules = [("GET", "https://api.example.com/*")]
        assert not fm.is_allowed(
            rules, "GET", "other.com", "https://other.com/v1/users"
        )

    def test_method_url_rule_wrong_path(self):
        rules = [("GET", "https://api.example.com/v1/*")]
        assert not fm.is_allowed(
            rules, "GET", "api.example.com", "https://api.example.com/v2/users"
        )

    def test_get_rule_also_allows_head(self):
        rules = [("GET", "https://example.com/*")]
        assert fm.is_allowed(rules, "HEAD", "example.com", "https://example.com/page")

    def test_post_rule_does_not_allow_head(self):
        rules = [("POST", "https://example.com/*")]
        assert not fm.is_allowed(rules, "HEAD", "example.com", "https://example.com/")

    def test_wildcard_crosses_path_separators(self):
        rules = [("GET", "https://example.com/*")]
        assert fm.is_allowed(
            rules, "GET", "example.com", "https://example.com/a/b/c/d"
        )

    def test_empty_rules_block_everything(self):
        assert not fm.is_allowed([], "GET", "example.com", "http://example.com/")


# ---------------------------------------------------------------------------
# AllowlistAddon integration
# ---------------------------------------------------------------------------

class TestAllowlistAddon:
    def test_allows_matching_rule(self, filter_env):
        allowlist, _ = filter_env
        allowlist.write_text("GET https://example.com/*\n")

        addon = fm.AllowlistAddon()
        flow = _make_flow("GET", "example.com", "https://example.com/page")
        addon.request(flow)
        assert flow.response is None  # not blocked

    def test_blocks_unmatched_request(self, filter_env):
        allowlist, _ = filter_env
        allowlist.write_text("GET https://example.com/*\n")

        addon = fm.AllowlistAddon()
        flow = _make_flow("GET", "cisco.com", "http://cisco.com/")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 418

    def test_blocked_response_mentions_allowlist(self, filter_env):
        allowlist, _ = filter_env
        allowlist.write_text("")

        addon = fm.AllowlistAddon()
        flow = _make_flow("GET", "cisco.com", "http://cisco.com/")
        addon.request(flow)
        body = flow.response.content.decode()
        assert "allowlist" in body.lower()

    def test_blocked_request_logged_to_jsonl(self, filter_env):
        allowlist, blocked = filter_env
        allowlist.write_text("GET https://example.com/*\n")

        addon = fm.AllowlistAddon()
        flow = _make_flow("GET", "cisco.com", "http://cisco.com/index.html")
        addon.request(flow)

        assert blocked.exists()
        entry = json.loads(blocked.read_text().strip())
        assert entry["method"] == "GET"
        assert entry["url"] == "http://cisco.com/index.html"
        assert entry["host"] == "cisco.com"
        assert "ts" in entry

    def test_allowed_request_not_logged(self, filter_env):
        allowlist, blocked = filter_env
        allowlist.write_text("GET https://example.com/*\n")

        addon = fm.AllowlistAddon()
        flow = _make_flow("GET", "example.com", "https://example.com/")
        addon.request(flow)
        assert not blocked.exists()

    def test_multiple_blocks_append_to_jsonl(self, filter_env):
        allowlist, blocked = filter_env
        allowlist.write_text("")

        addon = fm.AllowlistAddon()
        for host in ("a.com", "b.com", "c.com"):
            flow = _make_flow("GET", host, f"http://{host}/")
            addon.request(flow)

        lines = blocked.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_reload_when_allowlist_changes(self, filter_env):
        allowlist, _ = filter_env
        # Start with empty allowlist → request is blocked
        allowlist.write_text("")

        addon = fm.AllowlistAddon()
        flow1 = _make_flow("GET", "example.com", "https://example.com/")
        addon.request(flow1)
        assert flow1.response is not None  # blocked

        # Add a rule and bump mtime so _maybe_reload notices the change
        allowlist.write_text("GET https://example.com/*\n")
        st = allowlist.stat()
        os.utime(allowlist, (st.st_atime, st.st_mtime + 1))

        flow2 = _make_flow("GET", "example.com", "https://example.com/")
        addon.request(flow2)
        assert flow2.response is None  # now allowed

    def test_allows_head_when_get_rule_matches(self, filter_env):
        allowlist, _ = filter_env
        allowlist.write_text("GET https://example.com/*\n")

        addon = fm.AllowlistAddon()
        flow = _make_flow("HEAD", "example.com", "https://example.com/page")
        addon.request(flow)
        assert flow.response is None  # HEAD permitted by GET rule
