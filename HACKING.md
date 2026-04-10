# Hacking on Agent VM

Development notes for working on this project itself.

## Test suite

The test suite boots the VM end-to-end and verifies networking works correctly through mitmproxy.

```bash
uv run pytest tests/test_e2e.py -v -s
```

This takes ~90 seconds without KVM (TCG software emulation). It:
- Resets VM state and boots a fresh VM
- Verifies cloud-init completes cleanly
- Verifies `curl http://pypi.org` and `curl https://pypi.org` work through the proxy
- Verifies blocked domains return HTTP 418 from the proxy filter

On macOS, the test skips automatically if `socket_vmnet` is not running.

There is also a fast unit test suite for the filter logic (no VM required):

```bash
uv run pytest tests/test_filter.py -v
```

## Tooling

Use **uv** for all Python tasks. Do not use pip, conda, or pipx.
