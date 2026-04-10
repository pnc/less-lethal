"""
End-to-end test: reset → start VM → SSH in → curl example.com.

Runs the full vm.py stack (mitmproxy + QEMU) and verifies basic connectivity.
QEMU runs via TCG (software emulation) when KVM is unavailable, which is slow;
BOOT_TIMEOUT is set generously to accommodate that.
"""

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
VM_PY = REPO / "vm.py"
CONSOLE_LOG = REPO / ".vm" / "console.log"

# Generous timeout for TCG emulation (no KVM).  Reduce if KVM is available.
BOOT_TIMEOUT = 600   # seconds to wait for SSH to become available after start
SSH_POLL_INTERVAL = 15  # seconds between SSH probe attempts
CURL_TIMEOUT = 60    # seconds for the curl command itself


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vm(*args: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a vm.py subcommand and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(VM_PY), *args],
        **kwargs,
    )


def _vm_ssh(*cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command in the VM via ssh, capturing output."""
    return _vm("ssh", "--", *cmd, capture_output=True, text=True, timeout=timeout)


def _kill_all_vm_processes() -> None:
    """Kill any stray qemu-system-* and mitmdump processes."""
    subprocess.run(["pkill", "-f", "qemu-system-"], capture_output=True)
    subprocess.run(["pkill", "-f", "mitmdump"], capture_output=True)
    time.sleep(2)  # allow ports to be released


def _dump_logs() -> None:
    """Print console log and mitmdump log tails to stderr for diagnostics."""
    for label, path in [
        ("CONSOLE LOG", CONSOLE_LOG),
        ("MITMDUMP LOG", REPO / ".vm" / "mitmdump.log"),
    ]:
        print(f"\n{'=' * 60}", file=sys.stderr)
        print(f"{label}: {path}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        if path.exists():
            text = path.read_text(errors="replace")
            # Show the last 4 KB — enough to see what went wrong
            print(text[-4096:] if len(text) > 4096 else text, file=sys.stderr)
        else:
            print("(file not found)", file=sys.stderr)


def _wait_for_ssh(vm_proc: subprocess.Popen, timeout: int) -> None:
    """Poll SSH until the VM accepts connections, or raise on timeout/crash."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        if vm_proc.poll() is not None:
            _dump_logs()
            raise RuntimeError(
                f"vm.py start exited prematurely "
                f"(rc={vm_proc.returncode}, check console log above)"
            )

        attempt += 1
        remaining = int(deadline - time.monotonic())
        print(f"  SSH probe #{attempt} ({remaining}s remaining)…", file=sys.stderr)
        try:
            r = _vm_ssh("true", timeout=10)
            if r.returncode == 0:
                print(f"  SSH ready after {attempt} probe(s).", file=sys.stderr)
                return
        except subprocess.TimeoutExpired:
            pass  # SSH not up yet; keep waiting

        time.sleep(SSH_POLL_INTERVAL)

    _dump_logs()
    raise TimeoutError(
        f"VM did not become SSH-accessible within {timeout}s "
        f"after {attempt} probe(s)"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def running_vm():
    """
    Module-scoped fixture: reset state, boot the VM, wait for SSH,
    then tear down (terminate vm.py and kill any stray QEMU) on exit.
    """
    # Kill any stray processes from a previous run before touching port 8090
    _kill_all_vm_processes()

    # Start from a known clean state
    _vm("reset", check=True)

    CONSOLE_LOG.parent.mkdir(parents=True, exist_ok=True)
    console_f = CONSOLE_LOG.open("w")

    # vm.py start runs mitmproxy in the background and QEMU in the foreground.
    # Both inherit our file handles, so their output lands in console.log.
    vm_proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "start", "--memory", "1G"],
        stdout=console_f,
        stderr=console_f,
    )

    try:
        _wait_for_ssh(vm_proc, timeout=BOOT_TIMEOUT)
    except Exception:
        vm_proc.terminate()
        try:
            vm_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            vm_proc.kill()
        _kill_all_vm_processes()
        console_f.close()
        raise

    yield vm_proc

    # --- teardown ---
    vm_proc.terminate()
    try:
        vm_proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        vm_proc.kill()
        vm_proc.wait()
    _kill_all_vm_processes()
    console_f.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_curl_example_com(running_vm):
    """curl http://example.com from the guest should return the IANA example page."""
    # Pass as a single string so SSH doesn't split it.  bash -lc sources
    # /etc/profile.d/proxy.sh which sets http_proxy for the curl call.
    result = _vm_ssh(
        "bash -lc 'curl -fsS --max-time 15 http://example.com'",
        timeout=CURL_TIMEOUT,
    )

    if result.returncode != 0:
        _dump_logs()
        pytest.fail(
            f"curl failed (rc={result.returncode})\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )

    assert "Example Domain" in result.stdout, (
        f"'Example Domain' not found in curl output.\n"
        f"stdout: {result.stdout[:1000]}"
    )
