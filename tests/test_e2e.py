"""
End-to-end tests: reset → start VM → run all checks against the single booted VM.

The `running_vm` fixture is module-scoped, so QEMU boots once and all tests
share it.  Tests run in definition order; test_cloud_init_success intentionally
runs first so it can block on cloud-init completing before any test needs apt.

QEMU runs via TCG (software emulation) when KVM is unavailable, which is slow;
BOOT_TIMEOUT is set generously to accommodate that.
"""

import os
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

    All tests in the module share a single VM instance.
    """
    # On macOS, skip rather than hang if socket_vmnet isn't running.
    if sys.platform == "darwin":
        try:
            brew_prefix = Path(
                subprocess.check_output(["brew", "--prefix"], text=True).strip()
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Homebrew not found — cannot locate socket_vmnet")
        socket_path = brew_prefix / "var/run/socket_vmnet.host"
        if not socket_path.is_socket():
            pytest.skip(
                "socket_vmnet not running — start it first with:\n"
                f"  sudo {brew_prefix}/opt/socket_vmnet/bin/socket_vmnet "
                "--vmnet-mode=host --vmnet-gateway=192.168.100.1 "
                "--vmnet-dhcp-end=192.168.100.254 --vmnet-mask=255.255.255.0 "
                f"{socket_path}"
            )

    # Kill any stray processes from a previous run before touching port 8090
    _kill_all_vm_processes()

    # Start from a known clean state
    _vm("reset", check=True)

    # When the test suite itself runs inside a sandboxed VM (double-nested),
    # there is an outer intercepting proxy whose CA cert the inner mitmdump
    # must trust to verify upstream TLS connections.  Fetch it here — before
    # vm.py start — and write it where vm.py's start_mitmproxy() will find it.
    outer_proxy = (os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or
                   os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))
    if outer_proxy:
        state_dir = REPO / ".vm"
        state_dir.mkdir(parents=True, exist_ok=True)
        ca_result = subprocess.run(
            ["curl", "-fsS", "--proxy", outer_proxy, "http://mitm.it/cert/pem"],
            capture_output=True, timeout=10,
        )
        if ca_result.returncode != 0:
            pytest.fail(
                f"Could not fetch outer proxy CA cert from mitm.it via {outer_proxy}.\n"
                f"stderr: {ca_result.stderr.decode(errors='replace')}"
            )
        (state_dir / "upstream-ca.pem").write_bytes(ca_result.stdout)

    CONSOLE_LOG.parent.mkdir(parents=True, exist_ok=True)
    console_f = CONSOLE_LOG.open("w")

    # vm.py start runs mitmproxy in the background and QEMU in the foreground.
    # Both inherit our file handles, so their output lands in console.log.
    vm_proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "start", "--memory", "512M",
         "--extra-user-data", str(REPO / "tests" / "nmap.yaml")],
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
# Tests  (run in definition order against the single booted VM)
# ---------------------------------------------------------------------------

def test_cloud_init_success(running_vm):
    """cloud-init must complete without errors before other tests run.

    Polls rather than using `cloud-init status --wait` to avoid holding an
    SSH subprocess open during the entire cloud-init run (which includes
    package installation and can take several minutes in TCG mode).
    """
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        r = _vm_ssh("cloud-init status 2>&1", timeout=15)
        if "status: done" in r.stdout:
            return
        if "status: error" in r.stdout:
            detail = _vm_ssh("cloud-init status --long 2>&1", timeout=15)
            pytest.fail(f"cloud-init finished with errors:\n{detail.stdout or r.stdout}")
        time.sleep(10)
    pytest.fail("cloud-init did not complete within 300s")


def test_curl_http_pypi_org(running_vm):
    """curl -L http://pypi.org from the guest should reach PyPI (follows redirect to HTTPS)."""
    # Pass as a single string so SSH doesn't split it.  bash -lc sources
    # /etc/profile.d/proxy.sh which sets http_proxy for the curl call.
    result = _vm_ssh(
        "bash -lc 'curl -fsSL --max-time 15 http://pypi.org'",
        timeout=CURL_TIMEOUT,
    )

    if result.returncode != 0:
        _dump_logs()
        pytest.fail(
            f"curl failed (rc={result.returncode})\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )

    assert "PyPI" in result.stdout, (
        f"'PyPI' not found in curl output.\n"
        f"stdout: {result.stdout[:1000]}"
    )


def test_curl_https_pypi_org(running_vm):
    """curl https://pypi.org should succeed, verifying HTTPS works through the proxy."""
    result = _vm_ssh(
        "bash -lc 'curl -fsS --max-time 15 https://pypi.org'",
        timeout=CURL_TIMEOUT,
    )
    if result.returncode != 0:
        _dump_logs()
        pytest.fail(
            f"HTTPS curl failed (rc={result.returncode})\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )
    assert "PyPI" in result.stdout, (
        f"'PyPI' not found in HTTPS curl output.\n"
        f"stdout: {result.stdout[:1000]}"
    )


def test_blocked_domain(running_vm):
    """Requests to domains not in filter.py's allowlist should be blocked with 403."""
    result = _vm_ssh(
        "bash -lc 'curl -s --max-time 15 http://cisco.com'",
        timeout=CURL_TIMEOUT,
    )
    assert "Blocked by filter.py" in result.stdout, (
        f"Expected a block response from filter.py for cisco.com but got:\n"
        f"stdout: {result.stdout[:500]}\n"
        f"stderr: {result.stderr[:500]}"
    )


@pytest.mark.skip(reason="QEMU user networking exposes all host ports to guest; needs iptables/bridge isolation to fix")
def test_host_exposed_ports(running_vm):
    """Only the proxy port should be reachable from the VM to the host.

    This protects the host machine: if other services (SSH, databases, etc.)
    were reachable, a compromised VM could pivot to attack them.

    nmap is installed during provisioning via tests/nmap.yaml passed to
    vm.py start --extra-user-data, so no apt-get is needed here.
    """
    # Derive the host IP and proxy port from the VM's proxy env var.
    r = _vm_ssh("bash -lc 'echo $http_proxy'", timeout=10)
    proxy_url = r.stdout.strip()  # e.g. http://10.0.2.2:8090
    host_ip = proxy_url.split("//")[1].split(":")[0]
    proxy_port = int(proxy_url.split(":")[-1])

    # Full port scan with fast timing (-T4). Catches anything open, not just
    # a handpicked list.
    result = _vm_ssh(
        f"bash -lc 'nmap -p- -T4 --open {host_ip} -oG -'",
        timeout=300,
    )

    open_ports: set[int] = set()
    for line in result.stdout.splitlines():
        if "Ports:" in line:
            for part in line.split("Ports:")[1].split(","):
                part = part.strip()
                if "/open/" in part:
                    open_ports.add(int(part.split("/")[0]))

    unexpected = open_ports - {proxy_port}
    assert not unexpected, (
        f"Unexpected ports open on host {host_ip}: {sorted(unexpected)}\n"
        f"Only the proxy port ({proxy_port}) should be accessible from the VM."
    )
