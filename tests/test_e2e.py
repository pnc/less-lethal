"""
End-to-end tests: reset → start VM → run all checks against the single booted VM.

The `running_vm` fixture is module-scoped, so QEMU boots once and all tests
share it.  Tests run in definition order; test_cloud_init_success intentionally
runs first so it can block on cloud-init completing before any test needs apt.

QEMU runs via TCG (software emulation) when KVM is unavailable, which is slow;
BOOT_TIMEOUT is set generously to accommodate that.
"""

import os
import socket as _socket
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

# Use a different subnet and proxy port from the defaults so tests don't
# collide with a user's running VM on the default 192.168.100.0/24 subnet.
TEST_SUBNET = "192.168.101"
TEST_PROXY_PORT = 8091

# Module-level start time, set once the VM starts booting.
_t0: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elapsed() -> str:
    """Return a '[MM:SS]' tag relative to VM boot start."""
    s = int(time.monotonic() - _t0)
    return f"[{s // 60:02d}:{s % 60:02d}]"


def _progress(msg: str) -> None:
    """Print a timestamped progress line to stderr."""
    print(f"  {_elapsed()} {msg}", file=sys.stderr, flush=True)


def _vm(*args: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a vm.py subcommand and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(VM_PY), *args],
        **kwargs,
    )


def _vm_ssh(*cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command in the VM via ssh, capturing output."""
    return _vm("ssh", "--subnet", TEST_SUBNET, "--", *cmd, capture_output=True, text=True, timeout=timeout)


def _kill_all_vm_processes() -> None:
    """Kill stray processes from a previous test run.

    Targets the vm.py parent (which has --subnet in its args) rather than
    broadly killing all qemu-system-* processes, so a user's running VM on
    the default subnet is not disrupted.  vm.py's finally block propagates
    SIGTERM to its QEMU and mitmdump children.
    """
    subprocess.run(["pkill", "-f", f"vm\\.py.*--subnet.*{TEST_SUBNET}"], capture_output=True)
    # Also catch orphaned socket_vmnet_client wrappers (macOS) whose
    # command line includes the subnet-specific socket path.
    subprocess.run(["pkill", "-f", f"socket_vmnet.*{TEST_SUBNET}.*qemu"], capture_output=True)
    # Kill mitmdump on the test port only (not a user's default-port proxy).
    subprocess.run(["pkill", "-f", f"mitmdump.*-p.*{TEST_PROXY_PORT}"], capture_output=True)
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
        _progress(f"SSH probe #{attempt} ({remaining}s remaining)…")
        try:
            r = _vm_ssh("true", timeout=10)
            if r.returncode == 0:
                _progress(f"SSH ready after {attempt} probe(s)")
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
        socket_path = brew_prefix / f"var/run/socket_vmnet.{TEST_SUBNET}"
        def _skip_no_vmnet() -> None:
            print(
                "\n  socket_vmnet is not running for the test subnet.\n"
                "  Start it in a separate terminal before re-running:\n"
                "\n"
                f"    sudo {brew_prefix}/opt/socket_vmnet/bin/socket_vmnet \\\n"
                f"        --vmnet-mode=host \\\n"
                f"        --vmnet-gateway={TEST_SUBNET}.1 \\\n"
                f"        --vmnet-dhcp-end={TEST_SUBNET}.254 \\\n"
                f"        --vmnet-mask=255.255.255.0 \\\n"
                f"        {socket_path}\n",
                file=sys.stderr, flush=True,
            )
            pytest.skip("socket_vmnet not running for test subnet")

        if not socket_path.exists():
            _skip_no_vmnet()
        # A stale socket file can linger after the daemon is killed.
        # Try to connect to verify the daemon is actually responsive.
        _sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            _sock.settimeout(2)
            _sock.connect(str(socket_path))
        except (ConnectionRefusedError, OSError):
            _skip_no_vmnet()
        finally:
            _sock.close()

    # Kill any stray processes from a previous test run
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

    global _t0
    _t0 = time.monotonic()
    _progress("Launching VM (mitmproxy + QEMU)…")

    # vm.py start runs mitmproxy in the background and QEMU in the foreground.
    # Both inherit our file handles, so their output lands in console.log.
    vm_proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "start", "--memory", "512M",
         "--subnet", TEST_SUBNET,
         "--proxy-port", str(TEST_PROXY_PORT),
         "--no-firewall",
         "--extra-user-data", str(REPO / "tests" / "nmap.yaml")],
        stdout=console_f,
        stderr=console_f,
    )

    # Give vm.py a moment to fail fast (missing socket_vmnet, subnet
    # mismatch, port conflict, etc.) before entering the SSH probe loop.
    # Without this, a setup failure just looks like an SSH timeout.
    time.sleep(2)
    if vm_proc.poll() is not None:
        console_f.flush()
        _dump_logs()
        pytest.fail(
            f"vm.py exited immediately (rc={vm_proc.returncode}). "
            "See console log above."
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
    last_detail = ""
    while time.monotonic() < deadline:
        r = _vm_ssh("cloud-init status --long 2>&1", timeout=15)
        remaining = int(deadline - time.monotonic())
        # Compact multi-line status into a single progress line.
        detail = " | ".join(
            line.strip() for line in r.stdout.strip().splitlines() if line.strip()
        )
        if detail != last_detail:
            _progress(f"cloud-init ({remaining}s left): {detail}")
            last_detail = detail
        else:
            _progress(f"cloud-init ({remaining}s left): (unchanged)")
        if "status: done" in r.stdout:
            _progress("cloud-init finished successfully")
            return
        if "status: error" in r.stdout:
            pytest.fail(f"cloud-init finished with errors:\n{r.stdout}")
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
    assert "PROXY BLOCK" in result.stdout, (
        f"Expected a proxy block response for cisco.com but got:\n"
        f"stdout: {result.stdout[:500]}\n"
        f"stderr: {result.stderr[:500]}"
    )


def test_host_exposed_ports(running_vm):
    """Only the proxy port should be reachable from the VM to the host.

    This protects the host machine: if other services (SSH, databases, etc.)
    were reachable, a compromised VM could pivot to attack them.

    Requires host-side firewall rules (pf on macOS, iptables on Linux).
    Since the test suite runs with --no-firewall to avoid sudo prompts,
    this test loads rules non-interactively and skips if sudo credentials
    aren't cached.

    nmap is installed during provisioning via tests/nmap.yaml passed to
    vm.py start --extra-user-data, so no apt-get is needed here.
    """
    # Load firewall rules non-interactively.  Skip if sudo isn't cached.
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print(
            "\n  Skipping port isolation test — sudo credentials not cached.\n"
            "  To include this test, run:\n\n"
            "    sudo -v\n\n"
            "  then re-run the test suite within the sudo timeout.\n",
            file=sys.stderr, flush=True,
        )
        pytest.skip("sudo credentials not cached (needed for firewall rules)")

    if sys.platform == "darwin":
        pf_anchor = "com.apple/agent-vm"
        pf_rules = (
            f"pass in quick proto tcp from {TEST_SUBNET}.2 to {TEST_SUBNET}.1 port {TEST_PROXY_PORT}\n"
            f"block in quick proto tcp from {TEST_SUBNET}.0/24 to {TEST_SUBNET}.1\n"
        )
        subprocess.run(
            ["sudo", "-n", "pfctl", "-a", pf_anchor, "-f", "-"],
            input=pf_rules, text=True, check=True, capture_output=True,
        )
        subprocess.run(["sudo", "-n", "pfctl", "-E"], capture_output=True)

    # Derive the host IP and proxy port from the VM's proxy env var.
    r = _vm_ssh("bash -lc 'echo $http_proxy'", timeout=10)
    proxy_url = r.stdout.strip()  # e.g. http://192.168.101.1:8090
    host_ip = proxy_url.split("//")[1].split(":")[0]
    proxy_port = int(proxy_url.split(":")[-1])

    _progress(f"Starting nmap full port scan against {host_ip}")

    # Full port scan with aggressive timing (-T5). Host-side REJECT rules
    # give instant responses so the aggressive timing is safe.
    # --stats-every 15s prints periodic progress to stderr; we merge
    # remote stderr into stdout so we can stream progress lines while
    # collecting the grepable (-oG) output for parsing.
    nmap_cmd = f"nmap -p- -T5 -v --stats-every 15s --open {host_ip} -oG - 2>&1"
    proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "ssh", "--subnet", TEST_SUBNET, "--",
         f"bash -lc '{nmap_cmd}'"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    stdout_lines: list[str] = []
    scan_start = time.monotonic()
    for line in proc.stdout:
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        # Print lines that indicate scan progress or results.
        if any(kw in stripped for kw in [
            "Stats:", "About ", "Completed", "scan report",
            "/open/", "Nmap done",
        ]):
            scan_elapsed = int(time.monotonic() - scan_start)
            _progress(f"nmap [{scan_elapsed}s]: {stripped}")

    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    scan_elapsed = int(time.monotonic() - scan_start)
    _progress(f"nmap finished in {scan_elapsed}s")

    stdout = "".join(stdout_lines)

    open_ports: set[int] = set()
    for line in stdout.splitlines():
        if "Ports:" in line:
            for part in line.split("Ports:")[1].split(","):
                part = part.strip()
                if "/open/" in part:
                    open_ports.add(int(part.split("/")[0]))

    _progress(f"Open ports: {sorted(open_ports) if open_ports else 'none'}")

    # Clean up firewall rules regardless of assertion outcome.
    if sys.platform == "darwin":
        subprocess.run(
            ["sudo", "-n", "pfctl", "-a", pf_anchor, "-F", "all"],
            capture_output=True,
        )

    unexpected = open_ports - {proxy_port}
    assert not unexpected, (
        f"Unexpected ports open on host {host_ip}: {sorted(unexpected)}\n"
        f"Only the proxy port ({proxy_port}) should be accessible from the VM."
    )
