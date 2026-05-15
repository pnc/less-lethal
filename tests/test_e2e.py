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
STATE_DIR = Path(os.environ["VM_STATE_DIR"]) if "VM_STATE_DIR" in os.environ \
    else REPO / ".vm"
CONSOLE_LOG = STATE_DIR / "console.log"

# Generous timeout for TCG emulation (no KVM).  Reduce if KVM is available.
BOOT_TIMEOUT = 600   # seconds to wait for SSH to become available after start
SSH_POLL_INTERVAL = 15  # seconds between SSH probe attempts
CURL_TIMEOUT = 60    # seconds for the curl command itself

# Use different ports from the defaults so tests don't collide with a user's
# running VM.
TEST_PROXY_PORT = 8091
TEST_SSH_PORT = 2223

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
    return _vm("ssh", "--ssh-port", str(TEST_SSH_PORT), "--", *cmd,
               capture_output=True, text=True, timeout=timeout)


def _kill_all_vm_processes() -> None:
    """Kill stray processes from a previous test run.

    Targets processes by identifiers unique to this repo/test config so
    a user's running VM on the default ports is not disrupted.
    """
    # vm.py parent (has --ssh-port in its args).
    subprocess.run(["pkill", "-f", f"vm\\.py.*--ssh-port.*{TEST_SSH_PORT}"],
                   capture_output=True)
    # QEMU child — may outlive vm.py.  Identified by the repo-specific
    # disk path, which is always in the QEMU command line.
    disk = str(STATE_DIR / "disk.qcow2")
    subprocess.run(["pkill", "-f", f"qemu.*{disk}"], capture_output=True)
    # mitmdump on the test port only (not a user's default-port proxy).
    subprocess.run(["pkill", "-f", f"mitmdump.*-p.*{TEST_PROXY_PORT}"],
                   capture_output=True)
    time.sleep(2)  # allow ports to be released


def _dump_logs() -> None:
    """Print console log and mitmdump log tails to stderr for diagnostics."""
    for label, path in [
        ("CONSOLE LOG", CONSOLE_LOG),
        ("MITMDUMP LOG", STATE_DIR / "mitmdump.log"),
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
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        ca_result = subprocess.run(
            ["curl", "-fsS", "--proxy", outer_proxy, "http://mitm.it/cert/pem"],
            capture_output=True, timeout=10,
        )
        if ca_result.returncode != 0:
            pytest.fail(
                f"Could not fetch outer proxy CA cert from mitm.it via {outer_proxy}.\n"
                f"stderr: {ca_result.stderr.decode(errors='replace')}"
            )
        (STATE_DIR / "upstream-ca.pem").write_bytes(ca_result.stdout)

    CONSOLE_LOG.parent.mkdir(parents=True, exist_ok=True)
    console_f = CONSOLE_LOG.open("w")

    global _t0
    _t0 = time.monotonic()
    _progress("Launching VM (mitmproxy + QEMU)…")

    # vm.py start runs mitmproxy in the background and QEMU in the foreground.
    # Both inherit our file handles, so their output lands in console.log.
    vm_proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "start", "--memory", "512M",
         "--ssh-port", str(TEST_SSH_PORT),
         "--proxy-port", str(TEST_PROXY_PORT),
         "--extra-user-data", str(REPO / "tests" / "nmap.yaml")],
        stdout=console_f,
        stderr=console_f,
    )

    # Give vm.py a moment to fail fast (port conflict, etc.) before
    # entering the SSH probe loop.  Without this, a setup failure just
    # looks like an SSH timeout.
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
    deadline = time.monotonic() + 600
    last_detail = ""
    while time.monotonic() < deadline:
        try:
            r = _vm_ssh("cloud-init status --long 2>&1", timeout=30)
        except subprocess.TimeoutExpired:
            remaining = int(deadline - time.monotonic())
            _progress(f"cloud-init ({remaining}s left): (SSH timed out, retrying)")
            continue
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
    pytest.fail("cloud-init did not complete within 600s")


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


def test_docker_hello_world(running_vm):
    """docker run hello-world should pull the image and print the greeting.

    Exercises the Docker daemon's proxy configuration (systemd service
    override) and the Docker Hub allowlist rules.  The daemon pulls the
    image through mitmproxy, then runs the container locally.
    """
    _progress("Running docker hello-world (includes image pull)…")
    result = _vm_ssh(
        "docker run hello-world 2>&1",
        timeout=180,
    )
    if result.returncode != 0:
        _dump_logs()
        pytest.fail(
            f"docker run hello-world failed (rc={result.returncode})\n"
            f"stdout: {result.stdout[:1000]}\n"
            f"stderr: {result.stderr[:1000]}"
        )
    assert "Hello from Docker!" in result.stdout, (
        f"Expected 'Hello from Docker!' in output.\n"
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


def test_network_isolation(running_vm):
    """Only the proxy port should be reachable from the guest.

    A single unexpected open port is enough for a malicious subprocess to
    exfiltrate data or pivot laterally, so this test scans all 65535 ports
    on the guestfwd IP (10.0.2.100) — the only address the guest can
    interact with.  Non-forwarded ports respond with RST (closed), so the
    scan completes quickly (~10s).

    nmap is installed during provisioning via tests/nmap.yaml passed to
    vm.py start --extra-user-data.
    """
    # --- Full port scan of the guestfwd IP ---
    # -Pn: skip host discovery (host is virtual, may not respond to pings)
    # -T5: aggressive timing (~100 parallel probes, 300ms timeout)
    # --max-retries 1: don't re-probe filtered ports excessively
    # --host-timeout 300s: hard cap so the test doesn't hang forever
    _progress("Full port scan of guestfwd IP (10.0.2.100)…")
    nmap_cmd = (
        "nmap -p- -Pn -T5 --max-retries 1 --host-timeout 300s "
        "--open 10.0.2.100 -oG - 2>&1"
    )
    proc = subprocess.Popen(
        [sys.executable, str(VM_PY), "ssh", "--ssh-port", str(TEST_SSH_PORT), "--",
         f"bash -lc '{nmap_cmd}'"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    stdout_lines: list[str] = []
    scan_start = time.monotonic()
    for line in proc.stdout:
        stdout_lines.append(line)
        stripped = line.strip()
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

    _progress(f"Open ports on guestfwd IP: {sorted(open_ports) if open_ports else 'none'}")

    unexpected = open_ports - {TEST_PROXY_PORT}
    assert not unexpected, (
        f"Unexpected ports open on guestfwd IP 10.0.2.100: {sorted(unexpected)}\n"
        f"Only the proxy port ({TEST_PROXY_PORT}) should be accessible."
    )

    # --- Spot-check the slirp gateway ---
    # With restrict=on, the gateway (10.0.2.2) should be completely
    # unreachable.  A targeted scan is sufficient here — if restrict=on
    # is broken, all ports would be reachable, not just specific ones.
    _progress("Scanning slirp gateway (10.0.2.2) to verify restrict=on")
    r = _vm_ssh(
        "bash -lc 'nmap -Pn -p 22,80,443,8080,8090,8091 -T5 --max-retries 1 "
        "--host-timeout 30s 10.0.2.2 -oG -'",
        timeout=60,
    )
    for line in r.stdout.splitlines():
        if "Ports:" in line:
            assert "/open/" not in line, (
                f"Unexpected open port(s) on slirp gateway:\n{line}\n"
                "restrict=on should block all direct TCP to the gateway."
            )


# ---------------------------------------------------------------------------
# Guest isolation: network egress
# ---------------------------------------------------------------------------


def test_no_icmp_to_external_hosts(running_vm):
    """ICMP to external IPs must be dropped by slirp restrict=on.

    If ping succeeds, the guest has a network path to the internet
    that completely bypasses the proxy and allowlist filter.
    """
    for ip in ("1.1.1.1", "8.8.8.8"):
        _progress(f"Pinging {ip} (expect timeout)…")
        r = _vm_ssh(f"ping -c 1 -W 5 {ip} 2>&1", timeout=15)
        assert r.returncode != 0, (
            f"ping to {ip} succeeded — ICMP escapes the sandbox!\n"
            f"stdout: {r.stdout}"
        )


def test_slirp_gateway_does_not_route(running_vm):
    """The slirp gateway (10.0.2.2) may respond to ICMP but must not route packets.

    With restrict=on, the gateway IP is internal to the QEMU process and
    responds to pings — this is expected slirp behavior, not a security
    issue.  The critical property is that the gateway does NOT forward
    packets to external destinations, even if the guest explicitly adds
    a route through it.
    """
    # The gateway is on the same virtual subnet — ping is expected to work.
    _progress("Verifying gateway responds (expected slirp behavior)…")
    r = _vm_ssh("ping -c 1 -W 5 10.0.2.2 2>&1", timeout=15)
    _progress(f"Gateway ping rc={r.returncode} (non-zero is also fine)")

    # But it must NOT route traffic to external IPs.
    _progress("Verifying gateway does not route to external IPs…")
    r = _vm_ssh(
        "bash -c '"
        "sudo ip route replace default via 10.0.2.2 2>/dev/null; "
        "ping -c 1 -W 5 8.8.8.8 2>&1; "
        "RC=$?; "
        "sudo ip route del default via 10.0.2.2 2>/dev/null; "
        "exit $RC"
        "'",
        timeout=20,
    )
    assert r.returncode != 0, (
        f"Ping to 8.8.8.8 succeeded via slirp gateway as default route!\n"
        f"restrict=on is not preventing the gateway from routing traffic.\n"
        f"stdout: {r.stdout}"
    )


def test_no_direct_tcp_to_external(running_vm):
    """Direct TCP to external hosts must be blocked.

    A direct connection (without the HTTP proxy) to a public IP on a
    well-known port must fail.  This is the most important network
    isolation check: if it passes, a process in the VM can exfiltrate
    data to any IP without proxy visibility.
    """
    _progress("Direct TCP to 1.1.1.1:80 via nmap (expect filtered)…")
    r = _vm_ssh(
        "nmap -Pn -sT -p 80 --max-retries 0 --host-timeout 10s "
        "1.1.1.1 -oG - 2>&1",
        timeout=30,
    )
    assert "/open/" not in r.stdout, (
        f"Direct TCP to 1.1.1.1:80 is open — proxy bypass detected!\n"
        f"nmap output: {r.stdout}"
    )


def test_no_dns_resolution_without_proxy(running_vm):
    """Direct DNS queries must fail — no resolver is reachable.

    slirp restrict=on prevents the guest from reaching the built-in
    DNS forwarder (10.0.2.3).  Without a working resolver, the guest
    cannot map hostnames to IPs for direct connections, and DNS
    tunneling (a common exfiltration channel) is impossible.
    """
    _progress("UDP scan of slirp DNS (10.0.2.3:53, expect closed)…")
    r = _vm_ssh(
        "sudo nmap -sU -Pn -p 53 --max-retries 0 --host-timeout 10s "
        "10.0.2.3 -oG - 2>&1",
        timeout=30,
    )
    assert "53/open/" not in r.stdout, (
        f"UDP port 53 on slirp DNS (10.0.2.3) is open!\n"
        f"Guest can reach the DNS forwarder — DNS tunneling is possible.\n"
        f"nmap output: {r.stdout}"
    )

    _progress("UDP scan of public DNS (8.8.8.8:53, expect filtered)…")
    r2 = _vm_ssh(
        "sudo nmap -sU -Pn -p 53 --max-retries 0 --host-timeout 10s "
        "8.8.8.8 -oG - 2>&1",
        timeout=30,
    )
    assert "53/open/" not in r2.stdout, (
        f"UDP port 53 on public DNS (8.8.8.8) is open!\n"
        f"Guest can reach external DNS servers.\n"
        f"nmap output: {r2.stdout}"
    )


def test_no_unexpected_udp_on_slirp_gateway(running_vm):
    """Only known slirp-internal UDP services may be open on the gateway.

    QEMU's slirp stack exposes a small number of built-in UDP services
    on the gateway (10.0.2.2): TFTP (69) for PXE boot, and DHCP (67/68).
    These are QEMU-internal and do not provide a path to the host or
    external network.  DNS (53) must NOT be open — a reachable DNS server
    would enable DNS tunneling for data exfiltration.
    """
    # Known slirp-internal services that are not exfiltration vectors:
    # - 67/68 (DHCP): needed for guest IP assignment
    # - 69 (TFTP): QEMU's built-in PXE server, serves only configured files
    KNOWN_SLIRP_UDP = {67, 68, 69}

    _progress("UDP scan of slirp gateway (10.0.2.2, common ports)…")
    r = _vm_ssh(
        "sudo nmap -sU -Pn -p 53,67,68,69,123,161,443,500 --max-retries 0 "
        "--host-timeout 15s 10.0.2.2 -oG - 2>&1",
        timeout=30,
    )
    if "Ports:" in r.stdout:
        for part in r.stdout.split("Ports:")[1].split(","):
            part = part.strip()
            if "/open/" in part:
                port = int(part.split("/")[0])
                assert port in KNOWN_SLIRP_UDP, (
                    f"Unexpected open UDP port on slirp gateway: {part}\n"
                    f"Only known slirp services {KNOWN_SLIRP_UDP} should be open.\n"
                    f"Full output: {r.stdout}"
                )


def test_no_route_via_slirp_gateway(running_vm):
    """Manually adding a route through the slirp gateway must not enable external access.

    Even if the guest configures 10.0.2.2 as a default gateway, slirp's
    restrict=on ensures the gateway does not forward packets.  This test
    verifies that a motivated attacker cannot simply reconfigure routing
    to escape the sandbox.
    """
    _progress("Adding manual route via gateway, then pinging external IP…")
    r = _vm_ssh(
        "bash -c '"
        "sudo ip route add 1.1.1.1/32 via 10.0.2.2 2>/dev/null; "
        "ping -c 1 -W 5 1.1.1.1 2>&1; "
        "RC=$?; "
        "sudo ip route del 1.1.1.1/32 via 10.0.2.2 2>/dev/null; "
        "exit $RC"
        "'",
        timeout=20,
    )
    assert r.returncode != 0, (
        f"Ping to 1.1.1.1 succeeded after adding route via slirp gateway!\n"
        f"restrict=on is not preventing gateway-based routing.\n"
        f"stdout: {r.stdout}"
    )


# ---------------------------------------------------------------------------
# Guest isolation: shared directory (9p)
# ---------------------------------------------------------------------------


def test_9p_symlink_escape_blocked(running_vm):
    """Guest must not be able to create real symlinks on the host via ~/shared.

    With security_model=mapped-xattr, guest-created symlinks are stored as
    regular files with the target in extended attributes — not as real
    symlinks on the host.  This blocks the classic 9p symlink escape
    (CVE-2020-35517).

    An even stronger outcome is that the bindfs UID-mapping layer blocks
    symlink creation entirely (Permission denied).  Either result is safe;
    the only failure is a real symlink appearing on the host.
    """
    marker = ".test-symlink-escape"
    _progress("Attempting symlink creation in shared dir…")

    try:
        r = _vm_ssh(f"ln -sf /etc/shadow ~/shared/{marker} 2>&1", timeout=10)

        if r.returncode != 0:
            # Symlink creation denied — strongest possible isolation.
            # bindfs or mapped-xattr prevented the operation entirely.
            _progress(f"Symlink creation denied (rc={r.returncode}) — safe")
            return

        # Symlink was created.  Verify it is NOT a real symlink on the host.
        time.sleep(1)
        host_path = REPO / "shared" / marker
        assert not host_path.is_symlink(), (
            f"Guest-created symlink is a REAL symlink on the host!\n"
            f"Target: {os.readlink(host_path)}\n"
            "security_model=mapped-xattr is not in effect — "
            "the VM can escape to arbitrary host filesystem paths."
        )
    finally:
        _vm_ssh(f"rm -f ~/shared/{marker}", timeout=10)


def test_guest_cannot_modify_host_allowlist(running_vm):
    """The guest must not be able to modify the host's allowlist.txt.

    allowlist.txt lives in the project root, outside the shared directory.
    A guest that modifies it can grant itself access to arbitrary network
    endpoints, defeating the entire proxy-based isolation model.  This test
    tries both a symlink-based escape and direct path traversal, verifying
    the file is untouched regardless of whether symlinks are blocked by
    mapped-xattr/bindfs or simply resolve within the guest namespace.
    """
    _progress("Attempting to modify host allowlist via shared directory…")
    marker = ".test-allowlist-escape"
    allowlist_path = REPO / "allowlist.txt"
    original_content = allowlist_path.read_text()

    try:
        # Attempt 1: symlink targeting the allowlist's relative path
        _vm_ssh(f"ln -sf ../allowlist.txt ~/shared/{marker} 2>/dev/null; true",
                timeout=10)
        _vm_ssh(
            f"bash -c 'echo \"GET https://evil.com/*\" >> ~/shared/{marker} 2>/dev/null; true'",
            timeout=10,
        )

        # Attempt 2: direct path traversal (resolves in guest namespace,
        # but verify the host file is safe regardless)
        _vm_ssh(
            "bash -c 'echo \"GET https://evil.com/*\" >> ~/shared/../allowlist.txt 2>/dev/null; true'",
            timeout=10,
        )

        # Verify the host's allowlist was not modified
        assert allowlist_path.read_text() == original_content, (
            "Host allowlist.txt was MODIFIED through the shared directory!\n"
            "The guest can escalate its own network permissions."
        )
    finally:
        _vm_ssh(f"rm -f ~/shared/{marker} 2>/dev/null; true", timeout=10)
        # Safety net: restore original content in case the test failed
        allowlist_path.write_text(original_content)


# ---------------------------------------------------------------------------
# Kernel upgrade + reboot
# ---------------------------------------------------------------------------


def test_kernel_install_and_reboot(running_vm):
    """Installing a new kernel and rebooting must not kernel panic.

    The base cloud-init config once diverted update-initramfs to /bin/true
    to speed up provisioning (~2 min saved under TCG emulation).  This was
    safe under the assumption that the VM was ephemeral and never rebooted.
    In practice, Debian's unattended-upgrades installs kernel security
    updates on a daily timer.  Because update-initramfs was a no-op, the
    new kernel shipped without an initramfs.  GRUB's os-prober still picked
    up the new vmlinuz and made it the default boot entry — but with no
    initrd line.  On next boot the kernel couldn't load the virtio_blk
    module (it lives in the initramfs, not built-in), so the root disk was
    invisible and the kernel panicked:

        VFS: Cannot open root device "PARTUUID=..." or unknown-block(0,0)
        Kernel panic - not syncing: VFS: Unable to mount root fs

    This test reproduces that scenario end-to-end: install a second kernel
    flavor, set GRUB to boot it, and reboot.  If update-initramfs is broken,
    the VM kernel-panics and SSH never comes back.

    Placed last because it reboots the VM.
    """
    # Detect guest architecture to pick the right cloud kernel package.
    r = _vm_ssh("dpkg --print-architecture", timeout=10)
    assert r.returncode == 0
    arch = r.stdout.strip()
    cloud_pkg = f"linux-image-cloud-{arch}"

    _progress(f"Installing {cloud_pkg}…")
    r = _vm_ssh(
        f"bash -lc 'sudo apt-get install -y -qq {cloud_pkg} 2>&1'",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"Kernel install failed (rc={r.returncode}):\n"
        f"{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    )

    # Find the newly installed cloud kernel version.
    r = _vm_ssh(f"ls /boot/vmlinuz-*-cloud-{arch}", timeout=10)
    assert r.returncode == 0, f"No cloud kernel found in /boot:\n{r.stderr}"
    cloud_vmlinuz = r.stdout.strip().splitlines()[-1].strip()
    cloud_version = cloud_vmlinuz.rsplit("/", 1)[-1].removeprefix("vmlinuz-")
    _progress(f"Installed cloud kernel: {cloud_version}")

    # Verify the initramfs was created for it.
    r = _vm_ssh(f"test -f /boot/initrd.img-{cloud_version}", timeout=10)
    assert r.returncode == 0, (
        f"initrd.img-{cloud_version} was not created.\n"
        "update-initramfs is likely diverted to /bin/true."
    )

    # Set GRUB to boot the cloud kernel by default.
    grub_entry = f"gnulinux-advanced-e82711d0-3a02-4e17-9f90-2f275b0368c5>gnulinux-{cloud_version}-advanced-e82711d0-3a02-4e17-9f90-2f275b0368c5"
    _vm_ssh(
        f"sudo grub-set-default '{grub_entry}' 2>&1",
        timeout=10,
    )
    # Alternatively, just make sure it's the default (newest) entry.
    _vm_ssh("sudo update-grub 2>&1", timeout=60)

    # Verify GRUB config has an initrd line for the cloud kernel.
    r = _vm_ssh("cat /boot/grub/grub.cfg", timeout=10)
    assert f"initrd\t/boot/initrd.img-{cloud_version}" in r.stdout, (
        f"GRUB config missing initrd for {cloud_version}."
    )

    _progress("Rebooting into cloud kernel…")
    _vm_ssh("sudo reboot", timeout=10)

    # Wait for SSH to go down.
    time.sleep(10)

    # Wait for SSH to come back — if the kernel panicked, it never will.
    deadline = time.monotonic() + BOOT_TIMEOUT
    attempt = 0
    while time.monotonic() < deadline:
        if running_vm.poll() is not None:
            _dump_logs()
            pytest.fail(
                "QEMU exited during reboot — likely kernel panic.\n"
                "Check console log above."
            )
        attempt += 1
        remaining = int(deadline - time.monotonic())
        _progress(f"Post-reboot SSH probe #{attempt} ({remaining}s remaining)…")
        try:
            r = _vm_ssh("true", timeout=10)
            if r.returncode == 0:
                _progress(f"VM back after reboot ({attempt} probe(s))")
                break
        except subprocess.TimeoutExpired:
            pass
        time.sleep(SSH_POLL_INTERVAL)
    else:
        _dump_logs()
        pytest.fail(
            f"VM did not come back after reboot within {BOOT_TIMEOUT}s.\n"
            "Likely kernel panic due to missing initramfs."
        )

    # Confirm we're running the new kernel.
    r = _vm_ssh("uname -r", timeout=10)
    _progress(f"Running kernel after reboot: {r.stdout.strip()}")
    assert "cloud" in r.stdout, (
        f"Expected to boot cloud kernel, got: {r.stdout.strip()}"
    )
