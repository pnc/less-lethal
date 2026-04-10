#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["mitmproxy"]
# ///

"""Agent VM — sandboxed Debian VM with mitmproxy traffic control."""

import argparse
import hashlib
import os
import platform
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path

# --- Config defaults (overridable via CLI flags) ---
SCRIPT_DIR = Path(__file__).parent.resolve()
PROXY_PORT: int = 8090
STATE_DIR: Path = SCRIPT_DIR / ".vm"       # ephemeral state, nuked on reset
IMAGES_DIR: Path = SCRIPT_DIR / ".images"  # persistent download cache (base image)
SHARED_DIR: Path = SCRIPT_DIR / "shared"
CLOUD_INIT_DIR: Path = SCRIPT_DIR / "cloud-init"


# ---------------------------------------------------------------------------
# Architecture enum
# ---------------------------------------------------------------------------

class Arch(Enum):
    ARM64 = "arm64"
    X86_64 = "x86_64"

    @classmethod
    def detect(cls) -> "Arch":
        m = platform.machine()
        if m in ("arm64", "aarch64"):
            return cls.ARM64
        if m in ("x86_64", "amd64"):
            return cls.X86_64
        sys.exit(f"Unsupported architecture: {m}")

    @property
    def qemu_bin(self) -> str:
        return "qemu-system-aarch64" if self == Arch.ARM64 else "qemu-system-x86_64"

    @property
    def debian_image_url(self) -> str:
        slug = "arm64" if self == Arch.ARM64 else "amd64"
        return (
            f"https://cloud.debian.org/images/cloud/trixie/daily/latest/"
            f"debian-13-generic-{slug}-daily.qcow2"
        )


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------

class Backend(ABC):
    """Abstracts platform-specific VM operations."""

    def __init__(self, arch: Arch, subnet: str, proxy_port: int = PROXY_PORT) -> None:
        self.arch = arch
        self._subnet = subnet
        self.proxy_port = proxy_port

    # -- Network --

    @property
    def host_ip(self) -> str:
        """IP address the guest uses to reach the proxy on the host."""
        return f"{self._subnet}.1"

    @property
    def ssh_host(self) -> str:
        """Hostname/IP to SSH to from the host."""
        return f"{self._subnet}.2"

    @property
    def ssh_port(self) -> int:
        return 22

    @abstractmethod
    def setup_network(self) -> None:
        """Ensure host-side networking is ready before QEMU starts."""

    @abstractmethod
    def qemu_netdev_arg(self) -> str:
        """Return the full value of QEMU's -netdev flag."""

    def network_config_override(self) -> str | None:
        """Return a cloud-init network-config string, or None to use the file."""
        return f"""\
version: 2
ethernets:
  eth:
    match:
      macaddress: "52:54:00:12:34:56"
    addresses:
      - {self.ssh_host}/24
    routes:
      - to: default
        via: {self.host_ip}
"""

    # -- QEMU --

    @property
    def qemu_bin(self) -> str:
        return self.arch.qemu_bin

    @property
    def image_url(self) -> str:
        return self.arch.debian_image_url

    @property
    def needs_efi(self) -> bool:
        return self.arch == Arch.ARM64

    @property
    @abstractmethod
    def machine_args(self) -> list[str]:
        """QEMU -machine/-cpu args."""

    @abstractmethod
    def prepare_efi(self, state_dir: Path) -> tuple[Path, Path]:
        """
        Return (efi_code_path, efi_vars_path), creating them in state_dir if needed.
        Both must be exactly 64 MiB so QEMU can map them as pflash devices.
        """

    @abstractmethod
    def teardown_network(self) -> None:
        """Clean up host-side networking (non-privileged) after QEMU exits."""

    def setup_firewall(self) -> None:
        """Load firewall rules restricting guest→host traffic. Requires sudo."""

    def teardown_firewall(self) -> None:
        """Remove firewall rules. Requires sudo."""

    @abstractmethod
    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        """Launch QEMU, wrapping with any platform-specific launcher."""


# ---------------------------------------------------------------------------
# Darwin (macOS) backend
# ---------------------------------------------------------------------------

class DarwinBackend(Backend):
    """macOS backend: socket_vmnet for host-only networking, HVF acceleration."""

    # Anchor namespace: macOS's default /etc/pf.conf evaluates
    # `anchor "com.apple/*"`, so sub-anchors in this namespace are
    # automatically active without modifying any system files.
    # Alternatives considered:
    #   - Custom anchor in /etc/pf.conf: invasive, reset by macOS updates,
    #     silent security regression if the line is lost.
    #   - pfctl -f with standalone file: replaces ALL pf rules, dangerous.
    #   - LaunchDaemon for custom anchor: over-engineered for a dev tool.
    # The com.apple/* pattern has been stable since macOS 10.10 and is used
    # by Apple's own services.  If Apple removes it, the firewall fails
    # open — the nmap test in test_e2e.py will catch this.
    _PF_ANCHOR = "com.apple/agent-vm"

    def __init__(self, brew: Path, arch: Arch, subnet: str, proxy_port: int = PROXY_PORT) -> None:
        super().__init__(arch, subnet, proxy_port)
        self._brew = brew
        self._vmnet_proc: subprocess.Popen | None = None

    # -- Network --

    def setup_network(self) -> None:
        socket_path = self._socket_path
        if not socket_path.is_socket():
            self._start_socket_vmnet()

        # Verify the expected gateway IP is assigned to a local interface.
        # socket_vmnet assigns --vmnet-gateway to a bridge interface; if the
        # daemon was started with a different gateway, the guest won't be
        # able to reach the host and SSH probes will silently fail.
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        if f"inet {self.host_ip} " not in result.stdout:
            sys.exit(
                f"socket_vmnet appears to be running on a different subnet.\n"
                f"Expected {self.host_ip} on a local interface, but it was not found.\n"
                "\n"
                "Restart socket_vmnet with the matching gateway:\n"
                "\n"
                f"  sudo {self._brew}/opt/socket_vmnet/bin/socket_vmnet \\\n"
                f"      --vmnet-mode=host \\\n"
                f"      --vmnet-gateway={self.host_ip} \\\n"
                f"      --vmnet-dhcp-end={self._subnet}.254 \\\n"
                f"      --vmnet-mask=255.255.255.0 \\\n"
                f"      {self._socket_path}\n"
            )

    def _start_socket_vmnet(self) -> None:
        """Launch socket_vmnet via sudo.

        Prints a justification explaining what needs root and why before
        the sudo prompt appears.  Polls for the socket to appear.
        """
        socket_vmnet = self._brew / "opt/socket_vmnet/bin/socket_vmnet"
        if not socket_vmnet.exists():
            sys.exit("socket_vmnet not found. Install via: brew install socket_vmnet")

        socket_path = self._socket_path
        socket_dir = socket_path.parent
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

        print(
            "socket_vmnet needs to run as root because macOS's vmnet framework\n"
            "requires a privileged entitlement.  The following will run with sudo:\n"
            "\n"
            f"  1. Create socket directory:  mkdir -p {socket_dir}\n"
            f"  2. Set ownership:            chown {user} {socket_dir}\n"
            f"  3. Start vmnet daemon:       {socket_vmnet.name} --vmnet-mode=host ...\n"
            "\n"
            "The daemon will be stopped automatically when vm.py exits.\n"
        )

        _sudo("mkdir", "-p", str(socket_dir))
        _sudo("chown", user, str(socket_dir))
        _sudo("chmod", "700", str(socket_dir))

        self._vmnet_proc = subprocess.Popen([
            "sudo", str(socket_vmnet),
            "--vmnet-mode=host",
            f"--vmnet-gateway={self.host_ip}",
            f"--vmnet-dhcp-end={self._subnet}.254",
            "--vmnet-mask=255.255.255.0",
            str(socket_path),
        ])

        # Wait for the socket to appear.
        for _ in range(30):
            if socket_path.is_socket():
                break
            if self._vmnet_proc.poll() is not None:
                sys.exit(
                    f"socket_vmnet exited immediately (rc={self._vmnet_proc.returncode}). "
                    "Is another instance already running for this subnet?"
                )
            time.sleep(0.5)
        else:
            self._vmnet_proc.terminate()
            sys.exit("socket_vmnet did not create socket within 15s")

    def setup_firewall(self) -> None:
        """Load pf rules restricting guest→host traffic to the proxy port.

        Rules go into the com.apple/agent-vm anchor which macOS's default
        pf.conf evaluates via ``anchor "com.apple/*"``.  Requires sudo.
        """
        pf_rules = self.pf_rules()
        subprocess.run(
            ["sudo", "pfctl", "-a", self._PF_ANCHOR, "-f", "-"],
            input=pf_rules, text=True, check=True, capture_output=True,
        )
        # Enable pf (reference-counted; harmless if already enabled).
        subprocess.run(["sudo", "pfctl", "-E"], capture_output=True)

        # Verify the anchor is active (catches the case where macOS
        # stopped evaluating com.apple/* anchors in a future release).
        result = subprocess.run(
            ["sudo", "pfctl", "-a", self._PF_ANCHOR, "-sr"],
            capture_output=True, text=True,
        )
        if "block" not in result.stdout:
            print(
                "WARNING: pf anchor rules may not be active. "
                "Host ports may be accessible from the VM.",
                file=sys.stderr,
            )

    def teardown_firewall(self) -> None:
        subprocess.run(
            ["sudo", "pfctl", "-a", self._PF_ANCHOR, "-F", "all"],
            capture_output=True,
        )

    def teardown_network(self) -> None:
        if self._vmnet_proc is not None:
            # socket_vmnet runs as root; terminate via sudo kill.
            subprocess.run(
                ["sudo", "kill", str(self._vmnet_proc.pid)],
                capture_output=True,
            )
            self._vmnet_proc.wait(timeout=5)
            self._vmnet_proc = None

    def pf_rules(self) -> str:
        """Return the pf rule text for the current subnet/port."""
        return (
            f"pass in quick proto tcp from {self.ssh_host} to {self.host_ip} port {self.proxy_port}\n"
            f"block in quick from {self._subnet}.0/24 to any\n"
        )

    def qemu_netdev_arg(self) -> str:
        return "socket,id=net0,fd=3"

    # -- QEMU --

    @property
    def machine_args(self) -> list[str]:
        if self.arch == Arch.ARM64:
            return ["-machine", "virt,accel=hvf", "-cpu", "host"]
        return ["-machine", "q35,accel=hvf", "-cpu", "host"]

    def prepare_efi(self, state_dir: Path) -> tuple[Path, Path]:
        code_src = self._brew / "share/qemu/edk2-aarch64-code.fd"
        if not code_src.exists():
            sys.exit(f"UEFI firmware not found at {code_src}\nInstall: brew install qemu")
        vars_src = self._brew / "share/qemu/edk2-arm-vars.fd"
        return _prepare_efi(state_dir, code_src, vars_src)

    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        client = self._brew / "opt/socket_vmnet/bin/socket_vmnet_client"
        return subprocess.Popen([str(client), str(self._socket_path), self.qemu_bin, *qemu_args])

    @property
    def _socket_path(self) -> Path:
        # Each subnet gets its own socket so multiple instances can coexist
        # (e.g. a long-running default VM on 192.168.100 alongside a test
        # run on 192.168.101).  The default subnet keeps the conventional
        # name for backward compatibility with existing setups.
        if self._subnet == "192.168.100":
            return self._brew / "var/run/socket_vmnet.host"
        return self._brew / f"var/run/socket_vmnet.{self._subnet}"


# ---------------------------------------------------------------------------
# Linux backend
# ---------------------------------------------------------------------------

class LinuxBackend(Backend):
    """Linux backend: TAP/bridge networking with host-side iptables, KVM (or TCG) acceleration."""

    _BRIDGE = "vm-br0"
    _TAP = "vm-tap0"

    def __init__(self, arch: Arch, subnet: str, proxy_port: int = PROXY_PORT) -> None:
        super().__init__(arch, subnet, proxy_port)
        self._accel = "kvm" if Path("/dev/kvm").exists() else "tcg"

    # -- Network --

    def setup_network(self) -> None:
        """Create bridge + TAP device.

        All commands use sudo.  The bridge gives the guest a dedicated L2
        segment.  Firewall rules are applied separately by setup_firewall().
        """
        br, tap = self._BRIDGE, self._TAP
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

        # -- Bridge --
        if not Path(f"/sys/class/net/{br}").exists():
            _sudo("ip", "link", "add", br, "type", "bridge")
            _sudo("ip", "addr", "add", f"{self.host_ip}/24", "dev", br)
            _sudo("ip", "link", "set", br, "up")

        # -- TAP device (owned by the current user so QEMU can open it) --
        if not Path(f"/sys/class/net/{tap}").exists():
            _sudo("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user)
            _sudo("ip", "link", "set", tap, "master", br)
            _sudo("ip", "link", "set", tap, "up")

    def setup_firewall(self) -> None:
        for rule in self._iptables_rules():
            # -C checks existence; add only if missing (idempotent).
            if subprocess.run(
                ["sudo", "iptables", "-C", *rule],
                capture_output=True,
            ).returncode != 0:
                _sudo("iptables", "-A", *rule)

    def teardown_firewall(self) -> None:
        for rule in self._iptables_rules():
            subprocess.run(["sudo", "iptables", "-D", *rule], capture_output=True)

    def teardown_network(self) -> None:
        br, tap = self._BRIDGE, self._TAP

        if Path(f"/sys/class/net/{tap}").exists():
            _sudo("ip", "link", "del", tap)
        if Path(f"/sys/class/net/{br}").exists():
            _sudo("ip", "link", "del", br)

    def _iptables_rules(self) -> list[list[str]]:
        """Return the iptables rule specs (without -A/-C/-D prefix)."""
        br = self._BRIDGE
        return [
            ["INPUT", "-i", br, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["INPUT", "-i", br, "-p", "tcp", "--dport", str(self.proxy_port), "-j", "ACCEPT"],
            ["INPUT", "-i", br, "-j", "REJECT"],
            ["FORWARD", "-i", br, "-j", "REJECT"],
        ]

    def qemu_netdev_arg(self) -> str:
        return f"tap,id=net0,ifname={self._TAP},script=no,downscript=no"

    # -- QEMU --

    @property
    def machine_args(self) -> list[str]:
        if self.arch == Arch.ARM64:
            cpu = "host" if self._accel == "kvm" else "cortex-a57"
            return ["-machine", f"virt,accel={self._accel}", "-cpu", cpu]
        cpu = "host" if self._accel == "kvm" else "qemu64"
        return ["-machine", f"q35,accel={self._accel}", "-cpu", cpu]

    def prepare_efi(self, state_dir: Path) -> tuple[Path, Path]:
        code_src = Path("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd")
        if not code_src.exists():
            sys.exit("UEFI firmware not found. Install: apt install qemu-efi-aarch64")
        return _prepare_efi(state_dir, code_src, vars_src=None)

    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        return subprocess.Popen([self.qemu_bin, *qemu_args])


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def _sudo(*args: str) -> None:
    """Run a command via sudo, raising on failure."""
    subprocess.run(["sudo", *args], check=True)


def make_backend(subnet: str = "192.168.100", proxy_port: int = PROXY_PORT) -> Backend:
    arch = Arch.detect()

    if sys.platform == "darwin":
        return DarwinBackend(brew=_brew_prefix(), arch=arch, subnet=subnet, proxy_port=proxy_port)
    elif sys.platform == "linux":
        return LinuxBackend(arch=arch, subnet=subnet, proxy_port=proxy_port)
    else:
        sys.exit(f"Unsupported OS: {sys.platform}")


def _brew_prefix() -> Path:
    result = subprocess.run(["brew", "--prefix"], capture_output=True, text=True, check=True)
    return Path(result.stdout.strip())


# ---------------------------------------------------------------------------
# Platform-independent helpers
# ---------------------------------------------------------------------------

def _indent(text: str, n: int) -> str:
    """Indent every line of *text* by *n* spaces."""
    prefix = " " * n
    return "".join(prefix + line + "\n" for line in text.splitlines()) + "\n"


def _build_iso(source_dir: str, output: Path) -> None:
    """Build a cloud-init seed ISO from *source_dir*."""
    if sys.platform == "darwin":
        subprocess.run(
            ["hdiutil", "makehybrid", "-iso", "-joliet",
             "-default-volume-name", "cidata", "-o", str(output), source_dir],
            check=True,
        )
        # hdiutil appends .cdr to the output path; rename it.
        cdr = Path(str(output) + ".cdr")
        if cdr.exists():
            cdr.rename(output)
    else:
        tool = "mkisofs" if shutil.which("mkisofs") else "xorriso"
        cmd = [tool] if tool == "mkisofs" else [tool, "-as", "mkisofs"]
        subprocess.run(
            [*cmd, "-output", str(output), "-volid", "cidata",
             "-joliet", "-rock", source_dir],
            check=True, capture_output=True,
        )


def _prepare_efi(state_dir: Path, code_src: Path, vars_src: Path | None) -> tuple[Path, Path]:
    """Prepare 64 MiB pflash images for QEMU EFI boot.

    Copies *code_src* into state_dir (padding to 64 MiB if smaller).
    Copies *vars_src* if provided, otherwise creates a zero-filled file.
    """
    flash_size = 64 * 1024 * 1024

    efi_code = state_dir / "efi-code.fd"
    if not efi_code.exists():
        fw = code_src.read_bytes()
        if len(fw) < flash_size:
            fw += b"\x00" * (flash_size - len(fw))
        efi_code.write_bytes(fw)

    efi_vars = state_dir / "efi-vars.fd"
    if not efi_vars.exists():
        if vars_src and vars_src.exists():
            shutil.copy(vars_src, efi_vars)
        else:
            efi_vars.write_bytes(b"\x00" * flash_size)

    return efi_code, efi_vars


def ensure_ssh_key() -> None:
    key = STATE_DIR / "id_ed25519"
    if not key.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-C", "vm-access", "-q"],
            check=True,
        )


def ensure_base_image(backend: Backend) -> None:
    base = IMAGES_DIR / "base.qcow2"
    if not base.exists():
        image_url = backend.image_url
        image_filename = image_url.rsplit("/", 1)[1]
        checksums_url = image_url.rsplit("/", 1)[0] + "/SHA512SUMS"

        print("Downloading Debian testing cloud image...")
        tmp_image = IMAGES_DIR / "base.qcow2.tmp"
        subprocess.run(["curl", "-L", "-o", str(tmp_image), image_url], check=True)

        print("Verifying image checksum...")
        checksums_file = IMAGES_DIR / "SHA512SUMS"
        subprocess.run(["curl", "-L", "-o", str(checksums_file), checksums_url], check=True)

        expected_hash = None
        for line in checksums_file.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == image_filename:
                expected_hash = parts[0]
                break

        if expected_hash is None:
            tmp_image.unlink(missing_ok=True)
            sys.exit(f"Image filename {image_filename} not found in SHA512SUMS")

        sha512 = hashlib.sha512()
        with open(tmp_image, "rb") as f:
            while chunk := f.read(1 << 20):
                sha512.update(chunk)
        actual_hash = sha512.hexdigest()

        if actual_hash != expected_hash:
            tmp_image.unlink(missing_ok=True)
            sys.exit(
                f"Image checksum mismatch!\n"
                f"  Expected: {expected_hash}\n"
                f"  Got:      {actual_hash}\n"
                "The download may be corrupted or tampered with."
            )

        tmp_image.rename(base)
        print("Image checksum verified.")


def ensure_disk() -> None:
    disk = STATE_DIR / "disk.qcow2"
    if not disk.exists():
        print("Creating VM disk...")
        base = IMAGES_DIR / "base.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-b", str(base), "-F", "qcow2", str(disk), "20G"],
            check=True,
        )


def build_seed_iso(backend: Backend, extra_user_data: Path | None = None) -> None:
    seed = STATE_DIR / "seed.iso"
    if seed.exists():
        return

    print("Building cloud-init seed ISO...")
    ssh_pub = (STATE_DIR / "id_ed25519.pub").read_text().strip()
    override = backend.network_config_override()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for src in CLOUD_INIT_DIR.iterdir():
            if override is not None and src.name == "network-config":
                (tmp_path / src.name).write_text(override)
            else:
                content = src.read_text()
                content = content.replace("__SSH_PUB_KEY__", ssh_pub)
                content = content.replace("__HOST_IP__", backend.host_ip)
                content = content.replace("__PROXY_PORT__", str(backend.proxy_port))
                if src.name == "user-data" and extra_user_data is not None:
                    # Merge base + extra via cloud-init's cloud-config-archive.
                    # merge_how tells cloud-init to append list keys (packages,
                    # runcmd, etc.) rather than letting the second part replace
                    # the first.  Without this, only the last part's packages
                    # list is installed.
                    merge_directive = (
                        "merge_how:\n"
                        " - name: list\n"
                        "   settings: [append]\n"
                        " - name: dict\n"
                        "   settings: [no_replace, recurse_list]\n"
                    )
                    base_part = content.rstrip() + "\n" + merge_directive
                    extra_part = extra_user_data.read_text().rstrip() + "\n" + merge_directive
                    content = (
                        "#cloud-config-archive\n"
                        "- type: \"text/cloud-config\"\n"
                        "  content: |\n"
                        + _indent(base_part, 4)
                        + "- type: \"text/cloud-config\"\n"
                        "  content: |\n"
                        + _indent(extra_part, 4)
                    )
                (tmp_path / src.name).write_text(content)

        _build_iso(tmp, seed)


def build_qemu_args(backend: Backend, memory: str) -> list[str]:
    disk = STATE_DIR / "disk.qcow2"
    seed = STATE_DIR / "seed.iso"

    args = backend.machine_args + [
        "-m", memory, "-smp", "1",
        "-nographic",
        "-drive", f"file={disk},if=virtio",
        "-drive", f"file={seed},if=virtio,media=cdrom",
        "-device", "virtio-net-pci,netdev=net0",
        "-netdev", backend.qemu_netdev_arg(),
        "-virtfs", f"local,path={SHARED_DIR},mount_tag=shared,security_model=mapped-xattr,id=shared",
    ]

    if backend.needs_efi:
        efi_code, efi_vars = backend.prepare_efi(STATE_DIR)
        args = [
            "-drive", f"if=pflash,format=raw,readonly=on,file={efi_code}",
            "-drive", f"if=pflash,format=raw,file={efi_vars}",
        ] + args

    return args


def start_mitmproxy(listen_host: str, proxy_port: int = PROXY_PORT) -> subprocess.Popen:
    """Start mitmdump in the background, logging to .vm/mitmdump.log."""
    log_path = STATE_DIR / "mitmdump.log"
    cmd = ["mitmdump", "--listen-host", listen_host, "-p", str(proxy_port)]

    # If this host itself uses an upstream proxy (e.g. we're inside a sandboxed
    # VM), forward mitmproxy's own outbound traffic through it.
    upstream = (os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or
                os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))
    if upstream:
        cmd += ["--mode", f"upstream:{upstream}"]
        # If a caller has pre-placed the upstream proxy's CA cert here
        # (e.g. the test suite when running inside a sandboxed VM),
        # pass it to mitmdump so upstream TLS verification works.
        outer_ca = STATE_DIR / "upstream-ca.pem"
        if outer_ca.exists():
            cmd += ["--set", f"ssl_verify_upstream_trusted_ca={outer_ca}"]
        print(f"  (forwarding upstream through {upstream})")

    filter_script = SCRIPT_DIR / "filter.py"
    if filter_script.exists():
        cmd += ["--script", str(filter_script)]

    log_file = log_path.open("w")
    print(f"Starting mitmproxy on port {proxy_port} (log: .vm/mitmdump.log)...")
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)
    time.sleep(1)
    if proc.poll() is not None:
        log_file.flush()
        sys.exit(
            f"mitmdump failed to start (exit code {proc.returncode}). "
            f"Check {log_path} — port {proxy_port} may already be in use."
        )
    return proc


def _ssh_args(backend: Backend) -> list[str]:
    """Return the SSH command-line arguments for connecting to the VM."""
    return [
        "ssh",
        "-i", str(STATE_DIR / "id_ed25519"),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(backend.ssh_port),
        "-q",
        f"vm@{backend.ssh_host}",
    ]


def _wait_for_ssh(backend: Backend, qemu_proc: subprocess.Popen,
                  timeout: int = 300) -> None:
    """Poll SSH until the VM accepts connections, or exit on timeout/crash."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        if qemu_proc.poll() is not None:
            # Dump console log tail to help debug.
            console = STATE_DIR / "console.log"
            if console.exists():
                tail = console.read_text(errors="replace")[-2048:]
                print(f"\n--- last console output ---\n{tail}", file=sys.stderr)
            sys.exit(
                f"QEMU exited prematurely (rc={qemu_proc.returncode}). "
                "Check .vm/console.log for details."
            )
        attempt += 1
        remaining = int(deadline - time.monotonic())
        print(f"\r  Waiting for SSH... attempt {attempt} ({remaining}s remaining)  ",
              end="", flush=True)
        try:
            r = subprocess.run(
                [*_ssh_args(backend), "-o", "ConnectTimeout=5", "true"],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0:
                print(f"\r  SSH ready after {attempt} attempt(s).{'':30}")
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(10)

    console = STATE_DIR / "console.log"
    if console.exists():
        tail = console.read_text(errors="replace")[-2048:]
        print(f"\n--- last console output ---\n{tail}", file=sys.stderr)
    sys.exit(
        f"VM did not become SSH-accessible within {timeout}s. "
        "Check .vm/console.log for boot output."
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> None:
    backend = make_backend(subnet=args.subnet, proxy_port=args.proxy_port)
    interactive = sys.stdout.isatty()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    SHARED_DIR.mkdir(parents=True, exist_ok=True)

    backend.setup_network()
    if not args.no_firewall:
        backend.setup_firewall()
    ensure_ssh_key()
    ensure_base_image(backend)
    ensure_disk()
    extra = Path(args.extra_user_data) if args.extra_user_data else None
    build_seed_iso(backend, extra_user_data=extra)

    mitm = start_mitmproxy(listen_host=backend.host_ip, proxy_port=backend.proxy_port)

    qemu_args = build_qemu_args(backend, memory=args.memory)

    if interactive:
        # Background QEMU with serial output to file, then drop into SSH.
        console_log = STATE_DIR / "console.log"
        qemu_args = [a for a in qemu_args if a != "-nographic"]
        qemu_args += ["-serial", f"file:{console_log}", "-monitor", "none", "-display", "none"]

        print(f"\nStarting VM (console: .vm/console.log)...")
        print(f"  Proxy:    http://{backend.host_ip}:{backend.proxy_port} (from guest)")
        print(f"  Logs:     tail -f .vm/mitmdump.log")
        print()

        qemu_proc = backend.launch_qemu(qemu_args)
        signal.signal(signal.SIGTERM, lambda *_: qemu_proc.terminate())

        try:
            _wait_for_ssh(backend, qemu_proc)
            print(f"  Log out of the SSH session to stop the VM.\n")
            subprocess.run([*_ssh_args(backend)])
        except KeyboardInterrupt:
            pass
        finally:
            qemu_proc.terminate()
            qemu_proc.wait()
            mitm.terminate()
            mitm.wait()
            if not args.no_firewall:
                backend.teardown_firewall()
            backend.teardown_network()
    else:
        # Non-interactive: foreground QEMU with serial console on stdout.
        # Used by the test suite (stdout redirected to a file).
        print(f"\nStarting VM...")
        print(f"  SSH:      ./vm.py ssh")
        print(f"  Proxy:    http://{backend.host_ip}:{backend.proxy_port} (from guest)")
        print(f"  Logs:     tail -f .vm/mitmdump.log")
        print(f"  Quit:     Ctrl-A X")
        print()

        qemu_proc = backend.launch_qemu(qemu_args)
        signal.signal(signal.SIGTERM, lambda *_: qemu_proc.terminate())

        try:
            qemu_rc = qemu_proc.wait()
        except KeyboardInterrupt:
            qemu_proc.terminate()
            qemu_proc.wait()
            qemu_rc = 0  # clean user exit
        finally:
            mitm.terminate()
            mitm.wait()
            if not args.no_firewall:
                backend.teardown_firewall()
            backend.teardown_network()

        if qemu_rc != 0:
            sys.exit(f"QEMU exited with code {qemu_rc}")


def cmd_ssh(args: argparse.Namespace) -> None:
    backend = make_backend(subnet=args.subnet)
    os.execvp("ssh", [*_ssh_args(backend), *args.cmd])


def cmd_reset(args: argparse.Namespace) -> None:
    if STATE_DIR.exists():
        # ignore_errors handles FUSE hidden files (.fuse_hidden*) on 9p
        # shared mounts that can't be removed while the host holds them open.
        shutil.rmtree(STATE_DIR, ignore_errors=True)
    print("VM state removed. Base image kept in .images/.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent VM — sandboxed Debian VM with mitmproxy traffic control.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    start_p = sub.add_parser("start", help="Start networking, mitmproxy, and QEMU")
    start_p.add_argument(
        "--memory", default="2G", metavar="SIZE",
        help="RAM to give the VM, in QEMU notation (default: 2G)",
    )
    start_p.add_argument(
        "--extra-user-data", metavar="FILE",
        help="Extra cloud-init user-data file merged with the base config "
             "(packages, runcmd, write_files, etc. are appended)",
    )
    start_p.add_argument(
        "--subnet", default="192.168.100", metavar="PREFIX",
        help="First three octets of the VM subnet (default: 192.168.100). "
             "Host gets .1, guest gets .2. Change to avoid collisions "
             "when running inside another VM on the same subnet.",
    )
    start_p.add_argument(
        "--proxy-port", default=PROXY_PORT, type=int, metavar="PORT",
        help=f"Port for the mitmproxy listener (default: {PROXY_PORT}). "
             "Change to run multiple VMs simultaneously on different subnets.",
    )
    start_p.add_argument(
        "--no-firewall", action="store_true",
        help="Skip host-side firewall setup (pf/iptables). "
             "Useful when running from a test suite that should not prompt for sudo.",
    )
    sub.add_parser("reset", help="Destroy ephemeral VM state (keeps base image and SSH key)")

    ssh_p = sub.add_parser("ssh", help="SSH into the VM")
    ssh_p.add_argument("cmd", nargs=argparse.REMAINDER, help="Optional command to run in VM")
    ssh_p.add_argument(
        "--subnet", default="192.168.100", metavar="PREFIX",
        help="Must match the --subnet used with start (default: 192.168.100).",
    )

    args = parser.parse_args()

    if args.command == "start":
        cmd_start(args)
    elif args.command == "ssh":
        cmd_ssh(args)
    elif args.command == "reset":
        cmd_reset(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
