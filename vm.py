#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["mitmproxy"]
# ///

"""Agent VM — sandboxed Debian VM with mitmproxy traffic control."""

import argparse
import os
import platform
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

    def __init__(self, arch: Arch) -> None:
        self.arch = arch

    # -- Network --

    @property
    @abstractmethod
    def host_ip(self) -> str:
        """IP address the guest uses to reach the proxy on the host."""

    @property
    @abstractmethod
    def ssh_host(self) -> str:
        """Hostname/IP to SSH to from the host."""

    @property
    @abstractmethod
    def ssh_port(self) -> int:
        """SSH port to connect to (may differ from 22 via port-forwarding)."""

    @abstractmethod
    def setup_network(self) -> None:
        """Ensure host-side networking is ready before QEMU starts."""

    @abstractmethod
    def qemu_netdev_arg(self) -> str:
        """Return the full value of QEMU's -netdev flag."""

    @abstractmethod
    def network_config_override(self) -> str | None:
        """Return a cloud-init network-config string, or None to use the file."""

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
    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        """Launch QEMU, wrapping with any platform-specific launcher."""


# ---------------------------------------------------------------------------
# Darwin (macOS) backend
# ---------------------------------------------------------------------------

class DarwinBackend(Backend):
    """macOS backend: socket_vmnet for host-only networking, HVF acceleration."""

    def __init__(self, brew: Path, arch: Arch) -> None:
        super().__init__(arch)
        self._brew = brew

    # -- Network --

    @property
    def host_ip(self) -> str:
        return "192.168.100.1"

    @property
    def ssh_host(self) -> str:
        return "192.168.100.2"

    @property
    def ssh_port(self) -> int:
        return 22

    def setup_network(self) -> None:
        socket_path = self._socket_path
        if socket_path.is_socket():
            return

        socket_vmnet = self._brew / "opt/socket_vmnet/bin/socket_vmnet"
        if not socket_vmnet.exists():
            sys.exit("socket_vmnet not found. Install via: brew install socket_vmnet")

        socket_dir = socket_path.parent
        sys.exit(
            f"socket_vmnet is not running (socket not found at {socket_path}).\n"
            "\n"
            "Start it in a separate terminal before running vm.py:\n"
            "\n"
            f"  sudo mkdir -p {socket_dir}\n"
            f"  sudo chown $USER {socket_dir}\n"
            f"  sudo chmod 700 {socket_dir}\n"
            f"  sudo {socket_vmnet} \\\n"
            f"      --vmnet-mode=host \\\n"
            f"      --vmnet-gateway=192.168.100.1 \\\n"
            f"      --vmnet-dhcp-end=192.168.100.254 \\\n"
            f"      --vmnet-mask=255.255.255.0 \\\n"
            f"      {socket_path}\n"
            "\n"
            "Verify the socket exists before continuing:\n"
            f"  ls -la {socket_path}\n"
            "\n"
            "socket_vmnet is open source: https://github.com/lima-vm/socket_vmnet"
        )

    def qemu_netdev_arg(self) -> str:
        return "socket,id=net0,fd=3"

    def network_config_override(self) -> str | None:
        return None  # use cloud-init/network-config as-is

    # -- QEMU --

    @property
    def machine_args(self) -> list[str]:
        if self.arch == Arch.ARM64:
            return ["-machine", "virt,accel=hvf", "-cpu", "host"]
        return ["-machine", "q35,accel=hvf", "-cpu", "host"]

    def prepare_efi(self, state_dir: Path) -> tuple[Path, Path]:
        # Homebrew ships properly-sized 64 MiB EDK2 images; use them directly.
        efi_code = self._brew / "share/qemu/edk2-aarch64-code.fd"
        if not efi_code.exists():
            sys.exit(f"UEFI firmware not found at {efi_code}\nInstall: brew install qemu")

        efi_vars = state_dir / "efi-vars.fd"
        if not efi_vars.exists():
            template = self._brew / "share/qemu/edk2-arm-vars.fd"
            if template.exists():
                shutil.copy(template, efi_vars)
            else:
                efi_vars.write_bytes(b"\x00" * (64 * 1024 * 1024))
        return efi_code, efi_vars

    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        client = self._brew / "opt/socket_vmnet/bin/socket_vmnet_client"
        return subprocess.Popen([str(client), str(self._socket_path), self.qemu_bin, *qemu_args])

    @property
    def _socket_path(self) -> Path:
        return self._brew / "var/run/socket_vmnet.host"


# ---------------------------------------------------------------------------
# Linux backend
# ---------------------------------------------------------------------------

class LinuxBackend(Backend):
    """Linux backend: QEMU user networking, KVM (or TCG) acceleration."""

    def __init__(self, arch: Arch) -> None:
        super().__init__(arch)
        self._accel = "kvm" if Path("/dev/kvm").exists() else "tcg"

    # -- Network --

    @property
    def host_ip(self) -> str:
        return "10.0.2.2"  # QEMU user-networking gateway

    @property
    def ssh_host(self) -> str:
        return "127.0.0.1"

    @property
    def ssh_port(self) -> int:
        return 2222

    def setup_network(self) -> None:
        pass  # user networking is built into QEMU, nothing to start

    def qemu_netdev_arg(self) -> str:
        return f"user,id=net0,hostfwd=tcp::{self.ssh_port}-:22"

    def network_config_override(self) -> str | None:
        """Use DHCP — QEMU user networking provides it at 10.0.2.15."""
        return """\
version: 2
ethernets:
  eth:
    match:
      macaddress: "52:54:00:12:34:56"
    dhcp4: true
"""

    # -- QEMU --

    @property
    def machine_args(self) -> list[str]:
        if self.arch == Arch.ARM64:
            cpu = "host" if self._accel == "kvm" else "cortex-a57"
            return ["-machine", f"virt,accel={self._accel}", "-cpu", cpu]
        cpu = "host" if self._accel == "kvm" else "qemu64"
        return ["-machine", f"q35,accel={self._accel}", "-cpu", cpu]

    def prepare_efi(self, state_dir: Path) -> tuple[Path, Path]:
        # The Debian package ships a raw 3 MiB firmware blob; QEMU pflash
        # requires exactly 64 MiB.  We pad it once into state_dir.
        src = Path("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd")
        if not src.exists():
            sys.exit("UEFI firmware not found. Install: apt install qemu-efi-aarch64")

        flash_size = 64 * 1024 * 1024

        efi_code = state_dir / "efi-code.fd"
        if not efi_code.exists():
            fw = src.read_bytes()
            efi_code.write_bytes(fw + b"\x00" * (flash_size - len(fw)))

        efi_vars = state_dir / "efi-vars.fd"
        if not efi_vars.exists():
            efi_vars.write_bytes(b"\x00" * flash_size)

        return efi_code, efi_vars

    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        return subprocess.Popen([self.qemu_bin, *qemu_args])


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def make_backend() -> Backend:
    arch = Arch.detect()

    if sys.platform == "darwin":
        return DarwinBackend(brew=_brew_prefix(), arch=arch)
    elif sys.platform == "linux":
        return LinuxBackend(arch=arch)
    else:
        sys.exit(f"Unsupported OS: {sys.platform}")


def _brew_prefix() -> Path:
    result = subprocess.run(["brew", "--prefix"], capture_output=True, text=True, check=True)
    return Path(result.stdout.strip())


# ---------------------------------------------------------------------------
# Platform-independent helpers
# ---------------------------------------------------------------------------

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
        print("Downloading Debian testing cloud image...")
        subprocess.run(["curl", "-L", "-o", str(base), backend.image_url], check=True)


def ensure_disk() -> None:
    disk = STATE_DIR / "disk.qcow2"
    if not disk.exists():
        print("Creating VM disk...")
        base = IMAGES_DIR / "base.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-b", str(base), "-F", "qcow2", str(disk), "20G"],
            check=True,
        )


def build_seed_iso(backend: Backend) -> None:
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
                content = content.replace("__PROXY_PORT__", str(PROXY_PORT))
                (tmp_path / src.name).write_text(content)

        if shutil.which("mkisofs"):
            subprocess.run(
                ["mkisofs", "-output", str(seed), "-volid", "cidata", "-joliet", "-rock", tmp],
                check=True, capture_output=True,
            )
        elif shutil.which("xorriso"):
            subprocess.run(
                ["xorriso", "-as", "mkisofs", "-output", str(seed), "-volid", "cidata", "-joliet", "-rock", tmp],
                check=True, capture_output=True,
            )
        else:
            subprocess.run(
                ["hdiutil", "makehybrid", "-iso", "-joliet", "-default-volume-name", "cidata", "-o", str(seed), tmp],
                check=True,
            )
            cdr = Path(str(seed) + ".cdr")
            if cdr.exists():
                cdr.rename(seed)


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
        "-virtfs", f"local,path={SHARED_DIR},mount_tag=shared,security_model=none,id=shared",
    ]

    if backend.needs_efi:
        efi_code, efi_vars = backend.prepare_efi(STATE_DIR)
        args = [
            "-drive", f"if=pflash,format=raw,readonly=on,file={efi_code}",
            "-drive", f"if=pflash,format=raw,file={efi_vars}",
        ] + args

    return args


def start_mitmproxy() -> subprocess.Popen:
    """Start mitmdump in the background, logging to .vm/mitmdump.log."""
    log_path = STATE_DIR / "mitmdump.log"
    cmd = ["mitmdump", "--listen-host", "0.0.0.0", "-p", str(PROXY_PORT)]

    # If this host itself uses an upstream proxy (e.g. we're inside a sandboxed
    # VM), forward mitmproxy's own outbound traffic through it.
    upstream = (os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or
                os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))
    if upstream:
        cmd += ["--mode", f"upstream:{upstream}"]
        print(f"  (forwarding upstream through {upstream})")

    filter_script = SCRIPT_DIR / "filter.py"
    if filter_script.exists():
        cmd += ["--script", str(filter_script)]

    log_file = log_path.open("w")
    print(f"Starting mitmproxy on port {PROXY_PORT} (log: .vm/mitmdump.log)...")
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)
    time.sleep(1)
    if proc.poll() is not None:
        log_file.flush()
        sys.exit(
            f"mitmdump failed to start (exit code {proc.returncode}). "
            f"Check {log_path} — port {PROXY_PORT} may already be in use."
        )
    return proc


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> None:
    backend = make_backend()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    SHARED_DIR.mkdir(parents=True, exist_ok=True)

    backend.setup_network()
    ensure_ssh_key()
    ensure_base_image(backend)
    ensure_disk()
    build_seed_iso(backend)

    mitm = start_mitmproxy()

    print(f"\nStarting VM...")
    print(f"  SSH:      ./vm.py ssh")
    print(f"  Proxy:    http://{backend.host_ip}:{PROXY_PORT} (from guest)")
    print(f"  Logs:     tail -f .vm/mitmdump.log")
    print(f"  Quit:     Ctrl-A X")
    print()

    qemu_proc = backend.launch_qemu(build_qemu_args(backend, memory=args.memory))
    try:
        qemu_rc = qemu_proc.wait()
    except KeyboardInterrupt:
        qemu_proc.terminate()
        qemu_proc.wait()
        qemu_rc = 0  # clean user exit
    finally:
        mitm.terminate()
        mitm.wait()

    if qemu_rc != 0:
        sys.exit(f"QEMU exited with code {qemu_rc}")


def cmd_ssh(args: argparse.Namespace) -> None:
    backend = make_backend()
    key = STATE_DIR / "id_ed25519"
    os.execvp("ssh", [
        "ssh",
        "-i", str(key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(backend.ssh_port),
        "-q",
        f"vm@{backend.ssh_host}",
        *args.cmd,
    ])


def cmd_reset(args: argparse.Namespace) -> None:
    if STATE_DIR.exists():
        shutil.rmtree(STATE_DIR)
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
    sub.add_parser("reset", help="Destroy ephemeral VM state (keeps base image and SSH key)")

    ssh_p = sub.add_parser("ssh", help="SSH into the VM")
    ssh_p.add_argument("cmd", nargs=argparse.REMAINDER, help="Optional command to run in VM")

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
