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
SSH_HOST_PORT: int = 2222
STATE_DIR: Path = Path(os.environ["VM_STATE_DIR"]) if "VM_STATE_DIR" in os.environ \
    else SCRIPT_DIR / ".vm"                  # ephemeral state, nuked on reset
IMAGES_DIR: Path = SCRIPT_DIR / ".images"  # persistent download cache (base image)
SHARED_DIR: Path = SCRIPT_DIR / "shared"
CLOUD_INIT_DIR: Path = SCRIPT_DIR / "cloud-init"

# The guestfwd IP is an address inside QEMU's slirp virtual network.
# The guest connects to this IP to reach the host-side proxy.  It never
# appears on a real network interface — it's internal to the QEMU process.
_GUESTFWD_IP = "10.0.2.100"


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
    """Platform-specific QEMU configuration.

    Networking is handled by QEMU's built-in slirp stack with restrict=on,
    which isolates the guest without any host-side network devices or
    firewall rules — no sudo required.  The only platform-specific parts
    are EFI firmware paths and QEMU acceleration.
    """

    def __init__(self, arch: Arch, proxy_port: int = PROXY_PORT,
                 ssh_host_port: int = SSH_HOST_PORT) -> None:
        self.arch = arch
        self.proxy_port = proxy_port
        self.ssh_host_port = ssh_host_port

    # -- Network --

    @property
    def proxy_ip(self) -> str:
        """IP the guest uses to reach the proxy (guestfwd target inside slirp)."""
        return _GUESTFWD_IP

    def qemu_netdev_arg(self) -> str:
        """Slirp netdev with restrict=on, SSH hostfwd, and proxy guestfwd."""
        return (
            f"user,id=net0,restrict=on"
            f",hostfwd=tcp:127.0.0.1:{self.ssh_host_port}-:22"
            f",guestfwd=tcp:{_GUESTFWD_IP}:{self.proxy_port}"
            f"-cmd:nc 127.0.0.1 {self.proxy_port}"
        )

    def network_config_override(self) -> str | None:
        """Cloud-init network-config for slirp DHCP."""
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

    def launch_qemu(self, qemu_args: list[str]) -> subprocess.Popen:
        return subprocess.Popen([self.qemu_bin, *qemu_args])


# ---------------------------------------------------------------------------
# Darwin (macOS) backend
# ---------------------------------------------------------------------------

class DarwinBackend(Backend):
    """macOS backend: HVF acceleration, Homebrew firmware paths."""

    def __init__(self, brew: Path, arch: Arch, proxy_port: int = PROXY_PORT,
                 ssh_host_port: int = SSH_HOST_PORT) -> None:
        super().__init__(arch, proxy_port, ssh_host_port)
        self._brew = brew

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


# ---------------------------------------------------------------------------
# Linux backend
# ---------------------------------------------------------------------------

class LinuxBackend(Backend):
    """Linux backend: KVM (or TCG fallback) acceleration, apt firmware paths."""

    def __init__(self, arch: Arch, proxy_port: int = PROXY_PORT,
                 ssh_host_port: int = SSH_HOST_PORT) -> None:
        super().__init__(arch, proxy_port, ssh_host_port)
        self._accel = "kvm" if Path("/dev/kvm").exists() else "tcg"

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


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def make_backend(proxy_port: int = PROXY_PORT,
                 ssh_host_port: int = SSH_HOST_PORT) -> Backend:
    arch = Arch.detect()

    if sys.platform == "darwin":
        return DarwinBackend(brew=_brew_prefix(), arch=arch,
                             proxy_port=proxy_port, ssh_host_port=ssh_host_port)
    elif sys.platform == "linux":
        return LinuxBackend(arch=arch, proxy_port=proxy_port,
                            ssh_host_port=ssh_host_port)
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
                content = content.replace("__HOST_IP__", backend.proxy_ip)
                content = content.replace("__PROXY_PORT__", str(backend.proxy_port))
                if src.name == "user-data" and extra_user_data is not None:
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


def start_mitmproxy(proxy_port: int = PROXY_PORT) -> subprocess.Popen:
    """Start mitmdump in the background, logging to .vm/mitmdump.log."""
    log_path = STATE_DIR / "mitmdump.log"
    cmd = ["mitmdump", "--listen-host", "127.0.0.1", "-p", str(proxy_port)]

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


def _ssh_args(ssh_host_port: int = SSH_HOST_PORT) -> list[str]:
    """Return the SSH command-line arguments for connecting to the VM."""
    return [
        "ssh",
        "-i", str(STATE_DIR / "id_ed25519"),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(ssh_host_port),
        "-q",
        "vm@127.0.0.1",
    ]


def _wait_for_ssh(ssh_host_port: int, qemu_proc: subprocess.Popen,
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
                [*_ssh_args(ssh_host_port), "-o", "ConnectTimeout=5", "true"],
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
    backend = make_backend(proxy_port=args.proxy_port,
                           ssh_host_port=args.ssh_port)
    interactive = sys.stdout.isatty()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    SHARED_DIR.mkdir(parents=True, exist_ok=True)

    ensure_ssh_key()
    ensure_base_image(backend)
    ensure_disk()
    extra = Path(args.extra_user_data) if args.extra_user_data else None
    build_seed_iso(backend, extra_user_data=extra)

    mitm = start_mitmproxy(proxy_port=backend.proxy_port)

    qemu_args = build_qemu_args(backend, memory=args.memory)

    if interactive:
        # Background QEMU with serial output to file, then drop into SSH.
        console_log = STATE_DIR / "console.log"
        qemu_args = [a for a in qemu_args if a != "-nographic"]
        qemu_args += ["-serial", f"file:{console_log}", "-monitor", "none", "-display", "none"]

        print(f"\nStarting VM (console: .vm/console.log)...")
        print(f"  SSH:      ./vm.py ssh (port {backend.ssh_host_port})")
        print(f"  Logs:     tail -f .vm/mitmdump.log")
        print()

        qemu_proc = backend.launch_qemu(qemu_args)
        signal.signal(signal.SIGTERM, lambda *_: qemu_proc.terminate())

        try:
            _wait_for_ssh(backend.ssh_host_port, qemu_proc)
            print(f"  Log out of the SSH session to stop the VM.\n")
            subprocess.run([*_ssh_args(backend.ssh_host_port)])
        except KeyboardInterrupt:
            pass
        finally:
            qemu_proc.terminate()
            qemu_proc.wait()
            mitm.terminate()
            mitm.wait()
    else:
        # Non-interactive: foreground QEMU with serial console on stdout.
        # Used by the test suite (stdout redirected to a file).
        print(f"\nStarting VM...")
        print(f"  SSH:      ./vm.py ssh (port {backend.ssh_host_port})")
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

        if qemu_rc != 0:
            sys.exit(f"QEMU exited with code {qemu_rc}")


def cmd_ssh(args: argparse.Namespace) -> None:
    os.execvp("ssh", [*_ssh_args(args.ssh_port), *args.cmd])


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

    start_p = sub.add_parser("start", help="Start mitmproxy and QEMU")
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
        "--proxy-port", default=PROXY_PORT, type=int, metavar="PORT",
        help=f"Port for the mitmproxy listener (default: {PROXY_PORT}). "
             "Change to run multiple VMs simultaneously.",
    )
    start_p.add_argument(
        "--ssh-port", default=SSH_HOST_PORT, type=int, metavar="PORT",
        help=f"Host port forwarded to guest SSH (default: {SSH_HOST_PORT}). "
             "Change to avoid collisions with another running VM.",
    )
    sub.add_parser("reset", help="Destroy ephemeral VM state (keeps base image and SSH key)")

    ssh_p = sub.add_parser("ssh", help="SSH into the VM")
    ssh_p.add_argument("cmd", nargs=argparse.REMAINDER, help="Optional command to run in VM")
    ssh_p.add_argument(
        "--ssh-port", default=SSH_HOST_PORT, type=int, metavar="PORT",
        help=f"Host port forwarded to guest SSH (default: {SSH_HOST_PORT}). "
             "Must match the --ssh-port used with start.",
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
