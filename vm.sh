#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="$SCRIPT_DIR/.vm"
SHARED_DIR="$SCRIPT_DIR/shared"
CLOUD_INIT_DIR="$SCRIPT_DIR/cloud-init"

# --- Network configuration ---
# The VM lives on a host-only vmnet subnet with no internet access.
# The host (gateway) runs mitmproxy, which is the only way out.
VMNET_HOST_IP=192.168.100.1
VMNET_GUEST_START=192.168.100.2
VMNET_GUEST_END=192.168.100.254
VMNET_MASK=255.255.255.0
PROXY_PORT=8090

# socket_vmnet provides vmnet.framework access to unprivileged QEMU.
# The daemon (start-vmnet.sh) creates a Unix socket; socket_vmnet_client
# passes an fd from that socket into QEMU as its network backend.
BREW_PREFIX="$(brew --prefix 2>/dev/null)"
SOCKET_VMNET_CLIENT="$BREW_PREFIX/opt/socket_vmnet/bin/socket_vmnet_client"
SOCKET_PATH="$BREW_PREFIX/var/run/socket_vmnet.host"

# --- Architecture detection ---
# Pick the right QEMU binary, machine type, and cloud image.
# We use the "generic" (not "genericcloud") image because the generic
# kernel includes 9p filesystem modules needed for the shared directory.
# aarch64 requires UEFI firmware; x86_64 boots with SeaBIOS by default.
case "$(uname -m)" in
  arm64)
    QEMU_BIN=qemu-system-aarch64
    MACHINE_ARGS=(-machine virt,accel=hvf -cpu host)
    IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-generic-arm64-daily.qcow2"
    NEEDS_EFI=1
    ;;
  x86_64)
    QEMU_BIN=qemu-system-x86_64
    MACHINE_ARGS=(-machine q35,accel=hvf -cpu host)
    IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-generic-amd64-daily.qcow2"
    NEEDS_EFI=0
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

# --- start ---

do_start() {
  # Ensure the vmnet daemon is running (started separately via start-vmnet.sh).
  if [[ ! -S "$SOCKET_PATH" ]]; then
    echo "socket_vmnet not running. Run: sudo ./start-vmnet.sh" >&2
    exit 1
  fi

  mkdir -p "$STATE_DIR" "$SHARED_DIR"

  # Generate a dedicated SSH keypair on first run. This key is injected
  # into the VM via cloud-init and used by ssh.sh. It survives resets
  # (only the disk and seed ISO are destroyed, not the key or base image).
  if [[ ! -f "$STATE_DIR/id_ed25519" ]]; then
    ssh-keygen -t ed25519 -f "$STATE_DIR/id_ed25519" -N "" -C "vm-access" -q
  fi

  # Download the Debian cloud image (kept across resets).
  local base_image="$STATE_DIR/base.qcow2"
  if [[ ! -f "$base_image" ]]; then
    echo "Downloading Debian testing cloud image..."
    curl -L -o "$base_image" "$IMAGE_URL"
  fi

  # Create a copy-on-write overlay so the base image stays clean.
  # Resets just delete this file; a fresh overlay is created on next start.
  local disk="$STATE_DIR/disk.qcow2"
  if [[ ! -f "$disk" ]]; then
    echo "Creating VM disk..."
    (cd "$STATE_DIR" && qemu-img create -f qcow2 -b base.qcow2 -F qcow2 disk.qcow2 20G)
  fi

  # Build the cloud-init "nocloud" seed ISO. Cloud-init reads user-data,
  # meta-data, and network-config from a volume labeled "cidata".
  # The SSH public key is templated in at build time (replacing __SSH_PUB_KEY__).
  local seed="$STATE_DIR/seed.iso"
  if [[ ! -f "$seed" ]]; then
    echo "Building cloud-init seed ISO..."
    local ci_tmp
    ci_tmp="$(mktemp -d)"

    local ssh_pub
    ssh_pub="$(cat "$STATE_DIR/id_ed25519.pub")"

    for f in "$CLOUD_INIT_DIR"/*; do
      sed "s|__SSH_PUB_KEY__|$ssh_pub|g" "$f" > "$ci_tmp/$(basename "$f")"
    done

    if command -v mkisofs &>/dev/null; then
      mkisofs -output "$seed" -volid cidata -joliet -rock "$ci_tmp"
    elif command -v xorriso &>/dev/null; then
      xorriso -as mkisofs -output "$seed" -volid cidata -joliet -rock "$ci_tmp"
    else
      hdiutil makehybrid -iso -joliet -default-volume-name cidata -o "$seed" "$ci_tmp"
      [[ -f "${seed}.cdr" ]] && mv "${seed}.cdr" "$seed"
    fi

    rm -rf "$ci_tmp"
  fi

  # Assemble the QEMU command line.
  local -a qemu_args=(
    "${MACHINE_ARGS[@]}"
    -m 2G -smp 1
    -nographic                                          # serial console only
    -drive "file=$disk,if=virtio"                       # root disk (CoW overlay)
    -drive "file=$seed,if=virtio,media=cdrom"           # cloud-init seed ISO
    -device virtio-net-pci,netdev=net0                  # virtual NIC
    -netdev socket,id=net0,fd=3                         # fd=3 is passed by socket_vmnet_client
    # 9p shared directory: the host's shared/ folder is exposed as the
    # "shared" mount tag. security_model=none means no permission mapping
    # at the QEMU level; a bindfs mount inside the guest handles UID translation.
    -virtfs "local,path=${SHARED_DIR},mount_tag=shared,security_model=none,id=shared"
  )

  # aarch64 has no default firmware — we must provide UEFI via pflash.
  # The code (read-only) comes from Homebrew's QEMU package; the vars
  # file is per-VM and stores UEFI settings like boot order.
  if [[ "$NEEDS_EFI" -eq 1 ]]; then
    local efi_code="$BREW_PREFIX/share/qemu/edk2-aarch64-code.fd"
    if [[ ! -f "$efi_code" ]]; then
      echo "UEFI firmware not found at $efi_code" >&2
      echo "Install QEMU via: brew install qemu" >&2
      exit 1
    fi

    local efi_vars="$STATE_DIR/efi-vars.fd"
    if [[ ! -f "$efi_vars" ]]; then
      local efi_vars_template="$BREW_PREFIX/share/qemu/edk2-arm-vars.fd"
      if [[ -f "$efi_vars_template" ]]; then
        cp "$efi_vars_template" "$efi_vars"
      else
        dd if=/dev/zero of="$efi_vars" bs=1m count=64 2>/dev/null
      fi
    fi

    qemu_args=(
      -drive "if=pflash,format=raw,readonly=on,file=$efi_code"
      -drive "if=pflash,format=raw,file=$efi_vars"
      "${qemu_args[@]}"
    )
  fi

  echo "Starting VM (host-only network via socket_vmnet)..."
  echo "  SSH:   ./ssh.sh"
  echo "  Proxy: http://$VMNET_HOST_IP:$PROXY_PORT (from guest)"
  echo "  Quit:  Ctrl-A X"
  echo ""

  # socket_vmnet_client connects to the daemon's Unix socket, receives a
  # vmnet file descriptor, and passes it as fd 3 to the child process (QEMU).
  exec "$SOCKET_VMNET_CLIENT" "$SOCKET_PATH" \
    "$QEMU_BIN" "${qemu_args[@]}"
}

# --- reset ---
# Destroys the VM disk, seed ISO, and EFI vars so the next start rebuilds
# from scratch. The base image and SSH keypair are preserved to avoid a
# large re-download and to keep the same key across rebuilds.

do_reset() {
  rm -f "$STATE_DIR/disk.qcow2" "$STATE_DIR/seed.iso" "$STATE_DIR/efi-vars.fd"
  echo "VM state removed. Base image and SSH key kept."
}

# --- Main ---

case "${1:-start}" in
  start) do_start ;;
  reset) do_reset ;;
  *)
    echo "Usage: $0 {start|reset}" >&2
    exit 1
    ;;
esac
