#!/usr/bin/env bash
#
# Starts the socket_vmnet daemon in host-only mode.
#
# This is the ONLY script that requires sudo. It is kept separate so the
# privileged operation can be audited independently of the rest of the setup.
#
# What it does:
#   1. Creates a host-only network via macOS vmnet.framework (no NAT, no internet)
#   2. Listens on a Unix socket that unprivileged QEMU instances connect to
#
# Why sudo is needed:
#   vmnet.framework requires the com.apple.vm.networking entitlement, which
#   is restricted to Apple-signed binaries. socket_vmnet is a small privileged
#   daemon that holds this entitlement and passes vmnet file descriptors to
#   unprivileged clients over a Unix socket.
#
set -euo pipefail

BREW_PREFIX="$(brew --prefix 2>/dev/null)"
SOCKET_VMNET="$BREW_PREFIX/opt/socket_vmnet/bin/socket_vmnet"
SOCKET_PATH="$BREW_PREFIX/var/run/socket_vmnet.host"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must be run with sudo." >&2
  exit 1
fi

if [[ ! -x "$SOCKET_VMNET" ]]; then
  echo "socket_vmnet not found. Install via: brew install socket_vmnet" >&2
  exit 1
fi

# Protect the socket: place it inside a directory owned exclusively by the
# invoking user with mode 700. This prevents other local users from connecting
# a VM to this network. The directory is created before the daemon starts,
# avoiding any TOCTOU race on the socket file itself.
OWNER="${SUDO_USER:?sudo required}"
SOCKET_DIR="$(dirname "$SOCKET_PATH")"
mkdir -p "$SOCKET_DIR"
chown "$OWNER" "$SOCKET_DIR"
chmod 700 "$SOCKET_DIR"

# Start the daemon in the foreground. It creates a host-only network on
# 192.168.100.0/24 — the host gets .1 (gateway), guests get .2+ via DHCP.
# "host-only" means the guest can reach the host but has no route to the
# internet. All outbound traffic must go through the proxy.
exec "$SOCKET_VMNET" \
  --vmnet-mode=host \
  --vmnet-gateway=192.168.100.1 \
  --vmnet-dhcp-end=192.168.100.254 \
  --vmnet-mask=255.255.255.0 \
  "$SOCKET_PATH"
