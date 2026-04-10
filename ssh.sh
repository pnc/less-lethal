#!/usr/bin/env bash
# SSH into the VM using the auto-generated keypair.
# Host key checking is disabled because the key changes on every reset.
# Pass arguments through to ssh (e.g. ./ssh.sh ls /tmp).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec ssh -i "$SCRIPT_DIR/.vm/id_ed25519" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -q vm@192.168.100.2 "$@"
