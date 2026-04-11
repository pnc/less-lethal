# Developing agent-vm

## macOS test prerequisites

```bash
brew install qemu mitmproxy
```

## Linux test prerequisites

Install the following packages before running the test suite:

```bash
# QEMU emulator and firmware (ARM64 — use qemu-system-x86 on amd64 hosts)
sudo apt install qemu-system-arm qemu-efi-aarch64

# ISO tooling for building cloud-init seed images
sudo apt install genisoimage    # provides mkisofs

# netcat for slirp guestfwd proxy forwarding
sudo apt install netcat-openbsd

# uv (Python script runner / package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

No sudo is required to run the VM or the test suite.

## Running the tests

```bash
uv run pytest tests/test_e2e.py -v -s
```

The tests boot a real VM under TCG emulation (~90s without KVM, faster with
`/dev/kvm` available). They use `--ssh-port 2223` and `--proxy-port 8091`
to avoid colliding with a running default VM.

### Running alongside a live VM

The test suite uses different ports (8091/2223) from the defaults
(8090/2222), but shares the same `.vm/` state directory by default —
running `reset` would destroy your running VM's disk overlay and SSH
key.  To run tests without disturbing a live session, point the tests
at an isolated state directory:

```bash
VM_STATE_DIR=/tmp/agent-vm-test uv run pytest tests/test_e2e.py -v -s
```

This keeps the test's disk, seed ISO, SSH key, and logs completely
separate from `.vm/`.  The base image in `.images/` is read-only and
shared safely.

### Unit tests (fast, no VM required)

```bash
uv run pytest tests/test_filter.py -v
```

## Tooling

Use **uv** for all Python tasks. Do not use pip, conda, or pipx.
