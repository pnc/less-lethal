# Developing agent-vm

## Test prerequisites

These are for running the e2e test suite, which boots a real QEMU VM.
They are **not** needed to use the VM — only to develop and test the
VM project itself. (This distinction matters when hacking on agent-vm
from inside the VM: you need to install these prerequisites in the
guest to run the tests there.)

**macOS:**

```bash
brew install qemu mitmproxy
```

**Linux:**

```bash
# QEMU emulator and firmware (ARM64 — use qemu-system-x86 on amd64 hosts)
sudo apt install qemu-system-arm qemu-efi-aarch64

# ISO tooling for building cloud-init seed images
sudo apt install genisoimage    # provides mkisofs

# netcat for slirp guestfwd proxy forwarding
sudo apt install netcat-openbsd

# uv — download the binary from GitHub (pick your arch)
curl -fL https://github.com/astral-sh/uv/releases/latest/download/uv-aarch64-unknown-linux-gnu.tar.gz \
  | tar xz -C ~/.local/bin --strip-components=1
# For x86_64, use uv-x86_64-unknown-linux-gnu.tar.gz instead.
# Make sure ~/.local/bin is on your PATH.
```

No sudo is required to run the VM or the test suite.

**Running tests inside a VM (nested):** If you are running the e2e
tests from inside the VM itself, uncomment the Debian cloud image
offloader rules in `allowlist.txt` — the image download redirects to
hosts outside `*.debian.org` that are blocked by default.

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
