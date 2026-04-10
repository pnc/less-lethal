# Agent VM

A sandboxed Debian VM with no direct internet access. All traffic is forced through a host-side mitmproxy, giving full visibility and control over what the guest can reach. Runs on macOS (socket_vmnet + HVF) and Linux (TAP/bridge + TCG/KVM).

## Usage

**macOS prerequisites:** `brew install qemu socket_vmnet cdrtools mitmproxy`

**Linux prerequisites:** `apt install qemu-system-arm qemu-efi-aarch64 genisoimage iptables` (or x86 equivalents). Requires sudo for TAP/bridge setup.

```bash
# Start mitmproxy and QEMU
./vm.py start

# SSH in (from another terminal)
./vm.py ssh

# Run a command in the VM without an interactive shell
./vm.py ssh -- ls /tmp

# Destroy ephemeral state and start fresh (base image is kept in .images/)
./vm.py reset && ./vm.py start

# Pass extra cloud-init config at boot (e.g. install additional packages)
./vm.py start --extra-user-data my-extra.yaml
```

Files in `shared/` on the host appear at `~/shared` inside the guest.

## Traffic control

Edit `filter.py` to control what the VM can reach. By default it blocks everything except common Debian/Python package repositories. The filter is a standard [mitmproxy addon](https://docs.mitmproxy.org/stable/addons-overview/) — mitmproxy reloads it on change.

Proxy traffic is logged to `.vm/mitmdump.log`:

```bash
tail -f .vm/mitmdump.log
```

## Running the test suite

The test suite boots the VM end-to-end and verifies networking works correctly through mitmproxy.

```bash
uv run pytest tests/test_e2e.py -v -s
```

This takes ~90 seconds without KVM (TCG software emulation). It:
- Resets VM state and boots a fresh VM
- Verifies cloud-init completes cleanly
- Verifies `curl http://pypi.org` and `curl https://pypi.org` work through the proxy
- Verifies blocked domains (e.g. `cisco.com`) return a 403 from `filter.py`

On macOS, the test skips automatically if `socket_vmnet` is not running.
