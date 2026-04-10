# Agent VM

A sandboxed Debian VM on macOS with no internet access. All traffic is forced through a host-side mitmproxy, giving full visibility and control over what the guest can reach.

## Usage

Prerequisites: `brew install qemu socket_vmnet cdrtools mitmproxy`

```bash
# Start everything: vmnet daemon (sudo prompt), mitmproxy, and QEMU
./vm.py start

# SSH in (from another terminal)
./vm.py ssh

# Run a command in the VM without an interactive shell
./vm.py ssh -- ls /tmp

# Destroy and recreate (keeps base image and SSH key)
./vm.py reset
./vm.py start
```

Files in `shared/` on the host appear at `~/shared` inside the guest.

## Traffic control

Edit `filter.py` to control what the VM can reach. By default it blocks everything except common Debian/Python package repositories. The filter is a standard [mitmproxy addon](https://docs.mitmproxy.org/stable/addons-overview/) — mitmproxy reloads it on change.

Proxy traffic is logged to `.vm/mitmdump.log`:

```bash
tail -f .vm/mitmdump.log
```
