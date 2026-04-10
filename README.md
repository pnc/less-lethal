# Agent VM

A sandboxed Debian VM on macOS with no internet access. All traffic is forced through a host-side mitmproxy, giving full visibility and control over what the guest can reach.

## Usage

Prerequisites: `brew install qemu socket_vmnet cdrtools`

```bash
# 1. Start the host-only network daemon (once, needs sudo)
sudo ./start-vmnet.sh

# 2. Start mitmproxy on port 8090 (in another terminal)
mitmproxy --listen-host 0.0.0.0 -p 8090

# 3. Boot the VM (first run downloads the image and provisions)
./vm.sh start

# 4. SSH in
./ssh.sh

# 5. Destroy and recreate (keeps base image and SSH key)
./vm.sh reset
./vm.sh start
```

Files in `shared/` on the host appear at `~/shared` inside the guest.
