# CLAUDE.md

## Development workflow

Always run the test suite before committing:

```bash
uv run pytest tests/test_e2e.py -v -s
```

The test boots the VM end-to-end (takes ~90s without KVM) and verifies `curl https://pypi.org` works through mitmproxy. Do not commit if this fails.

The full suite including the nmap port-isolation test can take 10+ minutes under TCG emulation. Run the tests in the background and use the **Monitor** tool to stream results rather than blocking on a single long-running Bash call.

## Tooling policy

Use **uv** for all Python tasks (running scripts, managing dependencies, virtual environments). Install uv from its official binary release — never via pip, conda, or similar tools. Do not use pip, conda, pipx, or any other Python package manager.

## What this project is

A sandboxed Debian VM on macOS with no direct internet access. All network traffic is forced through a host-side mitmproxy instance, which intercepts TLS for full visibility. The VM is provisioned declaratively via cloud-init and launched with a single shell script.

## Architecture decisions and why

**QEMU + socket_vmnet** was chosen after eliminating several alternatives:

- **Vagrant** is effectively unmaintained.
- **Lima** was the first replacement attempt. It's a nice Vagrant-like tool with YAML configs, but it hardcodes QEMU's `-netdev user` (slirp) arguments and has no support for `restrict=on`, `guestfwd`, or `vmnet-host`. Network isolation is impossible without `socket_vmnet`, and Lima's `socket_vmnet` integration requires sudoers.
- **QEMU's `restrict=on` + `guestfwd`** was the next attempt — isolate with slirp's restrict flag, then use `guestfwd` to pipe proxy traffic via `nc`. This was abandoned because `guestfwd` with `cmd:` is unreliable (spawns a new process per connection, buggy interaction with `restrict=on`).
- **QEMU's built-in `vmnet-host` backend** (`-netdev vmnet-host`) works perfectly but requires the `com.apple.vm.networking` entitlement. Ad-hoc codesigning doesn't work — the kernel rejects it (`ASP: Security policy would not allow process`). This is a restricted entitlement that requires Apple Developer ID signing. UTM gets away with it because it ships as a signed .app bundle.
- **socket_vmnet** is the working solution. It's a small privileged daemon that holds the vmnet entitlement and passes file descriptors to unprivileged QEMU over a Unix socket. It requires one `sudo` invocation to start the daemon, which we isolated into `start-vmnet.sh` for auditability.

**Debian "generic" image, not "genericcloud"**: The genericcloud kernel strips out hardware drivers including 9p filesystem modules. The generic image uses the standard Debian kernel which includes them. This matters for the shared directory.

**Static IP, not DHCP**: vmnet's built-in DHCP server works but takes ~34 seconds to respond, which causes cloud-init's network stage to time out. A static IP assignment via cloud-init's `network-config` is instant and deterministic. The network-config must match the interface by MAC address (`52:54:00:12:34:56`, QEMU's default), not by device name — the device name isn't known at cloud-init network config time.

**bindfs for UID mapping**: The 9p shared directory shows files owned by the host's macOS UID (e.g. 501) inside the guest, where the `vm` user is UID 1000. A systemd service mounts the raw 9p at `/mnt/9p`, then uses `bindfs` to create a UID-mapped view at `/home/vm/shared`. The service reads the actual UID/GID from the 9p mount at runtime with `stat`, so no build-time templating is needed.

**SSH key, not password**: `vm.py` generates a dedicated ed25519 keypair in `.vm/` on first run and injects the public key into cloud-init. Password auth is disabled. The key is ephemeral (nuked on reset along with the disk), which is fine — a new key and new seed.iso are generated together on the next start.

## cloud-init ordering pitfalls

- `write_files` runs in the init stage (before packages). Use it for apt proxy config.
- `bootcmd` runs in the init stage after networking. Used to fetch the mitmproxy CA cert via plain HTTP before apt needs it.
- `packages` runs in the config stage. By this point, apt proxy and CA cert are in place.
- `runcmd` runs in the final stage. Used for systemd unit enablement.
- The `mounts` module runs `mount -a` and fails hard if any mount fails, cascading into network stage failure. Avoid it; use systemd mount units or runcmd instead.
- `write_files` runs before user home directories are created. Don't write to `/home/vm/`; use `/etc/profile.d/` for shell config.
- Duplicate YAML keys (two `write_files:` sections) silently shadow each other.

## File layout

```
vm.py              Main entry point: start, ssh, reset subcommands (PEP 723 uv script)
filter.py          mitmproxy allowlist addon — edit to control VM network access
shared/            Shared with guest at ~/shared (only .gitkeep is tracked)
cloud-init/
  user-data        Cloud-init config (proxy, CA cert, packages, systemd units)
  meta-data        Instance identity
  network-config   Static IP assignment (netplan v2 format)
.images/           Persistent download cache (gitignored)
  base.qcow2       Downloaded Debian cloud image (survives reset)
.vm/               Ephemeral VM state (gitignored, nuked on reset)
  id_ed25519[.pub] SSH keypair (regenerated after reset)
  disk.qcow2       CoW overlay disk
  seed.iso         Cloud-init seed ISO
  efi-code.fd      Padded UEFI firmware (Linux only, derived from system package)
  efi-vars.fd      UEFI variable store
  mitmdump.log     mitmproxy traffic log
  console.log      QEMU serial console output
```

`vm.py start` handles the full startup sequence: it auto-launches socket_vmnet
(macOS) if the socket isn't present, starts mitmdump in the background (logging
to `.vm/mitmdump.log`), boots QEMU, waits for SSH, then drops you into an SSH
session. On session exit, all processes (QEMU, mitmproxy, socket_vmnet) are
stopped. When stdout is not a TTY (e.g. test suite), QEMU runs in the
foreground with the serial console on stdout instead.
