# CLAUDE.md

## Development workflow

Always run the test suite before committing:

```bash
uv run pytest tests/test_e2e.py -v -s
```

The test boots the VM end-to-end (takes ~90s without KVM) and verifies `curl https://pypi.org` works through mitmproxy. Do not commit if this fails.

The full suite including the network isolation tests can take 5+ minutes under TCG emulation. Launch the test with `Bash` using `run_in_background: true`, then immediately attach a `Monitor` to tail the output file with a progress filter. This keeps the conversation unblocked while streaming results:

```
# 1. Launch (non-blocking)
Bash(command="...", run_in_background=true)

# 2. Stream progress
Monitor(command="tail -f <output_file> | grep --line-buffered -E '(PASSED|FAILED|ERROR|test_)'")
```

## Tooling policy

Use **uv** for all Python tasks (running scripts, managing dependencies, virtual environments). Install uv from its official binary release — never via pip, conda, or similar tools. Do not use pip, conda, pipx, or any other Python package manager.

## What this project is

A sandboxed Debian VM on macOS and Linux with no direct internet access. All network traffic is forced through a host-side mitmproxy instance, which intercepts TLS for full visibility. The VM is provisioned declaratively via cloud-init and launched with a single command — no sudo required.

## Architecture decisions and why

**QEMU slirp with `restrict=on` + `guestfwd`** provides network isolation without any host-side network devices or firewall rules.  Previous attempts that were eliminated:

- **Vagrant** is effectively unmaintained.
- **Lima** hardcodes QEMU's `-netdev user` arguments and has no support for `restrict=on` or `guestfwd`. Network isolation is impossible without external tools.
- **QEMU's `guestfwd` with `cmd:` piping through `nc`** was initially abandoned as unreliable, but revisiting it with QEMU 10.x showed `cmd:nc` works correctly with `restrict=on`. Each guest TCP connection to the guestfwd IP spawns a fresh `nc` that connects to the host-side proxy.
- **socket_vmnet** (macOS) was the previous working solution. It worked well but required sudo to start a privileged daemon, plus pf firewall rules for port isolation — adding complexity and platform-specific code. slirp replaces all of this with zero-privilege operation.
- **TAP/bridge** (Linux) was the previous Linux networking solution. Like socket_vmnet, it required sudo for bridge creation and iptables rules. Replaced by slirp.

**Debian "generic" image, not "genericcloud"**: The genericcloud kernel strips out hardware drivers including 9p filesystem modules. The generic image uses the standard Debian kernel which includes them. This matters for the shared directory.

**DHCP via slirp**: QEMU's built-in slirp stack provides instant DHCP responses, so cloud-init's network stage completes quickly. With `restrict=on`, the DHCP response omits gateway and DNS — the guest can only reach endpoints explicitly configured via `hostfwd` (SSH) and `guestfwd` (proxy).

**bindfs for UID mapping**: The 9p shared directory shows files owned by the host UID inside the guest. A systemd service mounts the raw 9p at `/mnt/9p`, then uses `bindfs --force-user=vm --force-group=vm` to present all files as owned by the `vm` user.

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
  network-config   DHCP via slirp (netplan v2 format)
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

`vm.py start` starts mitmdump in the background (logging to `.vm/mitmdump.log`),
boots QEMU with slirp networking, waits for SSH, then drops you into an SSH
session. On session exit, both QEMU and mitmproxy are stopped. No sudo is
required. When stdout is not a TTY (e.g. test suite), QEMU runs in the
foreground with the serial console on stdout instead.
