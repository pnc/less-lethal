# Developing agent-vm

## macOS test prerequisites

```bash
brew install qemu socket_vmnet
```

Start socket_vmnet for the test subnet in a separate terminal (persists until
you stop it):

```bash
sudo $(brew --prefix)/opt/socket_vmnet/bin/socket_vmnet \
    --vmnet-mode=host \
    --vmnet-gateway=192.168.101.1 \
    --vmnet-dhcp-end=192.168.101.254 \
    --vmnet-mask=255.255.255.0 \
    $(brew --prefix)/var/run/socket_vmnet.192.168.101
```

If socket_vmnet isn't running, all tests skip automatically with the command
to start it.

## Linux test prerequisites

Install the following packages before running the test suite:

```bash
# QEMU emulator and firmware (ARM64 — use qemu-system-x86 on amd64 hosts)
sudo apt install qemu-system-arm qemu-efi-aarch64

# ISO tooling for building cloud-init seed images
sudo apt install genisoimage    # provides mkisofs

# Host-side firewall for VM network isolation
sudo apt install iptables

# uv (Python script runner / package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

The test suite needs **passwordless sudo** for creating the TAP/bridge network
devices and iptables rules that enforce host-side isolation.

## Running the tests

```bash
uv run pytest tests/test_e2e.py -v -s
```

The tests boot a real VM under TCG emulation (~90s without KVM, faster with
`/dev/kvm` available). They use `--subnet 192.168.101` and `--proxy-port 8091`
to avoid colliding with a running default VM.

The test suite never prompts for sudo. Four of the five tests require no
privileges at all. The port-isolation test (`test_host_exposed_ports`) needs
sudo to load pf/iptables firewall rules; it checks for cached credentials
via `sudo -n` and skips cleanly if they aren't available. To include it:

```bash
sudo -v                                  # cache credentials
uv run pytest tests/test_e2e.py -v -s    # run within the sudo timeout
```

There is also a fast unit test suite for the filter logic (no VM required):

```bash
uv run pytest tests/test_filter.py -v
```

## Tooling

Use **uv** for all Python tasks. Do not use pip, conda, or pipx.
