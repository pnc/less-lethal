# Developing agent-vm

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
`/dev/kvm` available). They use `--subnet 192.168.101` to avoid colliding with
the default `192.168.100.0/24` subnet, which matters when the test host is
itself a VM on that subnet.
