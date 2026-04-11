# Agent VM

A sandboxed Debian VM with no direct internet access. All traffic is forced through a host-side [mitmproxy](https://mitmproxy.org/) that enforces an allowlist, giving full visibility and control over what the guest can reach. Runs on macOS (Hypervisor.framework) and Linux (KVM or software emulation). No sudo required.

## Why: the "lethal trifecta"

Simon Willison describes a ["lethal trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) when AI agents combine access to private data, exposure to untrusted content, and the ability to communicate externally — creating a path from prompt injection to data exfiltration. More broadly, an agent with these three capabilities is dangerous:

1. **Code execution** — present in this VM
2. **Autonomy** — present in this VM
3. Internet access — constrained by the allowlist proxy

This VM provides (1) and (2) but constrains (3): all traffic passes through a human-curated allowlist, so the operator approves every new endpoint.

### Why a VM instead of Docker?

Docker containers share the host kernel and were not designed as a security boundary — container escapes are a [well-known attack class](https://nvd.nist.gov/vuln/detail/CVE-2019-5736). A real VM provides hardware-level isolation via QEMU. It also means the agent can work on projects that themselves use Docker, without the complexity of Docker-in-Docker.

## Quick start

Install the prerequisites:

```bash
# macOS
brew install qemu mitmproxy uv

# Linux (ARM64 — use qemu-system-x86 on amd64 hosts)
sudo apt install qemu-system-arm qemu-efi-aarch64 genisoimage netcat-openbsd mitmproxy

# uv — download the binary from GitHub (pick your arch)
curl -fL https://github.com/astral-sh/uv/releases/latest/download/uv-aarch64-unknown-linux-gnu.tar.gz \
  | tar xz -C ~/.local/bin --strip-components=1
# For x86_64, use uv-x86_64-unknown-linux-gnu.tar.gz instead.
# Make sure ~/.local/bin is on your PATH.
```

Then launch the VM:

```bash
./vm.py                # boots the VM and drops you into an SSH session
```

The first run downloads a Debian cloud image (~700 MB) and provisions the VM with cloud-init. Subsequent starts reuse the cached image and take about a minute. Once you're in, run `claude` to start a Claude Code session.

Exit the SSH session to stop the VM. Other useful commands:

```bash
./vm.py ssh            # open another SSH session (from a second terminal)
./vm.py reset          # destroy ephemeral state, keep base image
```

No sudo is required — network isolation uses QEMU's built-in slirp stack with `restrict=on`. Serial console output is logged to `.vm/console.log`. Files in `shared/` on the host appear at `~/shared` inside the guest.

## Network filter

All outbound HTTP/HTTPS traffic passes through the proxy. Requests that don't match the allowlist are rejected with **HTTP 418** — a deliberately unusual status code so proxy blocks are never confused with real server errors.

### Two layers

1. **Trusted domains** (in `filter.py`): system infrastructure that the VM needs to function — Debian/Ubuntu repos, PyPI, and the mitmproxy CA endpoint. All methods and paths are allowed.

2. **User rules** (in `allowlist.txt`): per-method, per-URL patterns you add for your workload. Each rule is one line:

```
METHOD https://hostname/path/pattern
```

Wildcards (`*`) are allowed in the path but **not** in the hostname. The proxy reloads `allowlist.txt` on every request, so changes take effect immediately.

### Writing safe rules

- **Be specific.** `POST https://api.example.com/v1/messages` is better than `POST https://api.example.com/*`.
- **Scope wildcards to a prefix.** If the API uses `/v1/`, write `GET https://api.example.com/v1/*` — not `/*`.
- **Justify every wildcard.** Ask: can I enumerate the paths instead? Only use `*` when path segments genuinely vary (per-request IDs, pagination tokens, etc.).
- **Separate methods.** GET and POST are different rules. Don't grant POST when you only need GET. However, remember that exfiltration can occur using GET (such as using query parameters), so GET isn't always safe. (The best thing to do is to assume compromise by default—credentials and keys you give the VM should be short-lived, two hours or less.)

### Monitoring

Proxy traffic is logged to `.vm/mitmdump.log` and blocked requests are appended to `.vm/blocked.jsonl`:

```bash
tail -f .vm/mitmdump.log          # all proxy traffic
cat .vm/blocked.jsonl | jq .      # blocked requests
```

## Credentials and the shared directory

The `shared/` directory is mounted read-write inside the guest. Be deliberate about what you place there.

- **API keys:** Only add keys the agent actually needs. Prefer scoped, short-lived tokens over long-lived admin keys. Revoke them when the session is over.
- **Git credentials: do not provide them to the VM.** The agent can commit inside the VM, but push/pull operations should be performed on the host in the `shared/` directory. This keeps git credentials (SSH keys, tokens) out of the sandbox entirely.
- **Secrets files:** Never place `.env` files, service account JSON, or other broad credential bundles in `shared/` unless you have verified every key in them is safe to expose to the agent.
- **Cloning repos:** When giving the agent a repo to work on, `git clone` it fresh into `shared/` rather than copying or moving an existing checkout. Copied directories carry gitignored files (`.env`, credentials, local config) that a clone won't have.

## Development

See [HACKING.md](HACKING.md) for test suite instructions and development notes.
