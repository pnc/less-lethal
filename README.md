# Agent VM

A sandboxed Debian VM with no direct internet access. All traffic is forced through a host-side [mitmproxy](https://mitmproxy.org/) that enforces an allowlist, giving full visibility and control over what the guest can reach. Runs on macOS (socket\_vmnet + HVF) and Linux (TAP/bridge + TCG/KVM).

## Why: the "lethal trifecta"

Simon Willison describes a ["lethal trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) when AI agents combine access to private data, exposure to untrusted content, and the ability to communicate externally — creating a path from prompt injection to data exfiltration. More broadly, an agent with these three capabilities is dangerous:

1. **Code execution** — present in this VM
2. **Autonomy** — present in this VM
3. Internet access — constrained by the allowlist proxy

This VM provides (1) and (2) but constrains (3): all traffic passes through a human-curated allowlist, so the operator approves every new endpoint.

## Quick start

**macOS prerequisites:** `brew install qemu socket_vmnet mitmproxy`

**Linux prerequisites:** `apt install qemu-system-arm qemu-efi-aarch64 genisoimage iptables` (or x86 equivalents). Requires sudo for TAP/bridge setup.

```bash
./vm.py start          # start everything + drop into SSH session
./vm.py ssh            # open another SSH session (from a second terminal)
./vm.py reset          # destroy ephemeral state, keep base image
```

`vm.py start` launches socket\_vmnet (macOS), mitmproxy, and QEMU, waits for the VM to boot, then drops you into an SSH session. Exiting the session stops everything. Serial console output is logged to `.vm/console.log`.

Files in `shared/` on the host appear at `~/shared` inside the guest.

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
