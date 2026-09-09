# mcp-iap

[![CI](https://github.com/vpetersson/mcp-iap/actions/workflows/ci.yml/badge.svg)](https://github.com/vpetersson/mcp-iap/actions/workflows/ci.yml)

An identity-aware proxy for LLM agents.

**Give an agent access to an API or an MCP server without ever giving it the credential.**
Everything else here — the ACL, the interactive prompt, the tamper-evident audit
log — exists to make that grant narrow, observable and revocable.

```
  agent ──IAP token──▶  mcp-iap  ──real credential──▶  api.anthropic.com
                          │                             api.github.com
                          │                             an MCP server
                          ├─ who is this?      (agent token → identity)
                          ├─ may it do this?   (ACL: allow / deny / ask)
                          ├─ ask a human       (TUI, Little Snitch style)
                          └─ write it down     (hash-chained JSONL)
```

The agent holds a token minted by the proxy. It is not an API key, it buys
nothing anywhere else, and revoking it rotates nothing. The real credential is
resolved from 1Password (or the environment, or a file) inside the proxy and
attached on the way out, after the policy has already said yes.

## Quickstart

```bash
cargo build --release

# 1. Mint a token for the agent and paste the printed block into your policy file.
./target/release/mcp-iap gen-token claude-code

cp iap.example.toml iap.toml && $EDITOR iap.toml

# 2. Check the policy and prove every credential reference resolves.
./target/release/mcp-iap check --config iap.toml

# 3. Run it, with the approval console.
./target/release/mcp-iap run --config iap.toml --tui
```

Point the agent at the proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/anthropic
export ANTHROPIC_AUTH_TOKEN=iap_...        # the token from step 1, not your API key
```

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ mcp-iap   proxy 127.0.0.1:8080    1 waiting    1 agents · 1 upstreams · 0 mcp · 1 rules · default deny      │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ waiting for you ───────────────────────────────┐┌ request ─────────────────────────────────────────────────┐
│▶    4s Claude Code github POST /repos/acme/api/││   agent  Claude Code (claude-code)                       │
│                                                ││    kind  http                                            │
│                                                ││  target  github                                          │
│                                                ││  method  POST                                            │
│                                                ││    path  /repos/acme/api/issues                          │
│                                                ││ waiting  4s                                              │
│                                                ││                                                          │
│                                                ││The credential is never shown to the agent — allowing only│
│                                                ││lets this one call through.                               │
└────────────────────────────────────────────────┘└──────────────────────────────────────────────────────────┘
┌ audit log (live) ──────────────────────────────────────────────────────────────────────────────────────────┐
│06:04:13 allow                  claude-code github GET /repos/acme/api → 200  [github-reads]                │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ↑/↓  move   a  allow   A  allow for session   d  deny   D  deny for session   f  forget   q  quit           │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## What happens to a request

1. **Identify.** The agent sends `Authorization: Bearer <iap-token>` (or
   `X-IAP-Token`). Only the token's sha256 is stored in the policy file.
2. **Route.** `POST /anthropic/v1/messages` selects the `anthropic` upstream and
   forwards `/v1/messages`. `X-IAP-Upstream: anthropic` does the same without a
   path prefix, for SDKs that will not take one.
3. **Decide.** The first matching ACL rule wins. Nothing matched means the
   default applies, and the default is `deny`.
4. **Ask, if the rule says so.** The request is parked and the operator answers
   it. A timeout, or no one watching the queue, denies.
5. **Inject.** The agent's own token is stripped. The real credential is added.
6. **Record.** One JSON line: who, what, which rule decided, the status, how long
   it took. Then the response is streamed straight back — token-by-token
   responses stay token-by-token.

## The policy file

`iap.example.toml` is a commented walk-through. The shape:

```toml
[[agents]]
id = "claude-code"
name = "Claude Code"
token_sha256 = "…"                  # from `mcp-iap gen-token`
targets = ["anthropic", "github"]   # optional hard scope, checked before the ACL

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = { type = "header", header = "x-api-key", secret = "op://Private/Anthropic/credential" }

[[acl]]
name = "anthropic-inference"        # this name appears in every audit record
agent = "claude-code"
kind = "http"                       # http | mcp | *
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"                    # allow | deny | ask

[acl_default]
action = "deny"
```

`*` and `**` are globs. In `paths`, `*` stops at `/` and `**` crosses it, so
`/repos/*` does not silently grant everything under `/repos`. Unknown keys are a
hard error — a typo must never quietly widen access.

### Credential schemes

| `type` | Effect |
| --- | --- |
| `bearer` | `Authorization: Bearer <secret>` |
| `header` | any header, with an optional `prefix` |
| `basic` | `Authorization: Basic base64(username:secret)` |
| `query` | appends `?param=<secret>` |
| `oauth2_client_credentials` | fetches and caches an access token, refreshed a minute before expiry |
| `none` | pass through |

### Where secrets come from

`op://vault/item/field` (1Password CLI), `env:NAME`, `file:/path`, and
`literal:…` for demos — which the loader warns about. Everything is resolved at
startup, so a locked vault fails the process rather than the tenth request.
A bare value that is not one of these forms is rejected, and the error never
echoes what you pasted.

## MCP

MCP over HTTP is just HTTP — front it as an upstream. For stdio servers, the
agent runs the bridge as its MCP server:

```json
{ "mcpServers": { "github": {
    "command": "mcp-iap",
    "args": ["mcp", "--config", "/etc/mcp-iap/iap.toml", "--server", "github-mcp"],
    "env": { "IAP_TOKEN": "iap_..." } } } }
```

The bridge spawns the real server with the credential in *its* environment,
relays JSON-RPC, and asks the running daemon to authorize every message.
Policy and audit stay in one process, so `tools/call` shows up in the same log
and the same approval queue as an HTTP call:

```toml
[[acl]]
kind = "mcp"
target = "github-mcp"
methods = ["tools/call"]
paths = ["get_*", "list_*", "search_*"]   # `paths` is the tool name here
action = "allow"
```

`resources/read` matches on the URI instead. A method that names nothing —
`tools/list`, `initialize` — only matches a rule that places no constraint on
`paths`. A denied call gets a JSON-RPC error (`-32001`); a denied notification is
dropped. A batch is all-or-nothing, so ids never desynchronise. If the daemon is
unreachable the bridge refuses to start, and if an authorization call fails the
call is denied.

## The audit log

One JSON object per line, hash-chained: each entry commits to the one before it.

```json
{"seq":1,"id":"…","ts":"2026-09-09T06:01:18.484Z","kind":"http","event":"request",
 "agent":"demo-agent","agent_name":"Demo Agent","target":"demo-api","method":"GET",
 "path":"/v1/models","decision":"allow","rule":"api-reads","status":200,
 "duration_ms":0,"request_bytes":0,"client":"127.0.0.1:41876",
 "prev_hash":"…","hash":"…"}
```

```bash
mcp-iap audit tail  audit/iap-audit.jsonl -n 20
mcp-iap audit verify audit/iap-audit.jsonl
# 9 entries verified — the hash chain is intact.
```

Editing or removing a line is detected by `verify`. The chain resumes across
restarts, so one file covers the life of the deployment.

Bodies are **not** logged by default (`audit.log_bodies`), nor are MCP `params`
(`audit.log_mcp_params`) — both carry prompts and customer data. Credential
headers are replaced with `***` before anything is written; the tests assert that
neither the upstream credential nor the agent token ever reaches the log.

## Control plane

`admin_listen` (loopback, bearer token written to `admin-token` beside the audit
log) exists for the console and the MCP bridge, and is useful directly:

```bash
TOKEN=$(cat audit/admin-token)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/status
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/pending
curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/decide \
     -d '{"verdict":"allow","remember":true}' -H 'content-type: application/json'
```

Polling `/pending` counts as watching the queue for 30 seconds, so `curl` alone
can answer an `ask` without the TUI. With nobody watching, `ask` denies
immediately rather than parking the request for the full timeout.

## Security model

What this gives you:

- The agent never holds the upstream credential, so a leaked agent context, a
  prompt injection, or an exfiltrated config leaks a token that only works
  against this proxy, only for the paths the ACL allows, and that you can revoke
  in one line without rotating anything real.
- Every call is attributable to an agent and to the rule that permitted it.
- The blast radius of a compromised agent is the ACL, not the API key's scope.

What it does not give you, and you should know before relying on it:

- **The stdio MCP bridge is not a process boundary.** The child holds the
  credential in its environment, and a same-user process can read that. It buys
  you policy and audit, not isolation. For a hard boundary, run the MCP server
  behind the daemon over HTTP, or in a container.
- **No TLS on the listener.** Bind loopback, or put it behind something that
  terminates TLS. The agent's token is a bearer token.
- **The ACL sees method, path and tool name, not intent.** It cannot tell a
  reasonable `POST /v1/messages` from an expensive one. Use `ask` where the
  distinction matters.
- **Response bodies are not inspected.** Nothing here stops an upstream from
  returning data the agent should not have.
- Audit hash-chaining detects tampering by anyone who cannot rewrite the whole
  file; it is not an append-only store. Ship the lines somewhere else for that.

## Not built yet

Rate limits and spend caps per agent; hot config reload; a decoupled TUI that
attaches to an already-running daemon over the control plane; SSE streaming for
the HTTP MCP transport (single JSON responses work, `data:` frames are parsed,
long-lived streams are not); mTLS agent identity; native 1Password Connect
(the CLI is shelled out to today).

## Development

```bash
cargo test        # 64 tests: unit + end-to-end through a real proxy
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The end-to-end suite starts a proxy in front of a mock upstream and asserts the
properties that matter: the upstream receives the real key, the agent's token
stops at the proxy, denied calls never reach the network, an `ask` releases only
when a human answers, and the resulting log verifies.

CI runs exactly the three commands above on Linux and macOS, plus `cargo audit`
over the dependency tree — a dependency with a known advisory fails the build.
Dependabot opens weekly grouped PRs for Cargo and for the actions themselves.
Windows is not covered: the credential file permissions and the MCP stdio bridge
are Unix-shaped today.

## License

MIT — see `LICENSE`.
