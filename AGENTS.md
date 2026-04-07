# AGENTS.md

## Project Overview

This is a high-performance **Telegram MTProto proxy** written in **Erlang/OTP**. It sits between Telegram
clients and Telegram servers, helping users bypass DPI-based censorship. It supports multiple anti-detection
protocols (fake-TLS, obfuscated/secure), connection multiplexing, replay attack protection, domain fronting,
and flexible connection policies.

## Repository Layout

```
src/              Erlang source files (OTP application)
test/             EUnit, Common Test, and PropEr test suites + benchmarks
config/           Example configs (sys.config.example, vm.args.example)
rebar.config      Build tool configuration and dependencies
Makefile          Build, test, install targets
start.sh          Foreground start script for development
Dockerfile        Docker image build
```

### Key source modules

| Module                                           | Role                                                  |
|--------------------------------------------------|-------------------------------------------------------|
| `mtp_handler`                                    | Accepts client TCP connections (Ranch listener)       |
| `mtp_obfuscated`                                 | Obfuscated MTProto protocol (client-side codec)       |
| `mtp_fake_tls`                                   | Fake-TLS protocol (mimics TLSv1.3 + HTTP/2)           |
| `mtp_secure`                                     | "Secure" randomized-packet-size protocol              |
| `mtp_dc_pool` / `mtp_down_conn`                  | Pooled/multiplexed connections to Telegram DCs        |
| `mtp_rpc`                                        | RPC framing protocol between proxy and Telegram       |
| `mtp_config`                                     | Periodically fetches Telegram DC configuration        |
| `mtp_policy` / `mtp_policy_table`                | Connection limit, blacklist, and whitelist rules      |
| `mtp_codec` / `mtp_aes_cbc`                      | Codec pipeline (MTProto framing + AES-CBC encryption) |
| `mtp_abridged` / `mtp_full` / `mtp_intermediate` | MTProto transport codec variants                      |
| `mtp_metric`                                     | Metrics/telemetry                                     |
| `mtp_session_storage`                            | Replay-attack protection (session deduplication)      |

### Process architecture

```
OTP supervision tree
────────────────────────────────────────────────────────────────────
mtproto_proxy_sup  (one_for_one)
 ├── mtp_config            (gen_server, singleton)
 ├── mtp_session_storage   (gen_server, singleton)
 ├── mtp_dc_pool_sup       (supervisor, simple_one_for_one)
 │    └── mtp_dc_pool      (gen_server, one per DC id, permanent)
 ├── mtp_down_conn_sup     (supervisor, simple_one_for_one)
 │    └── mtp_down_conn    (gen_server, one per Telegram TCP conn, temporary)
 └── Ranch listeners       (one per configured port: mtp_ipv4, mtp_ipv6, …)
      └── mtp_handler      (gen_server, one per client TCP conn, transient)


Data-plane message flow  (one client connection)
────────────────────────────────────────────────────────────────────

  Telegram client                                  Telegram server
       │                                                 │
       │  TCP (fake-TLS / obfuscated / secure)           │
       ▼                                                 ▼
 ┌─────────────┐   gen_server:call({send,Data})   ┌──────────────┐   raw TCP     ┌──────────────┐
 │ mtp_handler │ ──────────────────────────────►  │ mtp_down_conn│ ────────────► │  Telegram DC │
 │  (upstream) │                                  │ (downstream) │ ◄──────────── │ (middle srv) │
 │             │ ◄──────────────────────────────  │              │               └──────────────┘
 └──────┬──────┘    gen_server:cast({proxy_ans})  └──────────────┘
        │
        │  on first data: mtp_config:get_downstream_safe/2 → picks (pool, down_conn)
        │  on disconnect: cast({return, self()}) → releases slot
        ▼
 ┌─────────────┐
 │ mtp_dc_pool │  — spawns mtp_down_conn via mtp_down_conn_sup when pool is empty
 │  (per DC)   │
 └─────────────┘

> **Naming note:** the terms "upstream" and "downstream" in the current code are the
> opposite of what one might expect:
> `upstream` = the client-side connection (`mtp_handler`),
> `downstream` = the Telegram-server-side connection (`mtp_down_conn`).
> This will be renamed in a future refactor.


Key interactions
────────────────────────────────────────────────────────────────────
mtp_handler  → mtp_config       : get_downstream_safe/2 — resolves DC id to
                                  a (pool_pid, down_conn_pid) pair on first
                                  upstream data packet
mtp_handler  → mtp_down_conn    : send/2 (sync call) — forward client data
mtp_down_conn → mtp_handler     : cast {proxy_ans, …} — forward Telegram reply
mtp_down_conn → mtp_handler     : cast {close_ext, …} — Telegram closed stream
mtp_handler  → mtp_dc_pool      : return/2 (cast) — release slot on disconnect
mtp_dc_pool  → mtp_down_conn    : upstream_new/upstream_closed (cast)
mtp_dc_pool  → mtp_down_conn_sup: start_conn/2 — spawn new TCP conn to Telegram
mtp_down_conn → mtp_config      : get_netloc/1, get_secret/0 — read DC address
                                  and proxy secret for RPC handshake
mtp_config   → mtp_dc_pool_sup  : start_pool/1 — create pool when new DC seen
```

## Build

Requires Erlang/OTP 25+.

```bash
# Install dependencies and compile
./rebar3 compile

# Build a production release (requires config/prod-sys.config and config/prod-vm.args)
cp config/sys.config.example config/prod-sys.config
cp config/vm.args.example config/prod-vm.args
make
```

## Running Locally (dev)

```bash
./rebar3 shell   # starts an Erlang shell with the app loaded (easiest for dev/debugging)
```

`start.sh` is the Docker container entry-point; use `rebar3 shell` for local development instead.

## Testing

Run the full test suite (xref, eunit, common test, property-based tests, dialyzer, coverage):

```bash
make test
```

Individual steps:

```bash
./rebar3 xref              # cross-reference checks (undefined calls, unused locals)
./rebar3 eunit -c          # unit tests
./rebar3 ct -c             # common tests (integration, uses test/test-sys.config)
./rebar3 proper -c -n 50   # PropEr property-based tests (50 runs each)
./rebar3 dialyzer          # type analysis
./rebar3 cover -v          # coverage report
```

Always run `make test` before committing. Fix all xref warnings and dialyzer errors — they are treated as errors.

### Test organisation — where to add new tests

There are three kinds of tests, each with a clear home:

| Kind | Files | When to add |
|------|-------|-------------|
| **EUnit** (unit) | `src/*.erl`, `-ifdef(TEST)` blocks | Pure functions with no I/O: codec encode/decode round-trips, packet parsing helpers, crypto primitives |
| **PropEr** (property-based) | `test/prop_mtp_<module>.erl` | Codec/parser properties that should hold for *arbitrary* inputs — e.g. encode→decode identity, parser accepts all valid inputs, parser never crashes on random bytes |
| **Common Test** (integration) | `test/single_dc_SUITE.erl` | End-to-end behaviour involving a real listener + fake DC: protocol negotiation, policy enforcement, error handling visible at the TCP level (alerts sent, connections closed), domain fronting, replay protection |

**Rule of thumb:** if the behaviour is observable only over a TCP socket or requires a running application, it belongs in `single_dc_SUITE`. If it is a property of a pure function, add a PropEr property in the matching `prop_mtp_<module>.erl`. If it is a targeted unit case for a specific input, use EUnit.

**What changes need new tests:**

- **New codec or protocol module** → PropEr round-trip property in `prop_mtp_<module>.erl` + a CT `echo_*_case` in `single_dc_SUITE`
- **New protocol error path** → CT case that sends the triggering byte sequence over TCP and asserts the exact response (alert bytes, metric counter, connection close)
- **New policy or config option** → CT case that sets the env, exercises the path, resets env in `{post, Cfg}`
- **New parser clause or binary pattern** → PropEr property verifying the clause accepts all valid inputs and a targeted EUnit/PropEr case for boundary/malformed inputs
- **Security-critical paths** (replay detection, session storage, digest validation) → CT case; also consider PropEr for the pure crypto/comparison functions

**Naming conventions:**

- CT cases: `<description>_case/1` — auto-discovered by `all/0`
- PropEr properties: `prop_<description>/0` (or `/1` with a `doc` clause)
- Each CT case must implement `{pre, Cfg}` / `{post, Cfg}` / `Cfg when is_list(Cfg)` clauses and call `setup_single` / `stop_single` to avoid resource leaks

### Debugging CT failures

When `rebar3 ct` (or `make test`) reports failures, **do not rely on the terminal output** — it is truncated and shows only the last error. Instead, go straight to the HTML logs:

```
_build/test/logs/ct_run.<timestamp>/lib.mtproto_proxy.logs/run.<timestamp>/
```

Key files:
- `suite.log` — machine-readable summary; `=case` lines show test order, `=result failed` shows which failed
- `single_dc_suite.<test_name>.html` — full log for one test case (strip HTML tags to read: `sed 's/<[^>]*>//g'`)
- `suite.log.html` / `index.html` — human-readable in a browser

Workflow:
1. Run `make test` — note how many pass/fail
2. Check `suite.log` for `=case` ordering and `=result failed` to identify the failing test
3. Read that test's `.html` log for the full stacktrace and system reports
4. Fix, then re-run `make test`. If tests still fail spuriously, try `rm -rf _build/test && make test` to clear stale test artifacts (removing only `_build/test` is faster than a full clean build).

## Code Style

- Language: **Erlang**. Follow standard Erlang OTP conventions.
- Module names use `snake_case`; all prefixed with `mtp_` (or `mtproto_` for top-level app modules).
- Keep modules focused; each codec/protocol has its own module.
- Avoid adding dependencies — the dep list in `rebar.config` is intentionally minimal (Ranch + psq).
- Comments use `%%` (module-level) or `%` (inline). Don't over-comment obvious code.
- Codecs are implemented as layered pipelines via `mtp_codec` — follow this pattern for new protocols.

## Configuration

- Config lives in `config/prod-sys.config` (Erlang term format). Do **not** edit `src/mtproto_proxy.app.src` — it documents defaults only.
- All configuration options are documented in `src/mtproto_proxy.app.src`.
- Config can be reloaded without restart: `make update-sysconfig && systemctl reload mtproto-proxy`.

## Debugging

### Enabling debug logs for a single module at runtime

The primary log level is `info`. To see `?LOG_DEBUG` messages from one module without
flooding the log with debug output from all of OTP:

```erlang
% In the running Erlang shell (e.g. via: sudo /opt/personal_mtproxy/bin/mtproto_proxy remote_console)
logger:set_module_level(mtp_handler, debug).   % override primary gate for this module only
logger:set_handler_config(default, level, debug).  % let the file handler pass debug through
```

This works because `set_module_level` bypasses the primary level check *only* for the
named module — no other module's debug messages are affected. The handler level change
is required because the `default` file handler has its own `level => info` guard.

To revert:

```erlang
logger:unset_module_level(mtp_handler).
logger:set_handler_config(default, level, info).
```

Both settings are in-memory only and reset on restart.

## Security Considerations

- Do **not** commit real secrets, tags, or credentials into config files.
- Replay attack protection (`replay_check_session_storage`) must stay correct — the session storage logic is security-critical.
- The fake-TLS and obfuscated protocol implementations must stay byte-exact with the reference (`../MTProxy/`).
- When modifying crypto code (`mtp_aes_cbc`, `mtp_obfuscated`, `mtp_fake_tls`), verify against reference
  implementations: `../MTProxy/` (C), `../mtprotoproxy/` (Python), `../mtg/` (Go), `../telemt/` (Rust).

## Reference Implementations

*Feature comparison last verified: 2026-04-03. These projects evolve independently — re-check if significant time has passed.*

Reference implementations may or may not be checked out in sibling directories. If a directory is missing, clone it from GitHub:

| Implementation        | Sibling dir        | GitHub URL                                   |
|-----------------------|--------------------|----------------------------------------------|
| MTProxy (C, official) | `../MTProxy/`      | https://github.com/TelegramMessenger/MTProxy |
| mtprotoproxy (Python) | `../mtprotoproxy/` | https://github.com/alexbers/mtprotoproxy     |
| mtg (Go)              | `../mtg/`          | https://github.com/9seconds/mtg              |
| telemt (Rust)         | `../telemt/`       | https://github.com/telemt/telemt             |

There are two ways a proxy can connect to Telegram on the backend:

- **Middle proxy (RPC/multiplexed)**: the proxy speaks the Telegram internal RPC protocol to a Telegram
  "middle server". Many client connections are multiplexed over a small number of long-lived proxy→Telegram
  connections. Required for `ad_tag` (promoted channels) support.
- **Direct**: the proxy opens a new raw TCP connection to a Telegram DC per client connection.
  Simpler, but no `ad_tag` support and more connections to Telegram.

Client-side connection protocols (what the Telegram app uses to connect to the proxy):

| Implementation                   | Classic (no prefix) | Secure (`dd`)    | Fake-TLS (`ee`) | Domain fronting²                 | Backend mode                                        |
|----------------------------------|---------------------|------------------|-----------------|----------------------------------|-----------------------------------------------------|
| **mtproto_proxy** (this, Erlang) | ✅                  | ✅               | ✅              | ✅ (`domain_fronting` config)    | Middle proxy (multiplexed)                          |
| **MTProxy** (C, official)        | ✅                  | ✅               | ✅              | ✅ (`--domain` flag)             | Middle proxy (multiplexed)                          |
| **mtprotoproxy** (Python)        | ✅                  | ✅               | ✅              | ✅ (`TLS_DOMAIN` config)         | Both (`USE_MIDDLE_PROXY`, auto-enabled on `AD_TAG`) |
| **mtg** (Go)                     | ❌ dropped in v2    | ❌ dropped in v2 | ✅ only         | ✅ (`domain-fronting-port` flag) | Direct (per-client connection)                      |
| **telemt** (Rust)                | ✅                  | ✅               | ✅              | ✅ (TLS-fronting)                | Both (configurable: `use_middle_proxy`)             |

² **Domain fronting**: when a fake-TLS handshake fails (non-proxy client, e.g. a real browser or DPI probe),
  the proxy forwards the connection to the real host from the TLS SNI field, making the proxy indistinguishable
  from a normal HTTPS server. Without this, a failed handshake results in an abrupt close, which itself can
  be a detection signal.

Key takeaways:
- **mtproto_proxy** and **MTProxy** always use the middle proxy (multiplexed) backend.
- **mtprotoproxy** and **telemt** support both backend modes (middle proxy auto-enabled when an ad_tag is configured).
- **mtg** v2 intentionally dropped `dd`/classic support and ad_tag/middle-proxy in favour of simplicity;
  it only accepts `ee` (fake-TLS) secrets and always connects directly to Telegram DCs.

