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

