# Transparent client migration on DC connection death

Telegram periodically closes the TCP connection to the proxy ("DC connection
rotation", typically every 30–70 s). Instead of dropping all clients
multiplexed on that connection, the proxy remaps each idle client to a
surviving (or freshly-started) DC connection transparently.

**Key actors:**
- `mtp_down_conn (old)` — the dying downstream connection process
- `mtp_dc_pool` — pool managing all downstream connections for one DC
- `mtp_handler` — one process per connected Telegram client
- `mtp_down_conn (new)` — replacement downstream spawned by the pool

```mermaid
sequenceDiagram
    participant TG as Telegram
    participant OldDown as mtp_down_conn (old)
    participant Pool as mtp_dc_pool
    participant Handler as mtp_handler
    participant NewDown as mtp_down_conn (new)

    TG->>OldDown: TCP close

    OldDown->>Pool: downstream_closing(self()) [sync]
    Pool-->>Pool: remove OldDown from ds_store + monitors
    Pool-->>NewDown: spawn & connect (maybe_restart_connection)
    Pool-->>OldDown: ok

    OldDown->>Handler: migrate(OldDown) [cast, to all known upstreams]

    Note over OldDown: drain_mailbox(5000)

    alt upstream_new in mailbox
        Note over Pool,OldDown: Race: pool processed a {get} call just before<br/>downstream_closing — upstream_new cast already queued
        Pool-->>OldDown: upstream_new(Handler2, Opts) [cast, queued]
        OldDown->>Handler2: migrate(OldDown) [cast, immediately]
    end

    alt Handler was blocked in down_send
        Handler-->>OldDown: {send, Data} [call, in mailbox]
        OldDown-->>Handler: {error, migrating}
        Note over Handler: metric[mid_send] → stop<br/>(client reconnects and resends)
    else Handler was idle
        Handler->>Pool: migrate(OldDown, self(), Opts) [sync]
        Pool-->>Pool: remove Handler from upstreams map
        Pool->>NewDown: upstream_new(Handler, Opts) [cast]
        Pool-->>Handler: NewDown pid
        Note over Handler: down = NewDown<br/>metric[ok]
    end

    Note over OldDown: stop {shutdown, downstream_migrated}
```
