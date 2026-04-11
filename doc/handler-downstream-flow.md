# Handler ↔ downstream lookup and handshake

Shows how `mtp_handler` locates an `mtp_down_conn` for a new client connection
and the steady-state data flow that follows.

**Key actors:**
- `mtp_handler` — one process per Telegram client TCP connection
- `mtp_dc_pool` — manages a pool of downstream connections for one DC
- `mtp_down_conn` — multiplexed TCP connection to a Telegram DC
- `Telegram DC` — the upstream Telegram data-centre server

In **split mode** (`node_role = front / back`) `mtp_handler` runs on the front
node and `mtp_dc_pool` / `mtp_down_conn` run on the back node.  The pool is
addressed as `{mtp_dc_pool_N, BackNode}` — Erlang distribution makes the
`gen_server:call` and all subsequent casts transparent across nodes.  Multiple
front nodes can share the same back node; the pools multiplex over all
upstream connections regardless of origin.

```mermaid
sequenceDiagram
    participant Client as Telegram client
    box LightBlue "FRONT node"
        participant Handler as mtp_handler
    end
    box LightGreen "BACK node"
        participant Pool as mtp_dc_pool
        participant Down as mtp_down_conn
    end
    participant TG as Telegram DC

    Client->>Handler: TCP connect + Hello bytes

    Note over Handler: decode protocol headers<br/>(fake-TLS / obfuscated / secure)<br/>stage: hello → tunnel

    Note over Handler: resolve pool:<br/>single-node: whereis(dc_to_pool_name(DcId))<br/>split mode:  erpc:call(BackNode, erlang, whereis, [PoolName])<br/>→ returns {PoolName, BackNode}<br/>(falls back to default DC from mtp_config if not found)
    Handler->>Pool: mtp_dc_pool:get(Pool, self(), Opts) [sync]
    Pool-->>Down: upstream_new(Handler, Opts) [cast]
    Pool->>Handler: Downstream pid

    Note over Handler: down = Downstream<br/>stage = tunnel

    loop steady-state data exchange
        Client->>Handler: TCP data
        Handler->>Down: mtp_down_conn:send(Down, Data) [sync]
        Down->>TG: TCP data (RPC-framed)
        TG->>Down: TCP data
        Down->>Handler: ok
        Down-->>Handler: {proxy_ans, Down, Data} [cast]
        Handler->>Client: TCP data
        Handler-->>Down: mtp_down_conn:ack(Down, Count, Size) [cast]
    end

    Client->>Handler: TCP close
    Handler-->>Pool: mtp_dc_pool:return(Pool, self()) [cast]
    Pool-->>Down: upstream_closed(Down, Handler) [cast]
```
