Erlang mtproto proxy
====================

This part of code was extracted from [@socksy_bot](https://t.me/socksy_bot).

Features
--------

* Promoted channels! See `mtproto_proxy_app.src` `tag` option.
* Multiple ports with unique secret and promo tag for each port
* Automatic configuration reload (no need for restarts once per day)
* Very high performance - can handle tens of thousands connections!
* Small codebase compared to oficial one
* A lots of metrics could be exported (optional)

How to start
------------

Install deps (ubuntu 18.04)

```
sudo apt install erlang-nox erlang-dev build-essential
```

Compile:

```
./rebar3 release
```

Start with interactive console:

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy console
```

Start in foreground

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy foreground
```

Start in background

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy start
```

Stop proxy started in background

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy stop
```

Settings
--------

See `src/mtproto_proxy.app.src`.

Secret key will be printed on start.


Helpers
-------

Number of connections in background mode

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy eval 'lists:sum([proplists:get_value(all_connections, L) || {_, L} <- ranch:info()]).'
```
