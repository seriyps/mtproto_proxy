Erlang mtproto proxy
====================

This part of code was extracted from [@socksy_bot](https://t.me/socksy_bot).

This implementation supports promoted channels! See `mtproto_proxy_app.src` `tag` option.

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
