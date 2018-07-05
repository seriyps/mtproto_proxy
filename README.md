Erlang mtproto proxy
====================

This part of code was extracted from [@socksy_bot](https://t.me/socksy_bot).

Features
--------

* Promoted channels! See `mtproto_proxy_app.src` `tag` option.
* "secure" randomized-packet-size protocol (34-symbol secrets starting with 'dd')
  to prevent detection by DPI
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

You need Erlang version 20 or higher! If your version is older, please, check
[Erlang solutions esl-erlang package](https://www.erlang-solutions.com/resources/download.html)
or use [kerl](https://github.com/kerl/kerl).

Get the code:

```
git clone https://github.com/seriyps/mtproto_proxy.git
cd mtproto_proxy/
```

Update settings (see [Settings](#settings)).

Compile:

```
./rebar3 release
```

Make sure your limit of open files is high enough! Check `ulimit -n`.
You may need to tweak your `/etc/security/limits.conf` or systemd `LimitNOFILE`
to be able to handle more than ~500 clients.

Start with interactive console (recommended for testing)

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy console
```

Or start in foreground (recommended for systemd service)

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy foreground
```

Or start in background (to run as a service without supervision)

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy start
```

Stop proxy started in background

```
./_build/default/rel/mtp_proxy/bin/mtp_proxy stop
```

Logs can be found at

```
./_build/default/rel/mtp_proxy/log/
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
