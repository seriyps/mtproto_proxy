Erlang mtproto proxy
====================

This part of code was extracted from [@socksy_bot](https://t.me/socksy_bot).

Support: https://t.me/erlang_mtproxy .

‼️ DON'T USE TELEGRAM FOR SENSITIVE DATA AND POLITICAL ACTIVITY
---------------------------------------------------------------

Telegram is known to cooperate with governments, especially with russian.
Telegram is NOT neutral and NOT fully independent. Please only use Telegram
for non-sensitive messaging. For private messaging prefer Signal or Session.

Features
--------

* Promoted channels. See `tag` option.
* "secure" randomized-packet-size protocol (34-symbol secrets starting with 'dd')
  to prevent detection by DPI
* Fake-TLS protocol ('ee'/base64 secrets) - another protocol to prevent DPI detection
* Secure-only mode (only allow connections with 'dd' or fake-TLS).
  See `allowed_protocols` option.
* Connection limit policies - limit number of connections by IP / tls-domain / port; IP / tls-domain
  blacklists / whitelists
* Multiple ports with unique secret and promo tag for each port
* Very high performance - can handle tens of thousands connections! Scales to all CPU cores.
  1Gbps, 90k connections on 4-core/8Gb RAM cloud server.
* Supports multiplexing (Many connections Client -> Proxy are wrapped to small amount of
  connections Proxy -> Telegram Server) - lower pings and better OS network utilization
* Protection from [replay attacks](https://habr.com/ru/post/452144/) used to detect proxies in some countries
* Domain fronting for fake-TLS connections — when a browser or DPI probe connects with a
  wrong/absent secret, the connection is forwarded transparently to the real HTTPS server
  in the SNI field; the proxy is indistinguishable from a normal web server
* Automatic telegram configuration reload (no need for restarts once per day)
* IPv6 for client connections
* All configuration options can be updated without service restart
* Small codebase compared to official one, code is covered by automated tests
* A lots of metrics could be exported (optional)

How to install - one-line interactive installer
-----------------------------------------------

This command will run [interactive script](https://gist.github.com/seriyps/dc00ad91bfd8a2058f30845cd0daed83)
that will install and configure proxy for your Ubuntu / Debian / CentOS server.
It will ask if you want to change default port/secret/ad-tag/protocols:

```bash
curl -L -o mtp_install.sh https://git.io/fj5ru && bash mtp_install.sh
```

You can also just provide port/secret/ad-tag/protocols/tls-domain as command line arguments:

```bash
curl -L -o mtp_install.sh https://git.io/fj5ru && bash mtp_install.sh -p 443 -s d0d6e111bada5511fcce9584deadbeef -t dcbe8f1493fa4cd9ab300891c0b5b326 -a dd -a tls -d s3.amazonaws.com
```

It does the same as described in [How to start OS-install - detailed](#how-to-start-os-install---detailed), but
generates config-file for you automatically.

How to start - Docker
---------------------

### To run with default settings

```bash
docker run -d --network=host seriyps/mtproto-proxy
```

### To run on single port with custom port, secret and ad-tag

```bash
docker run -d --network=host seriyps/mtproto-proxy -p 443 -s d0d6e111bada5511fcce9584deadbeef -t dcbe8f1493fa4cd9ab300891c0b5b326
```

or via environment variables

```bash
docker run -d --network=host -e MTP_PORT=443 -e MTP_SECRET=d0d6e111bada5511fcce9584deadbeef -e MTP_TAG=dcbe8f1493fa4cd9ab300891c0b5b326 seriyps/mtproto-proxy
```

Where

* `-p 443` / `MTP_PORT=…` proxy port
* `-s d0d6e111bada5511fcce9584deadbeef` / `MTP_SECRET=…` proxy secret (don't append `dd`! it should be 32 chars long!)
* `-t dcbe8f1493fa4cd9ab300891c0b5b326` / `MTP_TAG=…` ad-tag that you get from [@MTProxybot](https://t.me/MTProxybot)
* `-a dd` / `MTP_DD_ONLY=t` only allow "secure" connections (dd-secrets)
* `-a tls` / `MTP_TLS_ONLY=t` only allow "fake-TLS" connections (base64 secrets)

It's ok to provide both `-a dd -a tls` to allow both protocols. If no `-a` option provided, all protocols will be allowed.

### To run with custom config-file

1. Get the code `git clone https://github.com/seriyps/mtproto_proxy.git && cd mtproto_proxy/`
2. Copy config templates `cp config/{vm.args.example,prod-vm.args}; cp config/{sys.config.example,prod-sys.config}`
3. Edit configs. See [Settings](#settings).
4. Build `docker build -t mtproto-proxy-erl .`
5. Start `docker run -d --network=host mtproto-proxy-erl`

Installation via docker can work well for small setups (10-20k connections), but
for more heavily-loaded setups it's recommended to install proxy directly into
your server's OS (see below).

How to start OS-install - quick
-----------------------------------

You need at least Erlang version 25! Recommended OS is Ubuntu 24.04.

```bash
sudo apt install erlang-nox erlang-dev build-essential
git clone https://github.com/seriyps/mtproto_proxy.git
cd mtproto_proxy/
cp config/vm.args.example config/prod-vm.args
cp config/sys.config.example config/prod-sys.config
# configure your port, secret, ad_tag. See [Settings](#settings) below.
nano config/prod-sys.config
make && sudo make install
sudo systemctl enable mtproto-proxy
sudo systemctl start mtproto-proxy
```

How to start OS-install - detailed
--------------------------------------


### Install deps

Ubuntu 18.xx / Ubuntu 19.xx / Debian 10:

```bash
sudo apt install erlang-nox erlang-dev  make sed diffutils tar
```

CentOS 7

```bash
# Enable "epel" and "Erlang solutions" repositories
sudo yum install wget \
             https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
             https://packages.erlang-solutions.com/erlang-solutions-1.0-1.noarch.rpm
# Install Erlang
sudo yum install erlang-compiler erlang-erts erlang-kernel erlang-stdlib erlang-syntax_tools \
     erlang-crypto erlang-inets erlang-sasl erlang-ssl
```

You need Erlang version 20 or higher! If your version is older, please, check
[Erlang solutions esl-erlang package](https://www.erlang-solutions.com/resources/download.html)
or use [kerl](https://github.com/kerl/kerl).

### Get the code:

```bash
git clone https://github.com/seriyps/mtproto_proxy.git
cd mtproto_proxy/
```

### Create config file

see [Settings](#settings).

### Build and install

```bash
make && sudo make install
```

This will:
* install proxy into `/opt/mtp_proxy`
* create a system user
* install systemd service
* create a directory for logs in `/var/log/mtproto-proxy`
* Configure ulimit of max open files and `CAP_NET_BIND_SERVICE` by systemd

### Try to start in foreground mode

This step is optional, but it can be useful to test if everything works as expected

```bash
./start.sh
```

try to run `./start.sh -h` to learn some useful options.

### Start in background and enable start on system start-up

```bash
sudo systemctl enable mtproto-proxy
sudo systemctl start mtproto-proxy
```

Done! Proxy is up and ready to serve now!

### Stop / uninstall

Stop:

```bash
sudo systemctl stop mtproto-proxy
```

Uninstall:

```bash
sudo systemctl stop mtproto-proxy
sudo systemctl disable mtproto-proxy
sudo make uninstall
```

Logs can be found at

```
/var/log/mtproto-proxy/application.log
```

Settings
--------

All available documented configuration options could be found
in [src/mtproto_proxy.app.src](src/mtproto_proxy.app.src). Do not edit this file!

To change configuration, edit `config/prod-sys.config`:

Comments in this file start with `%%`.
Default port is 1443 and default secret is `d0d6e111bada5511fcce9584deadbeef`.

Secret key and proxy URLs will be printed on start.


### Apply config changes without restart

It's possible to reload config file without service restart (but if you want to update
ad_tag on existing port, all clients of this port will be disconnected).

This method doesn't work for Docker!

To do that, make changes in `config/prod-sys.config` and run following command:

```bash
sudo make update-sysconfig && sudo systemctl reload mtproto-proxy
```

### Change default port / secret / ad tag

To change default settings, change `mtproto_proxy` section of `prod-sys.config` as:

```erlang
 {mtproto_proxy,
  %% see src/mtproto_proxy.app.src for examples.
  [
   {ports,
    [#{name => mtp_handler_1,
       listen_ip => "0.0.0.0",
       port => 1443,
       secret => <<"d0d6e111bada5511fcce9584deadbeef">>,
       tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}
    ]}
   ]},

 {kernel,
  [{logger_level, info},
   {logger,
    [{handler, default, logger_std_h,
      #{config => #{file => "/var/log/mtproto-proxy/application.log"}}}
    ]}]},
<...>
```
(so, remove `%%`s) and replace `port` / `secret` / `tag` with yours.

### Listen on multiple ports / IPs

You can start proxy on many IP addresses or ports with different secrets/ad tags.
To do so, just add more configs to `ports` section, separated by comma, eg:

```erlang
 {mtproto_proxy,
  %% see src/mtproto_proxy.app.src for examples.
  [
   {ports,
    [#{name => mtp_handler_1,
       listen_ip => "0.0.0.0",
       port => 1443,
       secret => <<"d0d6e111bada5511fcce9584deadbeef">>,
       tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>},
     #{name => mtp_handler_2,
       listen_ip => "0.0.0.0",
       port => 2443,
       secret => <<"100000000000000000000000000000001">>,
       tag => <<"cf8e6baff125ed5f661a761e69567711">>}
    ]}
   ]},

 {kernel,
<...>
```

Each section should have unique `name`!

### Only allow connections with 'dd'-secrets

This protocol uses randomized packet sizes, so it's more difficult to detect on DPI by
packet sizes.
It might be useful in Iran, where proxies are detected by DPI.
You should disable all protocols other than `mtp_secure` by providing `allowed_protocols` option:

```erlang
  {mtproto_proxy,
   [
    {allowed_protocols, [mtp_secure]},
    {ports,
     [#{name => mtp_handler_1,
      <..>
```

### Only allow fake-TLS connections with ee/base64-secrets

Another censorship circumvention technique. MTPRoto proxy protocol pretends to be
HTTPS web traffic (technically speaking, TLSv1.3 + HTTP/2).
It's possible to only allow connections with this protocol by changing `allowed_protocols` to
be list with only `mtp_fake_tls`.

```erlang
  {mtproto_proxy,
   [
    {allowed_protocols, [mtp_fake_tls]},
    {ports,
     [#{name => mtp_handler_1,
      <..>
```

For even stronger DPI resistance you can enable domain fronting — see
[Domain fronting for fake-TLS](#domain-fronting-for-fake-tls).

### Domain fronting for fake-TLS

When `mtp_fake_tls` is the active protocol and an incoming TLS connection fails the MTProto
handshake (wrong or absent secret — e.g. a real browser or a DPI probe), the proxy can
**forward the raw TCP connection transparently** to the real HTTPS host instead of closing it.
Replay-attack connections are also fronted: the replayed ClientHello is forwarded and the
probe receives a genuine TLS certificate from the fronting host. In both cases the proxy
is indistinguishable from a normal HTTPS server to any external observer.

Two configuration keys control this feature:

```erlang
%% Values: off | sni | "host:port"
{domain_fronting, off},

%% TCP connect timeout to the fronting host (seconds).
{domain_fronting_timeout_sec, 10},
```

The SNI domain extracted from the client's TLS ClientHello is always required (if absent,
the connection is closed). It is used for policy checks in all modes and as the forwarding
target in `sni` mode.

#### a. Forward to the SNI host (simplest)

```erlang
{mtproto_proxy,
 [
  {domain_fronting, sni},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

The proxy connects to whatever domain the client presented in the SNI field, on port 443.
No additional configuration is needed.

**Pros:** zero config; works with any domain automatically.
**Cons:** can be used to relay arbitrary HTTPS traffic through your server. If this is a
concern, add policy rules to restrict which SNI domains are accepted — the same
`in_table` / `not_in_table` rules used for normal connection policies apply here too
(connections with disallowed SNI are closed rather than fronted):

```erlang
{mtproto_proxy,
 [
  {domain_fronting, sni},
  {policy,
   [{not_in_table, tls_domain, front_blacklist}]},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

Add domains to the blacklist at runtime:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:add(front_blacklist, tls_domain, "unwanted.example.com").'
```

#### b. Forward to a fixed third-party host

```erlang
{mtproto_proxy,
 [
  {domain_fronting, "my-website.com:443"},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

All unrecognised TLS connections are forwarded to a single fixed target regardless of the
SNI field. SNI is still extracted and checked against policy rules, but the TCP connection
goes to the configured host.

**Pros:** predictable destination; easy to lock down with a whitelist so only your own
domains trigger fronting.
**Cons:** requires knowing the target host in advance.

Example with an SNI whitelist (only listed domains trigger fronting; all others are closed):

```erlang
{mtproto_proxy,
 [
  {domain_fronting, "my-website.com:443"},
  {policy,
   [{in_table, tls_domain, front_allowlist}]},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

Add allowed domains at runtime:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:add(front_allowlist, tls_domain, "my-website.com").'
```

#### c. Forward to a local web server (Nginx on localhost:1443)

The most production-ready setup: run a real web server on the same machine so the proxy
port serves genuine HTTPS content for any browser that connects.

**Step 1 — configure Nginx** to listen on `127.0.0.1:1443`:

```nginx
server {
    listen 127.0.0.1:1443 ssl;
    server_name my-website.com;

    ssl_certificate     /etc/letsencrypt/live/my-website.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/my-website.com/privkey.pem;

    location / {
        root /var/www/html;
        index index.html;
    }
}
```

**Step 2 — obtain a TLS certificate.**

With [certbot](https://certbot.eff.org/) (Let's Encrypt, recommended — requires a real
domain pointing to your server and port 80 open to the internet):

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d my-website.com
```

Or generate a self-signed certificate (works for any hostname, but browsers will show a
warning — still enough to fool DPI):

```bash
openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/private/proxy-selfsigned.key \
    -out /etc/ssl/certs/proxy-selfsigned.crt -days 3650 -nodes \
    -subj "/CN=my-website.com"
```

Then reference those paths in the `ssl_certificate` / `ssl_certificate_key` lines above.

**Step 3 — configure the proxy:**

```erlang
{mtproto_proxy,
 [
  {domain_fronting, "127.0.0.1:1443"},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

**Pros:** proxy port truly serves HTTPS; real certificates; ideal for servers that already
run a website.
**Cons:** requires a running web server and a TLS certificate.

### Connection limit policies

Proxy supports flexible connection limit rules. It's possible to limit number of connections from
single IP or to single fake-TLS domain or to single port name; or any combination of them.
It also supports whitelists and blacklists: you can allow or forbid to connect from some IP or IP subnet
or with some TLS domains.

Policy is set as value of `policy` config key and the value is the list of policy structures.
If list is empty, no limits will be checked.

Following policies are supported:

* `{in_table, KEY, TABLE_NAME}` - only allow connections if KEY is present in TABLE_NAME (whitelist)
* `{not_in_table, KEY, TABLE_NAME}` - only allow connections if KEY is *not* present in TABLE_NAME (blacklist)
* `{max_connections, KEYS, NUMBER}` - EXPERIMENTAL! if there are more than NUMBER connections with
  KEYS to the proxy, new connections with those KEYS will be rejected. Note: number of connections is not the
  same as number of unique "users". When someone connects to proxy with telegram client, Telegram
  opens from 3 to 8 connections! So, you need to set this at least 8 * number of unique users.

Where:

- `KEY` is one of:
  - `port_name` - proxy port name
  - `client_ipv4` - client's IPv4 address; ignored on IPv6 ports!
  - `client_ipv6` - client's IPv6 address; ignored on IPv4 ports!
  - `{client_ipv4_subnet, MASK}` - client's IPv4 subnet; mask is from 8 to 32
  - `{client_ipv6_subnet, MASK}` - client's IPv6 subnet; mask is from 32 to 128
  - `tls_domain` - lowercase domain name from fake-TLS secret; ignored if connection with non-fake-TLS protocol
- `KEYS` is a list of one or more `KEY`, eg, `[port, tls_domain]`
- `TABLE_NAME` is free-form text name of special internal database table, eg, `my_table`.
  Tables will be created automatically when proxy is started; data in tables is not preserved when proxy
  is restarted!
  You can add or remove new values from table dynamically at any moment with commands like:
    - `/opt/mtp_proxy/bin/mtp_proxy eval 'mtp_policy_table:add(my_table, tls_domain, "google.com").'` to add
    - `/opt/mtp_proxy/bin/mtp_proxy eval 'mtp_policy_table:del(my_table, tls_domain, "google.com").'` to remove

Some policy recipes / examples below

#### Limit max connections to proxy port from single IP

Here we allow maximum 100 concurrent connections from single IP to proxy port (as it was said earlier, it's not
the same as 100 unique "users"! Each telegram client opens up to 8 connections; usually 3):

```erlang
{mtproto_proxy,
 [
  {policy,
    [{max_connections, [port_name, client_ipv4], 100}]},
  {ports,
    <..>
```

#### Disallow connections from some IPs

```erlang
{mtproto_proxy
 [
   {policy,
     [{not_in_table, client_ipv4, ip_blacklist}]},
   {ports,
     <..>
```

And then add IPs to blacklist with command:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:add(ip_blacklist, client_ipv4, "203.0.113.1").'
```

Remove from blacklist:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:del(ip_blacklist, client_ipv4, "203.0.113.1").'
```

#### Personal proxy / multi-secret proxy

We can limit number of connections with single fake-TLS domain and only allow connections
with fake-TLS domains from whitelist.

```erlang
{mtproto_proxy
 [
   {policy,
     [{max_connections, [port_name, tls_domain], 15},
      {in_table, tls_domain, customer_domains}]},
   {ports,
     <..>
```

Now we can assign each customer unique fake-TLS domain, eg, `my-client1.example.com`
and give them unique TLS secret.
Because we only allow 10 connections with single fake-TLS secret, they will not be able to
share their credentials with others. To add client's fake domain to whitelist:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:add(customer_domains, tls_domain, "my-client1.example.com").'
```

And then use https://seriyps.com/mtpgen.html to generate unique link for them.
Be aware that domains table will be reset if proxy is restarted! Make sure you re-add them
when proxy restarts (eg, via [systemd hook script](https://unix.stackexchange.com/q/326181/70382)).

### IPv6

Currently proxy only supports client connections via IPv6, but can only connect to Telegram servers
using IPv4.

To enable IPv6, you should put IPv6 address in `listen_ip` config key.
If you want proxy to accept clients on the same port with both IPv4 and IPv6, you should
have 2 `ports` sections with the same `port`, `secret` and `tag`, but with different names and
different `listen_ip` (one v4 and one v6):

```erlang
 {mtproto_proxy,
  %% see src/mtproto_proxy.app.src for examples.
  [
   {ports,
    [#{name => mtp_handler_all_ipv4,
       listen_ip => "0.0.0.0",  % IPv4 address, eg 203.0.113.1
       port => 1443,
       secret => <<"d0d6e111bada5511fcce9584deadbeef">>,
       tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>},
     #{name => mtp_handler_all_ipv6,
       listen_ip => "::",  % IPv6 address, eg "2001:db8:85a3::8a2e:370:7334"
       port => 1443,
       secret => <<"d0d6e111bada5511fcce9584deadbeef">>,
       tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}
    ]}
   ]},

 {kernel,
<...>
```

### Tune resource consumption

If your server have low amount of RAM, try to set

```erlang
{upstream_socket_buffer_size, 5120},
{downstream_socket_buffer_size, 51200},
{replay_check_session_storage, off},
{init_timeout_sec, 10},
{hibernate_timeout_sec, 30},
{ready_timeout_sec, 120},  % close connection after 2min of inactivity
```

this may make proxy slower, it can start to consume bit more CPU, will be vulnerable to replay attacks,
but will use less RAM.
You should also avoid `max_connections` policy because it uses RAM to track connections.

If your server have lots of RAM, you can make it faster (users will get higher uppload/download speed),
it will use less CPU and will be better protected from replay attacks, but will use more RAM:

```erlang
{max_connections, 128000},
{upstream_socket_buffer_size, 20480},
{downstream_socket_buffer_size, 512000},
{replay_check_session_storage, on},
{replay_check_session_storage_opts,
  #{max_memory_mb => 2048,
    max_age_minutes => 1440}},
```

One more option to decrease CPU usage is to disable CRC32 checksum check:

```erlang
{mtp_full_check_crc32, false},
```

Also, for highload setups it's recommended to increase sysctl parameters:

```
sudo sysctl net.ipv4.tcp_max_orphans=128000
sudo sysctl 'net.ipv4.tcp_mem=179200 256000 384000'
```

Values for `tcp_mem` are in pages. Size of one page can be found by `getconf PAGESIZE` and is most
likely 4kb.

If you have installed proxy via Docker or use some NAT firewall settings, you may want to increase
netfilter conntrack limits to be at least the max number of connections you expect:

```
sudo sysctl net.netfilter.nf_conntrack_max=128000
```


Helpers
-------

Number of connections

```bash
/opt/mtp_proxy/bin/mtp_proxy eval 'lists:sum([proplists:get_value(all_connections, L) || {_, L} <- ranch:info()]).'
```
