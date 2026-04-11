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
* Per-SNI derived secrets for personal proxies - each user gets a unique token tied to their
  fake-TLS domain; base secret cannot be extracted from user links
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
* Split-mode setup: run the client-facing part (front) on a domestic server and
  the Telegram-facing part (back) on a foreign server, connected via Erlang distribution
  (TLS or a censorship-resistant tunnel). Bypasses ISP blocks that target direct
  domestic→foreign connections. Multiple front servers can share one back server.
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
2. Copy config templates `make init-config` (or manually: `cp config/{vm.args.example,prod-vm.args}; cp config/{sys.config.example,prod-sys.config}`)
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
make init-config   # copies templates and auto-detects your server's IP
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

```bash
make init-config   # copies sys.config.example → prod-sys.config and vm.args.example → prod-vm.args
                   # also auto-detects your server's public IP
```

Edit `config/prod-sys.config` — see [Settings](#settings) for all options.

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
**Cons:** can be used to relay arbitrary HTTPS traffic through your server.

> **⚠️ Loop risk:** if a client presents an SNI domain that resolves to the proxy's own IP,
> the proxy will connect back to itself and loop indefinitely, exhausting file descriptors.
> Use `sni` mode together with policy rules (see below) or switch to the `"host:port"` mode,
> which is not affected by this issue.

You can optionally restrict which SNI domains get fronted using the same `in_table` /
`not_in_table` policy rules as normal connections. Two common approaches:

**Domain whitelist** — only front explicitly allowed domains (safest):

```erlang
{mtproto_proxy,
 [
  {domain_fronting, sni},
  {policy,
   [{in_table, tls_domain, front_allowlist}]},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

Add domains to the whitelist at runtime:

```bash
/opt/mtp_proxy/bin/mtp_proxy eval '
mtp_policy_table:add(front_allowlist, tls_domain, "my-website.com").'
```

**IP blacklist** — block the proxy's own public IP to prevent loops:

```erlang
{mtproto_proxy,
 [
  {domain_fronting, sni},
  {policy,
   [{not_in_table, client_ipv4, ip_blacklist}]},
  {ports,
   [#{name => mtp_handler_1,
      ...
```

```bash
# The proxy auto-detects its external IP; add it to the blacklist once on startup:
/opt/mtp_proxy/bin/mtp_proxy eval '
{ok, Ip} = application:get_env(mtproto_proxy, external_ip),
mtp_policy_table:add(ip_blacklist, client_ipv4, Ip).'
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

#### Strengthening personal proxies with per-SNI derived secrets

With the classic scheme above, the SNI domain in a user's link is the only thing that
distinguishes them — the underlying 16-byte secret is the same for everyone and is
embedded verbatim in every link, so any user who inspects their link gets the raw secret.
The only protection against credential sharing is the connection-count policy and the hope
that the user's SNI domain is long and obscure enough that no one else guesses it.

There is a tension here: for best DPI resistance, fake-TLS SNI domains should look like
real websites — short, readable names like `news.example.com` — but short readable names
are exactly the ones that are easy to guess or share.

**Per-SNI derived secrets resolve this tension.** Instead of embedding the base secret,
each user's link carries a token derived specifically for their SNI domain:

```
derived = SHA256(salt || hex(base_secret) || sni_domain)[0:16]
link    = ee | derived (16 bytes) | sni_domain
```

A user who inspects their link sees only their own derived token. They cannot recover the
base secret, cannot compute tokens for other domains, and cannot construct a valid
connection using a different SNI. Combined with the domain whitelist, revoking a user
(removing their domain from the whitelist) is now cryptographically meaningful: their
derived token is unique to their domain and is worthless elsewhere.

**Enable in `sys.config`:**

```erlang
{per_sni_secrets, on},
{per_sni_secret_salt, <<"my-private-salt-change-me">>},
```

> ⚠️ **Switching to `on` invalidates all existing fake-TLS user links.** Re-issue every
> user's link after the change.

The salt is the sole true secret — an attacker who knows the base secret but not the salt
cannot compute any derived secrets.

*(HMAC-SHA256 would be cryptographically more rigorous here, but SHA-256 is secure enough
for this use case and lets every language express the derivation as a
single hash call — see the one-liners below.)*

##### Generating user links

Given your `SALT`, `SECRET` (32 lowercase hex chars from your config), and `SNI` (the
domain in the user's link):

**Bash (Linux — `sha256sum` from coreutils):**
```bash
SALT="my-private-salt-change-me"
SECRET="d0d6e111bada5511fcce9584deadbeef"
SNI="alice.example.com"

DERIVED=$(printf '%s%s%s' "$SALT" "$SECRET" "$SNI" | sha256sum | cut -c1-32)
SNI_HEX=$(printf '%s' "$SNI" | od -A n -t x1 | tr -d ' \n')
echo "ee${DERIVED}${SNI_HEX}"
```

**Bash (macOS — replace `sha256sum` with `shasum -a 256`):**
```bash
DERIVED=$(printf '%s%s%s' "$SALT" "$SECRET" "$SNI" | shasum -a 256 | cut -c1-32)
```

**Python:**
```python
import hashlib
salt, secret, sni = "my-private-salt-change-me", "d0d6e111bada5511fcce9584deadbeef", "alice.example.com"
derived = hashlib.sha256((salt + secret + sni).encode()).hexdigest()[:32]
print(f"ee{derived}{sni.encode().hex()}")
```

**Node.js:**
```javascript
const crypto = require('crypto');
const [salt, secret, sni] = ['my-private-salt-change-me', 'd0d6e111bada5511fcce9584deadbeef', 'alice.example.com'];
const derived = crypto.createHash('sha256').update(salt + secret + sni).digest('hex').slice(0, 32);
console.log('ee' + derived + Buffer.from(sni).toString('hex'));
```

**Browser JavaScript (no dependencies):**
```javascript
async function makeLink(salt, secret, sni) {
    const data = new TextEncoder().encode(salt + secret + sni);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const hex = b => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return 'ee' + hex(new Uint8Array(hash).slice(0, 16)) + hex(new TextEncoder().encode(sni));
}
// makeLink('my-private-salt-change-me', 'd0d6...', 'alice.example.com').then(console.log)
```

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

Keep in mind that `listen_ip => "::"` would listen both on IPv6 and IPv4(!!) addresses (in IPv6 to v4 compat mode). If you need separate listeners, specify full IPv6 address explicitly.

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
/opt/mtp_proxy/bin/mtp_proxy eval 'lists:sum([maps:get(all_connections, L) || {_, L} <- maps:to_list(ranch:info())]).'
```

Split-mode setup (front + back)
--------------------------------

### Why split mode?

Some censors (e.g. Roskomnadzor) monitor connections from domestic IPs to foreign
servers more aggressively than domestic-to-domestic traffic. A common workaround is
to split the proxy across two servers:

- **Front server** — domestic (or neutral) IP, accepts Telegram client connections.
- **Back server** — foreign IP, connects to Telegram data centres.

```
Telegram client
      │
      ▼ (443 / any port)
 ┌────────────┐
 │ front node │  domestic server  (mtp_handler, session storage, policies)
 └─────┬──────┘
       │  inter-server link (VPN or TLS)
       ▼
 ┌────────────┐
 │ back node  │  foreign server   (DC pool connections to Telegram)
 └─────┬──────┘
       │  TCP to Telegram
       ▼
  Telegram DC
```

Multiple front servers can share one back server — just set the same `back_node`
address in each front's config.  The DC pools on the back multiplex all client
connections regardless of which front they came from.

### Prerequisites

- Erlang/OTP 25+ installed on **both** servers (same version recommended).
- Both servers can reach each other over TCP (the inter-server port, see below).
- The back server has outbound TCP access to Telegram's infrastructure (ports
  are announced dynamically in [Telegram's proxy config](https://core.telegram.org/getProxyConfig).

### Step 1 — secure the inter-server link

The two servers communicate using Erlang's built-in distribution protocol, which
allows full remote control of the process.  **You must restrict access to this
channel** to the two proxy servers only.  There are two ways to do this:

#### Option A: Censorship-resistant tunnel (recommended if front is in Russia)

Standard VPN protocols (WireGuard, OpenVPN) are detectable and blocked on many
Russian ISPs.  Use a DPI-resistant tunnel instead:

- **[Shadowsocks](https://shadowsocks.org/)** — widely used, low overhead
- **[VLESS/XRay](https://github.com/XTLS/Xray-core)** — highly configurable, very hard to block
- **[Hysteria2](https://github.com/apernet/hysteria)** — QUIC-based, good for lossy links

Set up the tunnel between front and back servers and use the **tunnel interface
addresses** in the node names (`front@10.8.0.1`, `back@10.8.0.2`).  No extra
Erlang config is needed once the tunnel is up.

> If the front server is **not** in a heavily censored region, WireGuard or
> IPsec work equally well and are simpler to set up.

#### Option B: TLS distribution (no tunnel required)

If you prefer not to run a separate tunnel, you can secure the distribution link
with mutual-TLS certificates.  Run on the **back server**:

```bash
# Step 1 — on the back server: initialise CA and generate back cert
./scripts/gen_dist_certs.sh init /etc/mtproto-proxy/dist

# Step 2 — repeat for each front server you add
./scripts/gen_dist_certs.sh add-node /etc/mtproto-proxy/dist front
# (use a distinct name per front, e.g. front1, front2, …)
```
Copy to each server (paths already substituted — no editing needed):

 * back server:  ca.pem  back.pem  back.key  ssl_dist.back.conf
 * front server: ca.pem  front.pem  front.key  ssl_dist.front.conf

Place all files in `/etc/mtproto-proxy/dist/`.
Then uncomment `-proto_dist` and `-ssl_dist_optfile` in `vm.args` on each server.


Reference: [Erlang TLS distribution docs](https://www.erlang.org/doc/apps/ssl/ssl_distribution.html)

### Step 2 — configure the back server

Run on the **back server**:

```bash
make init-config ROLE=back
```

This copies `config/sys.config.back.example` → `config/prod-sys.config` and
`config/vm.args.back.example` → `config/prod-vm.args`.  Edit them:

- In `vm.args`: set the **back** server's IP: `-name back@<BACK_IP>` and choose
  a strong cookie string (`-setcookie ...`).
- In `sys.config`: set `external_ip` to the back server's public IP, or leave
  `ip_lookup_services` to auto-detect it.
- If using TLS distribution (Option B): uncomment the `-proto_dist` /
  `-ssl_dist_optfile` lines in `vm.args`.

### Step 3 — configure the front server

Run on the **front server**:

```bash
make init-config ROLE=front
```

This copies `config/sys.config.front.example` → `config/prod-sys.config` and
`config/vm.args.front.example` → `config/prod-vm.args`.  Edit them:

- In `vm.args`: set the **front** server's IP: `-name front@<FRONT_IP>` and the
  **same** cookie string as the back.
- In `sys.config`: set `back_node` to the back node name you chose above
  (e.g. `'back@10.8.0.2'`), configure `ports` / `secret` / `tag` as usual.
- If using TLS distribution: uncomment `-proto_dist` / `-ssl_dist_optfile` here too.

### Step 4 — start in order

Always **start the back server first**.  The front server connects to it on
startup; if the back is not yet up the front will log a warning and retry
automatically on the next client connection.

```bash
# On back server:
make ROLE=back && sudo make install && systemctl start mtproto-proxy

# On front server (after back is up):
make ROLE=front && sudo make install && systemctl start mtproto-proxy
```

> **Why `ROLE=` on every `make`?**  After `git pull`, if a new release updates
> `config/sys.config.back.example`, `make ROLE=back` detects the change (target
> is older than its prerequisite), shows a diff, and prompts before overwriting
> your `prod-sys.config`.  Plain `make` (default `ROLE=both`) compares against
> `sys.config.example` instead and silently misses changes to the back/front
> templates.

### Step 5 — verify

On the front server, check that the back node is visible:

```bash
/opt/personal_mtproxy/bin/mtproto_proxy remote_console
# In the Erlang shell:
nodes().          % should list the back node
```

On the back server, verify DC pools are running:

```bash
/opt/personal_mtproxy/bin/mtproto_proxy remote_console
# In the Erlang shell:
mtp_config:status().
```

### Firewall rules

| Server | Port                  | Allow from    |
|--------|-----------------------|---------------|
| back   | 4369 (EPMD)           | front IP only |
| back   | 9199 (dist)           | front IP only |
| front  | 4369 (EPMD)           | back IP only  |
| front  | 9199 (dist)           | back IP only  |
| front  | 443 / your proxy port | anywhere      |

If you used a fixed dist port in `vm.args` (`inet_dist_listen_min/max 9199`),
only port 9199 needs to be open; otherwise allow the full 9199–9254 range plus
EPMD (4369).  **Never expose the distribution port to the public internet.**
