#!/usr/bin/env bash
# gen_dist_certs.sh — generate TLS certificates for Erlang distribution
#
# This script is designed to be run in TWO steps:
#
#   Step 1 — run on the BACK server (once, to set up the CA and back cert):
#     ./scripts/gen_dist_certs.sh init <output_dir>
#
#   Step 2 — run on the BACK server for each FRONT server you add:
#     ./scripts/gen_dist_certs.sh add-node <output_dir> <node_name>
#
# Example — back server and two front servers:
#   ./scripts/gen_dist_certs.sh init  /etc/mtproto-proxy/dist
#   ./scripts/gen_dist_certs.sh add-node /etc/mtproto-proxy/dist front1
#   ./scripts/gen_dist_certs.sh add-node /etc/mtproto-proxy/dist front2
#
# Output files (all in <output_dir>):
#   ca.pem                   — CA certificate  (copy to every server)
#   back.pem / back.key      — back node cert/key  (keep on back server)
#   <name>.pem / <name>.key  — per-front cert/key  (copy to that front server)
#   ssl_dist.back.conf       — ready-to-use Erlang TLS config for back
#                              (copy to /etc/mtproto-proxy/dist/ on back server)
#   ssl_dist.<name>.conf     — ready-to-use Erlang TLS config for that front
#                              (copy to /etc/mtproto-proxy/dist/ on that front server)
#
# After setup:
#   On back server:   ca.pem  back.pem  back.key  ssl_dist.back.conf
#   On each front:    ca.pem  <name>.pem  <name>.key  ssl_dist.<name>.conf
#   Uncomment -proto_dist and -ssl_dist_optfile in vm.args on each server.
#
# Reference: https://www.erlang.org/doc/apps/ssl/ssl_distribution.html

set -euo pipefail

usage() {
    echo "Usage:" >&2
    echo "  $0 init     <output_dir>              # Step 1: CA + back cert" >&2
    echo "  $0 add-node <output_dir> <node_name>  # Step 2: add a front cert" >&2
    exit 1
}

[ $# -lt 2 ] && usage

CMD="$1"
OUTDIR="$2"
DAYS=3650   # 10 years

mkdir -p "$OUTDIR"

# ---- shared: ensure CA exists ----
ensure_ca() {
    if [ ! -f "$OUTDIR/ca.key" ]; then
        echo "==> Generating CA key and certificate..."
        openssl req -new -x509 -days "$DAYS" \
            -keyout "$OUTDIR/ca.key" \
            -out    "$OUTDIR/ca.pem" \
            -nodes  \
            -subj   "/CN=mtproto-proxy-dist-ca"
        chmod 600 "$OUTDIR/ca.key"
    else
        echo "==> Using existing CA: $OUTDIR/ca.key"
    fi
}

# ---- shared: generate one node cert signed by the CA ----
gen_node_cert() {
    local NAME="$1"
    echo "==> Generating certificate for node: $NAME"
    openssl req -new \
        -keyout "$OUTDIR/$NAME.key" \
        -out    "$OUTDIR/$NAME.csr" \
        -nodes  \
        -subj   "/CN=$NAME"
    openssl x509 -req -days "$DAYS" \
        -in        "$OUTDIR/$NAME.csr" \
        -CA        "$OUTDIR/ca.pem" \
        -CAkey     "$OUTDIR/ca.key" \
        -CAcreateserial \
        -out       "$OUTDIR/$NAME.pem"
    rm -f "$OUTDIR/$NAME.csr"
    chmod 600 "$OUTDIR/$NAME.key"
    echo "    -> $OUTDIR/$NAME.pem  $OUTDIR/$NAME.key"
}

# ---- shared: write a ready-to-use ssl_dist.<name>.conf for one node ----
write_ssl_conf() {
    local NAME="$1"
    local CONF="$OUTDIR/ssl_dist.$NAME.conf"
    cat > "$CONF" << EOF
%% Erlang TLS distribution config for node: $NAME
%% Copy this file to /etc/mtproto-proxy/dist/ on the '$NAME' server.
[
  {server,
   [{certfile,             "/etc/mtproto-proxy/dist/$NAME.pem"},
    {keyfile,              "/etc/mtproto-proxy/dist/$NAME.key"},
    {cacertfile,           "/etc/mtproto-proxy/dist/ca.pem"},
    {verify,               verify_peer},
    {fail_if_no_peer_cert, true}]},
  {client,
   [{certfile,             "/etc/mtproto-proxy/dist/$NAME.pem"},
    {keyfile,              "/etc/mtproto-proxy/dist/$NAME.key"},
    {cacertfile,           "/etc/mtproto-proxy/dist/ca.pem"},
    {verify,               verify_peer}]}
].
EOF
    echo "    -> $CONF"
}

case "$CMD" in
    init)
        ensure_ca
        gen_node_cert "back"
        write_ssl_conf "back"
        echo ""
        echo "==> Done. Back server setup complete."
        echo ""
        echo "Next:"
        echo "  1. On the back server, copy to /etc/mtproto-proxy/dist/:"
        echo "       ca.pem  back.pem  back.key"
        echo "  2. Copy ssl_dist.back.conf to /etc/mtproto-proxy/dist/"
        echo "  3. Uncomment -proto_dist / -ssl_dist_optfile in vm.args."
        echo "  4. For each front server, run:"
        echo "       $0 add-node $OUTDIR <front_name>"
        ;;
    add-node)
        [ $# -lt 3 ] && usage
        NAME="$3"
        if [ ! -f "$OUTDIR/ca.key" ]; then
            echo "ERROR: CA not found in $OUTDIR. Run '$0 init $OUTDIR' first." >&2
            exit 1
        fi
        gen_node_cert "$NAME"
        write_ssl_conf "$NAME"
        echo ""
        echo "==> Done. Certificate for '$NAME' generated."
        echo ""
        echo "Copy to the '$NAME' front server:"
        echo "  ca.pem  $NAME.pem  $NAME.key"
        echo "  ssl_dist.$NAME.conf  (copy to /etc/mtproto-proxy/dist/ on that server)"
        ;;
    *)
        usage
        ;;
esac
