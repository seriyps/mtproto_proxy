# Based on https://github.com/erlang/docker-erlang-example

FROM erlang:21-alpine as builder

RUN apk add --no-cache git

RUN mkdir -p /build/mtproto_proxy

WORKDIR /build/mtproto_proxy
COPY src src
COPY rebar3 rebar3
COPY rebar.config rebar.config
COPY rebar.lock rebar.lock
COPY config config
RUN if [ ! -f config/prod-sys.config ]; then cp config/sys.config.example config/prod-sys.config; fi
RUN if [ ! -f config/prod-vm.args ]; then cp config/vm.args.example config/prod-vm.args; fi

RUN rebar3 as prod release

FROM alpine:3.9
RUN apk add --no-cache openssl && \
    apk add --no-cache ncurses-libs && \
    apk add --no-cache dumb-init

RUN mkdir -p /opt /var/log/mtproto-proxy
COPY start.sh /bin/start.sh
COPY --from=builder /build/mtproto_proxy/_build/prod/rel/mtp_proxy /opt/mtp_proxy

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/bin/start.sh"]
