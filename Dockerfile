# Based on https://github.com/erlang/docker-erlang-example

FROM erlang:alpine

RUN apk add --no-cache git

RUN mkdir -p /build/mtproto_proxy

WORKDIR /build/mtproto_proxy
COPY src src
COPY rebar3 rebar3
COPY rebar.config rebar.config
COPY rebar.lock rebar.lock
COPY config config
RUN [ ! -f config/prod-sys.config ] && cp config/sys.config.example config/prod-sys.config
RUN [ ! -f config/prod-vm.args ] && cp config/vm.args.example config/prod-vm.args

RUN rebar3 as prod release

FROM alpine
RUN apk add --no-cache openssl && \
    apk add --no-cache ncurses-libs && \
    apk add --no-cache dumb-init

RUN mkdir -p /opt
RUN mkdir -p /var/log/mtproto-proxy
COPY --from=0 /build/mtproto_proxy/_build/prod/rel/mtp_proxy /opt/mtp_proxy

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/opt/mtp_proxy/bin/mtp_proxy", "foreground"]
