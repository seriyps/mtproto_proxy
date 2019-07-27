%%%-------------------------------------------------------------------
%% @doc mtproto_proxy public API
%% @end
%%%-------------------------------------------------------------------

-module(mtproto_proxy_app).

-behaviour(application).

%% Application callbacks
-export([start/2, prep_stop/1, stop/1, config_change/3]).
-export([mtp_listeners/0, running_ports/0, start_proxy/1]).

-define(APP, mtproto_proxy).

-include_lib("hut/include/hut.hrl").

-type proxy_port() :: #{name := any(),
                        port := inet:port_number(),
                        secret := binary(),
                        tag := binary(),
                        listen_ip => string()}.

%%====================================================================
%% API
%%====================================================================
start(_StartType, _StartArgs) ->
    Res = {ok, _} = mtproto_proxy_sup:start_link(),
    report("+++++++++++++++++++++++++++++++++++++++~n"
           "Erlang MTProto proxy by @seriyps https://github.com/seriyps/mtproto_proxy~n"
           "Sponsored by and powers @socksy_bot~n", []),
    [start_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    Res.


prep_stop(State) ->
    [stop_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    State.


stop(_State) ->
    ok.


config_change(Changed, New, Removed) ->
    %% app's env is already updated when this callback is called
    ok = lists:foreach(fun(K) -> config_changed(removed, K, []) end, Removed),
    ok = lists:foreach(fun({K, V}) -> config_changed(changed, K, V) end, Changed),
    ok = lists:foreach(fun({K, V}) -> config_changed(new, K, V) end, New).

%%--------------------------------------------------------------------

%% @doc List of ranch listeners running mtproto_proxy
-spec mtp_listeners() -> [tuple()].
mtp_listeners() ->
    lists:filter(
      fun({_Name, Opts}) ->
              proplists:get_value(protocol, Opts) == mtp_handler
      end,
      ranch:info()).


%% @doc Currently running listeners in a form of proxy_port()
-spec running_ports() -> [proxy_port()].
running_ports() ->
    lists:map(
      fun({Name, Opts}) ->
              #{protocol_options := ProtoOpts,
                ip := Ip,
                port := Port} = maps:from_list(Opts),
              [Name, Secret, AdTag] = ProtoOpts,
              case inet:ntoa(Ip) of
                  {error, einval} ->
                      error({invalid_ip, Ip});
                  IpAddr ->
                      #{name => Name,
                        listen_ip => IpAddr,
                        port => Port,
                        secret => Secret,
                        tag => AdTag}
              end
      end, mtp_listeners()).

%%====================================================================
%% Internal functions
%%====================================================================
-spec start_proxy(proxy_port()) -> {ok, pid()}.
start_proxy(#{name := Name, port := Port, secret := Secret, tag := Tag} = P) ->
    ListenIpStr = maps:get(
                    listen_ip, P,
                    application:get_env(?APP, listen_ip, "0.0.0.0")),
    {ok, ListenIp} = inet:parse_address(ListenIpStr),
    Family = case tuple_size(ListenIp) of
                 4 -> inet;
                 8 -> inet6
             end,
    NumAcceptors = application:get_env(?APP, num_acceptors, 60),
    MaxConnections = application:get_env(?APP, max_connections, 10240),
    Res =
        ranch:start_listener(
          Name, ranch_tcp,
          #{socket_opts => [{ip, ListenIp},
                            {port, Port},
                            Family],
            num_acceptors => NumAcceptors,
            max_connections => MaxConnections},
          mtp_handler, [Name, Secret, Tag]),
    Urls = build_urls(application:get_env(?APP, external_ip, ListenIpStr),
                      Port, Secret, application:get_env(?APP, allowed_protocols, [])),
    UrlsStr = ["\n" | lists:join("\n", Urls)],
    report("Proxy started on ~s:~p with secret: ~s, tag: ~s~nLinks: ~s",
           [ListenIpStr, Port, Secret, Tag, UrlsStr]),
    Res.


stop_proxy(#{name := Name}) ->
    ranch:stop_listener(Name).

config_changed(_, ip_lookup_services, _) ->
    mtp_config:update();
config_changed(_, proxy_secret_url, _) ->
    mtp_config:update();
config_changed(_, proxy_config_url, _) ->
    mtp_config:update();
config_changed(Action, max_connections, N) when Action == new; Action == changed ->
    (is_integer(N) and (N >= 0)) orelse error({"max_connections should be non_neg_integer", N}),
    lists:foreach(fun({Name, _}) ->
                          ranch:set_max_connections(Name, N)
                  end, mtp_listeners());
config_changed(Action, downstream_socket_buffer_size, N) when Action == new; Action == changed ->
    [{ok, _} = mtp_down_conn:set_config(Pid, downstream_socket_buffer_size, N)
     || Pid <- downstream_connections()],
    ok;
config_changed(Action, downstream_backpressure, BpOpts) when Action == new; Action == changed ->
    is_map(BpOpts) orelse error(invalid_downstream_backpressure),
    [{ok, _} = mtp_down_conn:set_config(Pid, downstream_backpressure, BpOpts)
     || Pid <- downstream_connections()],
    ok;
%% Since upstream connections are mostly short-lived, live-update doesn't make much difference
%% config_changed(Action, upstream_socket_buffer_size, N) when Action == new; Action == changed ->
config_changed(Action, ports, Ports)  when Action == new; Action == changed ->
    %% TODO: update secret or ad_tag without disconnect
    RanchPorts = ordsets:from_list(running_ports()),
    DefaultListenIp = #{listen_ip => application:get_env(?APP, listen_ip, "0.0.0.0")},
    NewPorts = ordsets:from_list([maps:merge(DefaultListenIp, Port)
                                  || Port <- Ports]),
    ToStop = ordsets:subtract(RanchPorts, NewPorts),
    ToStart = ordsets:subtract(NewPorts, RanchPorts),
    lists:foreach(fun stop_proxy/1, ToStop),
    [{ok, _} = start_proxy(Conf) || Conf <- ToStart],
    ok;
config_changed(Action, K, V) ->
    %% Most of the other config options are applied automatically without extra work
    ?log(info, "Config ~p ~p to ~p ignored", [K, Action, V]),
    ok.

downstream_connections() ->
    [Pid || {_, Pid, worker, [mtp_down_conn]} <- supervisor:which_children(mtp_down_conn_sup)].


build_urls(Host, Port, Secret, Protocols) ->
    MkUrl = fun(ProtoSecret) ->
                    io_lib:format(
                      "https://t.me/proxy?server=~s&port=~w&secret=~s",
                      [Host, Port, ProtoSecret])
            end,
    UrlTypes = lists:usort(
                 lists:map(fun(mtp_abridged) -> normal;
                              (mtp_intermediate) -> normal;
                              (Other) -> Other
                           end, Protocols)),
    lists:map(
      fun(mtp_fake_tls) ->
              RawSecret = mtp_handler:unhex(Secret),
              ProtoSecret = base64url(<<16#ee, RawSecret/binary, "en.wikipedia.org">>),
              MkUrl(ProtoSecret);
         (mtp_secure) ->
              ProtoSecret = ["dd", Secret],
              MkUrl(ProtoSecret);
         (normal) ->
              MkUrl(Secret)
      end, UrlTypes).

base64url(Bin) ->
    %% see https://hex.pm/packages/base64url
    << << (urlencode_digit(D)) >> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

-ifdef(TEST).
report(Fmt, Args) ->
    ?log(debug, Fmt, Args).
-else.
report(Fmt, Args) ->
    io:format(Fmt ++ "\n", Args),
    ?log(info, Fmt, Args).
-endif.
