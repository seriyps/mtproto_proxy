%%%-------------------------------------------------------------------
%% @doc mtproto_proxy public API
%% @end
%%%-------------------------------------------------------------------

-module(mtproto_proxy_app).

-behaviour(application).

%% Application callbacks
-export([start/2, prep_stop/1, stop/1, config_change/3]).
%% Helpers
-export([mtp_listeners/0,
         reload_config/0,
         running_ports/0,
         start_proxy/1,
         build_urls/4,
         get_port_secret/1]).

-define(APP, mtproto_proxy).

-include_lib("kernel/include/logger.hrl").

-type proxy_port() :: #{name := any(),
                        port := inet:port_number(),
                        secret := binary(),
                        tag := binary(),
                        listen_ip => string()}.

%%====================================================================
%% Application behaviour API
%%====================================================================
start(_StartType, _StartArgs) ->
    Res = {ok, _} = mtproto_proxy_sup:start_link(),
    report("+++++++++++++++++++++++++++++++++++++++~n"
           "🇺🇦 Stand with Ukraine! Glory to the heroes! 🇺🇦~n"
           "Erlang MTProto proxy by @seriyps https://github.com/seriyps/mtproto_proxy~n", []),
    Role = node_role(),
    case Role of
        front ->
            maybe_connect_back_node();
        _ -> ok
    end,
    case Role of
        back -> ok;
        _    -> [start_proxy(Where) || Where <- application:get_env(?APP, ports, [])]
    end,
    Res.


prep_stop(State) ->
    [stop_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    State.


stop(_State) ->
    ok.


config_change(Changed, New, Removed) ->
    %% app's env is already updated when this callback is called
    Role = node_role(),
    ok = lists:foreach(fun(K) -> config_changed(removed, K, [], Role) end, Removed),
    ok = lists:foreach(fun({K, V}) -> config_changed(changed, K, V, Role) end, Changed),
    ok = lists:foreach(fun({K, V}) -> config_changed(new, K, V, Role) end, New).

%%--------------------------------------------------------------------
%% Other APIs

%% XXX: this is ad-hoc helper function; it is simplified version of code from OTP application_controller.erl
reload_config() ->
    PreEnv = application:get_all_env(?APP),
    NewConfig = read_sys_config(),
    [application:set_env(?APP, K, V) || {K, V} <- NewConfig],
    NewEnv = application:get_all_env(?APP),
    %% TODO: "Removed" will always be empty; to handle it properly we should merge env
    %% from .app file with NewConfig
    {Changed, New, Removed} = diff_env(NewEnv, PreEnv),
    ?LOG_INFO("Updating config; changed=~p, new=~p, deleted=~p", [Changed, New, Removed]),
    config_change(Changed, New, Removed).

read_sys_config() ->
    {ok, [[File]]} = init:get_argument(config),
    {ok, [Data]} = file:consult(File),
    proplists:get_value(?APP, Data, []).

diff_env(NewEnv, OldEnv) ->
    NewEnvMap = maps:from_list(NewEnv),
    OldEnvMap = maps:from_list(OldEnv),
    NewKeySet = ordsets:from_list(maps:keys(NewEnvMap)),
    OldKeySet = ordsets:from_list(maps:keys(OldEnvMap)),
    DelKeys = ordsets:subtract(OldKeySet, NewKeySet),
    AddKeys = ordsets:subtract(NewKeySet, OldKeySet),
    ChangedKeys =
        lists:filter(
          fun(K) ->
                  maps:get(K, NewEnvMap) =/= maps:get(K, OldEnvMap)
          end, ordsets:intersection(OldKeySet, NewKeySet)),
    {[{K, maps:get(K, NewEnvMap)} || K <- ChangedKeys],
     [{K, maps:get(K, NewEnvMap)} || K <- AddKeys],
     DelKeys}.


%% @doc List of ranch listeners running mtproto_proxy
-spec mtp_listeners() -> [{ranch:ref(), #{atom() => term()}}].
mtp_listeners() ->
    maps:to_list(
      maps:filter(
        fun(_Name, #{protocol := Protocol}) ->
                Protocol == mtp_handler
        end,
        ranch:info())).


%% @doc Currently running listeners in a form of proxy_port()
-spec running_ports() -> [proxy_port()].
running_ports() ->
    lists:map(
      fun({Name, #{protocol_options := ProtoOpts, ip := Ip, port := Port}}) ->
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

-spec get_port_secret(atom()) -> {ok, binary()} | not_found.
get_port_secret(Name) ->
    case [Secret
          || #{name := PortName, secret := Secret} <- application:get_env(?APP, ports, []),
             PortName == Name] of
        [Secret] ->
            {ok, Secret};
        _ ->
            not_found
    end.

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

maybe_connect_back_node() ->
    case application:get_env(?APP, back_node) of
        {ok, BackNode} ->
            connect_back_node(BackNode);
        undefined ->
            ?LOG_WARNING(
               "node_role=front but back_node is not configured; set {back_node, 'back@HOST'} "
               "in sys.config and start the back node first",
               [])
    end.

connect_back_node(BackNode) ->
    case net_kernel:connect_node(BackNode) of
        true ->
            ok;
        false ->
            ?LOG_WARNING(
               "Failed to connect front node ~p to back node ~p; listeners will keep running "
               "and the proxy will retry on demand. Check that the back node is running, "
               "back_node matches the back vm.args -name, -setcookie matches on both nodes, "
               "and TCP 4369 (epmd) plus the back vm.args -kernel inet_dist_listen_min/"
               "inet_dist_listen_max port (for example 9299) are reachable between the two "
               "servers; if you use a tunnel or TLS distribution, those settings must carry "
               "this same Erlang distribution connection successfully",
               [node(), BackNode])
    end.

config_changed(_, ip_lookup_services, _, front) -> ok;
config_changed(_, ip_lookup_services, _, _) ->
    mtp_config:update();
config_changed(_, proxy_secret_url, _, front) -> ok;
config_changed(_, proxy_secret_url, _, _) ->
    mtp_config:update();
config_changed(_, proxy_config_url, _, front) -> ok;
config_changed(_, proxy_config_url, _, _) ->
    mtp_config:update();
config_changed(Action, back_node, BackNode, front) when Action == new; Action == changed ->
    connect_back_node(BackNode);
config_changed(Action, max_connections, _, back) when Action == new; Action == changed -> ok;
config_changed(Action, max_connections, N, _) when Action == new; Action == changed ->
    (is_integer(N) and (N >= 0)) orelse error({"max_connections should be non_neg_integer", N}),
    lists:foreach(fun({Name, _}) ->
                          ranch:set_max_connections(Name, N)
                  end, mtp_listeners());
config_changed(Action, downstream_socket_buffer_size, _, front) when Action == new; Action == changed -> ok;
config_changed(Action, downstream_socket_buffer_size, N, _) when Action == new; Action == changed ->
    [{ok, _} = mtp_down_conn:set_config(Pid, downstream_socket_buffer_size, N)
     || Pid <- downstream_connections()],
    ok;
config_changed(Action, downstream_backpressure, _, front) when Action == new; Action == changed -> ok;
config_changed(Action, downstream_backpressure, BpOpts, _) when Action == new; Action == changed ->
    is_map(BpOpts) orelse error(invalid_downstream_backpressure),
    [{ok, _} = mtp_down_conn:set_config(Pid, downstream_backpressure, BpOpts)
     || Pid <- downstream_connections()],
    ok;
config_changed(Action, upstream_send_timeout_ms, TimeoutMs, _) when Action == new; Action == changed ->
    (is_integer(TimeoutMs) andalso TimeoutMs >= 0) orelse
        error({"upstream_send_timeout_ms should be non_neg_integer", TimeoutMs}),
    ok;
%% Since upstream connections are mostly short-lived, live-update doesn't make much difference
%% config_changed(Action, upstream_socket_buffer_size, N, _) when Action == new; Action == changed ->
config_changed(Action, ports, _, back) when Action == new; Action == changed -> ok;
config_changed(Action, ports, Ports, _) when Action == new; Action == changed ->
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
config_changed(Action, K, V, _) ->
    %% Most of the other config options are applied automatically without extra work
    ?LOG_INFO("Config ~p ~p to ~p ignored", [K, Action, V]),
    ok.

downstream_connections() ->
    [Pid || {_, Pid, worker, [mtp_down_conn]} <- supervisor:which_children(mtp_down_conn_sup)].

node_role() ->
    application:get_env(?APP, node_role, both).


build_urls(Host, Port, Secret, Protocols) ->
    MkUrl = fun(ProtoSecret) ->
                    io_lib:format(
                      "tg://proxy?server=~s&port=~w&secret=~s",
                      [Host, Port, ProtoSecret])
            end,
    UrlTypes = lists:usort(
                 lists:map(fun(mtp_abridged) -> normal;
                              (mtp_intermediate) -> normal;
                              (Other) -> Other
                           end, Protocols)),
    lists:map(
      fun(mtp_fake_tls) ->
              Domain = <<"s3.amazonaws.com">>,
              ProtoSecret = mtp_fake_tls:format_secret_hex(Secret, Domain),
              MkUrl(ProtoSecret);
         (mtp_secure) ->
              ProtoSecret = ["dd", Secret],
              MkUrl(ProtoSecret);
         (normal) ->
              MkUrl(Secret)
      end, UrlTypes).

-ifdef(TEST).
report(Fmt, Args) ->
    ?LOG_DEBUG(Fmt, Args).
-else.
report(Fmt, Args) ->
    io:format(Fmt ++ "\n", Args),
    ?LOG_INFO(Fmt, Args).
-endif.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

env_diff_test() ->
    Pre = [{a, 1},
           {b, 2},
           {c, 3}],
    Post = [{b, 2},
            {c, 4},
            {d, 5}],
    ?assertEqual(
       {[{c, 4}],
        [{d, 5}],
        [a]},
       diff_env(Post, Pre)).

-endif.
