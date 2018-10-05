%%%-------------------------------------------------------------------
%% @doc mtproto_proxy public API
%% @end
%%%-------------------------------------------------------------------

-module(mtproto_proxy_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, start_proxy/1]).
-define(APP, mtproto_proxy).

%%====================================================================
%% API
%%====================================================================
start(_StartType, _StartArgs) ->
    Res = mtproto_proxy_sup:start_link(),
    io:format("+++++++++++++++++++++++++++++++++++++++~n"
              "Erlang MTProto proxy by @seriyps https://github.com/seriyps/mtproto_proxy~n"
              "Sponsored by and powers @socksy_bot~n"),
    [start_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    Res.

%%--------------------------------------------------------------------
stop(_State) ->
    [stop_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
start_proxy(#{name := Name, port := Port, secret := Secret, tag := Tag} = P) ->
    ListenIpStr = maps:get(
                    listen_ip, P,
                    application:get_env(?APP, listen_ip, "0.0.0.0")),
    {ok, ListenIp} = inet:parse_ipv4_address(ListenIpStr),
    NumAcceptors = application:get_env(?APP, num_acceptors, 60),
    MaxConnections = application:get_env(?APP, max_connections, 10240),
    Res =
        ranch:start_listener(
          Name, ranch_tcp,
          [{ip, ListenIp},
           {port, Port},
           {num_acceptors, NumAcceptors},
           {max_connections, MaxConnections}],
          mtp_handler, [Name, Secret, Tag]),
    Url = io_lib:format(
            "https://t.me/proxy?server=~s&port=~w&secret=~s",
            [application:get_env(?APP, external_ip, ListenIpStr),
             Port, Secret]),
    io:format("Proxy started on ~s:~p with secret: ~s, tag: ~s~nUrl: ~s~n",
              [ListenIpStr, Port, Secret, Tag, Url]),
    Res.

stop_proxy(#{name := Name}) ->
    ranch:stop_listener(Name).
