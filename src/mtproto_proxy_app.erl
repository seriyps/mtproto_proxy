%%%-------------------------------------------------------------------
%% @doc mtproto_proxy public API
%% @end
%%%-------------------------------------------------------------------

-module(mtproto_proxy_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).
-define(APP, mtproto_proxy).

%%====================================================================
%% API
%%====================================================================
start(_StartType, _StartArgs) ->
    Res = mtproto_proxy_sup:start_link(),
    [start_proxy(Where) || Where <- application:get_env(?APP, ports, [])],
    Res.

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

start_proxy({Name, Port}) ->
    ListenIp = application:get_env(?APP, ip, {0, 0, 0, 0}),
    NumAcceptors = application:get_env(?APP, num_acceptors, 60),
    MaxConnections = application:get_env(?APP, max_connections, 1024),
    Res = {ok, Pid} =
        ranch:start_listener(
          Name, ranch_tcp,
          [{ip, ListenIp},
           {port, Port},
           {num_acceptors, NumAcceptors},
           {max_connections, MaxConnections}],
          mtp_handler, []),
    KeyStr = mtp_handler:key_str(),
    io:format("+++++++++++++++++++++++++++++++++++++++~n"
              "Erlang MTProto proxy by @seriyps https://github.com/seriyps/mtproto_proxy~n"
              "Sponsored by and powers @socksy_bot~n"
              "Proxy started on ~s:~p with key: ~s~n~n"
              "+++++++++++++++++++++++++++++++++++++++~n",
              [inet:ntoa(ListenIp), Port, KeyStr]),
    lager:info("mtproto=~p listening on addr=~s:~p with key ~s",
               [Pid, inet:ntoa(ListenIp), Port, KeyStr]),
    Res.
