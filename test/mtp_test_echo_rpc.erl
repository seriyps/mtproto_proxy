%% @doc simple callback module for mtp_test_middle_server that echoes received packets back
-module(mtp_test_echo_rpc).
-export([init/1,
         handle_rpc/2]).

init(_) ->
    #{}.

handle_rpc({data, ConnId, Data}, St) ->
    Cnt = maps:get(ConnId, St, 0),
    {rpc, {proxy_ans, ConnId, Data}, St#{ConnId => Cnt + 1}};
handle_rpc({remote_closed, ConnId}, St) ->
    is_integer(maps:get(ConnId, St))
        orelse error({unexpected_closed, ConnId}),
    {noreply, St#{ConnId := tombstone}}.
