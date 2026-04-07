%% @doc rpc_handler for mtp_test_middle_server that echoes packets and reports
%% each one to a registered process named `mtp_test_rpc_sink'.
%% The report message is `{rpc_from, self(), ConnId, Data}', where `self()' is
%% the mtp_test_middle_server Ranch connection pid — useful for tests that need
%% to identify which DC connection a client is multiplexed on and close it.
-module(mtp_test_reporter_rpc).
-export([init/1,
         handle_rpc/2]).

init(_) ->
    #{}.

handle_rpc({data, ConnId, Data}, St) ->
    mtp_test_rpc_sink ! {rpc_from, self(), ConnId, Data},
    {rpc, {proxy_ans, ConnId, Data}, St};
handle_rpc({remote_closed, ConnId}, St) ->
    {noreply, St#{ConnId => closed}}.
