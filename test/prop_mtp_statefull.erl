%% @doc Statefull property-based tests
-module(prop_mtp_statefull).
-export([prop_check_pooling/0,
         prop_check_pooling/1,
         initial_state/0,
         command/1,
         precondition/2,
         postcondition/3,
         next_state/3]).
-export([connect/2,
         echo_packet/2,
         ask_for_close/1,
         close/1]).
-export([gen_rpc_echo/3,
         gen_rpc_close/3]).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-record(st, {
          ever_opened = 0,
          open = [],
          closed = [],
          ask_for_close = [],
          n_packets = #{}
         }).

-define(PORT, 10800).
-define(SECRET, <<"d0d6e111bada5511fcce9584deadbeef">>).
-define(HOST, {127, 0, 0, 1}).
-define(DC_ID, 1).
-define(APP, mtproto_proxy).

prop_check_pooling(doc) ->
    "Check that connections and packets are 'accounted' correctly".

prop_check_pooling() ->
    ?FORALL(Cmds, commands(?MODULE), aggregate(command_names(Cmds), run_cmds(Cmds))).

initial_state() ->
    #st{}.

command(#st{open = [], ever_opened = EO}) ->
    {call, ?MODULE, connect, [EO, mtp_prop_gen:codec()]};
command(#st{open = L, ever_opened = EO}) ->
    proper_types:frequency(
      [
       {1, {call, ?MODULE, connect, [EO, proper_types:oneof(
                                           [mtp_prop_gen:codec(),
                                            {mtp_fake_tls, <<"en.wikipedia.org">>}])]}},
       {5, {call, ?MODULE, echo_packet, [proper_types:oneof(L), proper_types:binary()]}},
       {2, {call, ?MODULE, close, [proper_types:oneof(L)]}},
       {2, {call, ?MODULE, ask_for_close, [proper_types:oneof(L)]}}
      ]).

precondition(#st{open = L}, {call, ?MODULE, close, _}) ->
    length(L) > 0;
precondition(#st{open = L}, {call, ?MODULE, echo_packet, _}) ->
    length(L) > 0;
precondition(#st{open = L}, {call, ?MODULE, ask_for_close, _}) ->
    length(L) > 0;
precondition(_St, {call, _Mod, _Fun, _Args}) ->
    true.

%% Given the state `State' *prior* to the call `{call, Mod, Fun, Args}',
%% determine whether the result `Res' (coming from the actual system)
%% makes sense.
postcondition(_State, {call, ?MODULE, connect, _Args}, _Res) ->
    true;
postcondition(_State, {call, ?MODULE, close, _Args}, _Res) ->
    true;
postcondition(_State, {call, ?MODULE, ask_for_close, _Args}, _Res) ->
    true;
postcondition(_State, {call, ?MODULE, echo_packet, [_Conn, SendBin]}, RecvBin) ->
    ?assertEqual(SendBin, RecvBin),
    true;
postcondition(_State, {call, _Mod, _Fun, _Args}, _Res) ->
    false.

%% Assuming the postcondition for a call was true, update the model
%% accordingly for the test to proceed.
next_state(#st{open = L, ever_opened = EO} = St, _Res,
           {call, ?MODULE, connect, [ConnId, _Proto]}) ->
    St#st{open = [ConnId | L],
          ever_opened = EO + 1};
next_state(#st{open = L, closed = Cl} = St, _Res, {call, ?MODULE, close, [ConnId]}) ->
    St#st{open = lists:delete(ConnId, L),
          closed = [ConnId | Cl]};
next_state(#st{open = L, closed = Cl, ask_for_close = NA} = St, _Res,
           {call, ?MODULE, ask_for_close, [ConnId]}) ->
    St#st{open = lists:delete(ConnId, L),
          closed = [ConnId | Cl],
          ask_for_close = [ConnId | NA]};
next_state(#st{n_packets = N} = St, _Res, {call, ?MODULE, echo_packet, [ConnId, _]}) ->
    NForConn = maps:get(ConnId, N, 0),
    St#st{n_packets = N#{ConnId => NForConn + 1}};
next_state(State, _Res, {call, ?MODULE, _, _}) ->
    State.

run_cmds(Cmds) ->
    Cfg = setup(#{rpc_handler => mtp_test_cmd_rpc}),
    {History, State, Result} = run_commands(?MODULE, Cmds),
    %% Validate final states of proxy and "middle server"
    timer:sleep(100),
    ServerState = collect_server_state(Cfg),
    Metrics = collect_metrics(Cfg),
    ShimDump = shim_dump(),
    stop(Cfg),
    ?WHENFAIL(io:format("History: ~p\n"
                        "State: ~w\n"
                        "ServerState: ~p\n"
                        "Metrics: ~p\n"
                        "Result: ~p\n",
                        [History, State, ServerState, Metrics, Result]),
              proper:conjunction(
                [{state_ok, check_state(State, ServerState, Metrics, ShimDump)},
                 {result_ok, Result =:= ok}])).

%% Post-run checks. Assert that model's final state matches proxy and middle-server state
collect_server_state(Cfg) ->
    DcCfg = ?config(dc_conf, Cfg),
    Pids = mtp_test_datacenter:middle_connections(DcCfg),
    States = [mtp_test_middle_server:get_rpc_handler_state(Pid) || Pid <- Pids],
    %% io:format("~p~n", [States]),
    %% Can use just maps:merge/2 because connection IDs in different states will not overlap
    lists:foldl(fun maps:merge/2, #{}, States).

collect_metrics(_Cfg) ->
    GetTags = fun(Type, Name, Tags) ->
                      case mtp_test_metric:get_tags(Type, Name, Tags) of
                          not_found when Type == histogram -> {0, 0, 0, 0};
                          not_found -> 0;
                          Val -> Val
                      end
              end,
    #{in_connections => GetTags(count, [?APP, in_connection, total], [?MODULE]),
      closed_connections => GetTags(count, [?APP, in_connection_closed, total], [?MODULE]),
      tg_in_packet_size => GetTags(
                             histogram, [?APP, tg_packet_size, bytes], [upstream_to_downstream]),
      tg_out_packet_size => GetTags(
                             histogram, [?APP, tg_packet_size, bytes], [downstream_to_upstream])
     }.


check_state(#st{closed = ModClosed, n_packets = ModPackets, ask_for_close = ModAskClose,
                open = ModClients, ever_opened = ModOpened} = _St,
            SrvState, Metrics, ShimDump) ->
    %% io:format("~n~w~n~p~n~p~n~p~n", [St, SrvState, Metrics, ShimDump]),
    %% Assert shim is correct
    ?assertEqual(length(ModClients), map_size(ShimDump)),

    %% Total number of packets
    ModTotalPackets = maps:fold(fun(_K, N, Acc) -> Acc + N end, 0, ModPackets),
    SrvTotalPackets = maps:fold(fun({n_packets, _}, N, Acc) -> Acc + N;
                                   (_, _, Acc) -> Acc
                                end, 0, SrvState),
    ?assertEqual(ModTotalPackets, SrvTotalPackets),

    %% Number of connections that ever sent data RPC
    SrvConnsWithPackets = maps:fold(fun({n_packets, _}, _, Acc) -> Acc + 1;
                                       (_, _, Acc) -> Acc
                                    end, 0, SrvState),
    ?assertEqual(map_size(ModPackets), SrvConnsWithPackets),

    %% Number of sent data RPC per-connection
    ModSentPerConn = maps:values(ModPackets),
    SrvSentPerConn = maps:fold(fun({n_packets, _}, N, Acc) -> [N | Acc];
                                  (_, _, Acc) -> Acc
                               end, [], SrvState),
    ?assertEqual(lists:sort(ModSentPerConn), lists:sort(SrvSentPerConn)),

    %% Number of telegram packets send from client to server
    ModTgPackets = length(ModAskClose) + ModTotalPackets,
    ?assertMatch({ModTgPackets, _, _, _}, maps:get(tg_in_packet_size, Metrics)),

    %% Number of connections that were ever open
    %% Can be only asserted by metrics
    ?assertEqual(ModOpened, maps:get(in_connections, Metrics)),

    %% Number of connections that were closed
    SrvClosed = maps:fold(fun(_, tombstone, Acc) -> Acc + 1;
                             (_, _, Acc) -> Acc
                          end, 0, SrvState),
    ?assertEqual(length(ModClosed), SrvClosed),
    ?assertEqual(length(ModClosed), maps:get(closed_connections, Metrics)),

    %% Number of still open connections
    %% On middleproxy side, connection only started to be tracked if it sent any data.
    %% So, if we opened a connection and haven't sent anything, middle will not know about it
    MAlive = length(ordsets:intersection(
                      ordsets:from_list(ModClients),
                      ordsets:from_list(maps:keys(ModPackets)))),
    SrvAlive = maps:fold(fun(Id, Num, Acc) when is_integer(Id), is_integer(Num) -> Acc + 1;
                            (_, _, Acc) -> Acc
                         end, 0, SrvState),
    ?assertEqual(MAlive, SrvAlive),
    true.

%% Connect to proxy
connect(Id, Protocol) ->
    Conn = mtp_test_client:connect(?HOST, ?PORT, ?SECRET, ?DC_ID, Protocol),
    shim_add(Id, Conn),
    ok.

%% Send and receive back some binary data
echo_packet(Id, RandBin) ->
    Cli0 = shim_pop(Id),
    Req = mtp_test_cmd_rpc:call(?MODULE, gen_rpc_echo, RandBin),
    Cli1 = mtp_test_client:send(Req, Cli0),
    {ok, Res, Cli2} = mtp_test_client:recv_packet(Cli1, 1000),
    shim_add(Id, Cli2),
    mtp_test_cmd_rpc:packet_to_term(Res).

gen_rpc_echo(RandBin, ConnId, St) ->
    Key = {n_packets, ConnId},
    NPackets = maps:get(Key, St, 0),
    {reply, RandBin, St#{ConnId => 1,
                         Key => NPackets + 1}}.

%% Close from client-side
close(Id) ->
    Conn = shim_pop(Id),
    mtp_test_client:close(Conn).

%% Close from telegram-server side
ask_for_close(Id) ->
    Cli0 = shim_pop(Id),
    Req = mtp_test_cmd_rpc:call(?MODULE, gen_rpc_close, []),
    Cli1 = mtp_test_client:send(Req, Cli0),
    {error, closed} = mtp_test_client:recv_packet(Cli1, 1000),
    ok.

gen_rpc_close([], _ConnId, St) ->
    {close, St}.

-ifdef(OTP_RELEASE).
disable_log() ->
    logger:set_primary_config(level, critical).
-else.
disable_log() ->
    ok.
-endif.

%% Setup / teardown
setup(DcCfg0) ->
    application:ensure_all_started(lager),
    lager:set_loglevel(lager_console_backend, critical), %XXX lager-specific
    disable_log(),
    {ok, Pid} = mtp_test_metric:start_link(),
    PubKey = crypto:strong_rand_bytes(128),
    DcId = ?DC_ID,
    Ip = ?HOST,
    DcConf = [{DcId, Ip, ?PORT + 5}],
    Secret = ?SECRET,
    Listeners = [#{name => ?MODULE,
                   port => ?PORT,
                   listen_ip => inet:ntoa(Ip),
                   secret => Secret,
                   tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}],
    application:load(mtproto_proxy),
    Cfg1 = single_dc_SUITE:set_env([{ports, Listeners},
                                    {metric_backend, mtp_test_metric}], []),
    {ok, DcCfg} = mtp_test_datacenter:start_dc(PubKey, DcConf, DcCfg0),
    application:load(mtproto_proxy),
    {ok, _} = application:ensure_all_started(mtproto_proxy),
    shim_start(),
    [{dc_conf, DcCfg}, {metric, Pid} | Cfg1].

stop(Cfg) ->
    DcCfg = ?config(dc_conf, Cfg),
    MetricPid = ?config(metric, Cfg),
    ok = application:stop(mtproto_proxy),
    {ok, _} = mtp_test_datacenter:stop_dc(DcCfg),
    single_dc_SUITE:reset_env(Cfg),
    gen_server:stop(MetricPid),
    shim_stop(),
    Cfg.


%% Proces - wrapper holding client connections and states
shim_add(Id, Conn) ->
    ?MODULE ! {add, Id, Conn}.

shim_pop(Id) ->
    ?MODULE ! {pop, self(), Id},
    receive {conn, Conn} ->
            Conn
    end.

shim_dump() ->
    ?MODULE ! {dump, self()},
    receive {dump, Conns} ->
            Conns
    end.

shim_start() ->
    Pid = proc_lib:spawn_link(fun loop/0),
    register(?MODULE, Pid).

shim_stop() ->
    Pid = whereis(?MODULE),
    unregister(?MODULE),
    exit(Pid, normal).

loop() ->
    loop(#{}).


loop(Acc) ->
    receive
        {dump, From} ->
            From ! {dump, Acc},
            loop(Acc);
        {add, Id, Conn} ->
            false = maps:is_key(Id, Acc),
            loop(Acc#{Id => Conn});
        {pop, From, Id} ->
            {Conn, Acc1} = maps:take(Id, Acc),
            From ! {conn, Conn},
            loop(Acc1)
    end.
