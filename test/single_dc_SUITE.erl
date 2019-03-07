%% @doc Basic tests with only one telegram DC
-module(single_dc_SUITE).

-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2]).

-export([echo_secure_case/1,
         echo_abridged_many_packets_case/1,
         downstream_size_backpressure_case/1,
         downstream_qlen_backpressure_case/1
        ]).

-export([gen_rpc_replies/3]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-define(APP, mtproto_proxy).

-define(KB(N), N * 1024).
-define(MB(N), ?KB(N) * 1024).

all() ->
    %% All exported functions of arity 1 whose name ends with "_case"
    Exports = ?MODULE:module_info(exports),
    [F
     || {F, A} <- Exports,
        A == 1,
        case lists:reverse(atom_to_list(F)) of
            "esac_" ++ _ -> true;
            _ -> false
        end].

init_per_suite(Cfg) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ranch),
    Cfg.

end_per_suite(Cfg) ->
    Cfg.

init_per_testcase(Name, Cfg) ->
    ?MODULE:Name({pre, Cfg}).

end_per_testcase(Name, Cfg) ->
    ?MODULE:Name({post, Cfg}).

%% @doc Send single packet and receive it back
echo_secure_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, ?LINE, #{}, Cfg);
echo_secure_case({post, Cfg}) ->
    stop_single(Cfg);
echo_secure_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Data = crypto:strong_rand_bytes(64),
    Cli1 = mtp_test_client:send(Data, Cli),
    {ok, Packet, Cli2} = mtp_test_client:recv_packet(Cli1, 1000),
    ok = mtp_test_client:close(Cli2),
    ?assertEqual(Data, Packet),
    ok = mtp_test_metric:wait_for_value(
           count, [?APP, in_connection_closed, total], [?FUNCTION_NAME], 1, 5000),
    ?assertEqual(1, mtp_test_metric:get_tags(
                      count, [?APP, in_connection, total], [?FUNCTION_NAME])),
    ?assertEqual({1, 64, 64, 64},
                 mtp_test_metric:get_tags(
                   histogram, [?APP, tg_packet_size, bytes],
                   [upstream_to_downstream])),
    ?assertMatch({1, _, _, _},                  % larger because of RPC headers
                 mtp_test_metric:get_tags(
                   histogram, [?APP, tg_packet_size, bytes],
                   [downstream_to_upstream])).

%% @doc Send many packets and receive them back
echo_abridged_many_packets_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, ?LINE, #{}, Cfg);
echo_abridged_many_packets_case({post, Cfg}) ->
    stop_single(Cfg);
echo_abridged_many_packets_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    NPackets = 15,
    Packets =
        [crypto:strong_rand_bytes(4 * rand:uniform(50))
         || _ <- lists:seq(1, NPackets)],
    Cli2 = lists:foldl(fun mtp_test_client:send/2, Cli0, Packets),
    %% Wait until all packets will be sent by proxy (this actually can fail if buffers are full)
    ok = mtp_test_metric:wait_for(
           histogram, [?APP, upstream_send_duration, seconds], [?FUNCTION_NAME],
           fun({Cnt, _, _, _}) -> Cnt == NPackets; (not_found) -> false end, 5000),
    {ok, RecvPackets, Cli} = mtp_test_client:recv_all(Cli2, 1000),
    ok = mtp_test_client:close(Cli),
    ?assertEqual(Packets, RecvPackets),
    ?assertEqual({NPackets,                                              %total count
                  iolist_size(Packets),                                  %total sum
                  lists:min(lists:map(fun erlang:byte_size/1, Packets)), %min
                  lists:max(lists:map(fun erlang:byte_size/1, Packets))  %max
                 },
                 mtp_test_metric:get_tags(
                   histogram, [?APP, tg_packet_size, bytes],
                   [upstream_to_downstream])).


%% @doc test downstream backpressure when size of non-acknowledged packets grows above threshold
downstream_size_backpressure_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, ?LINE, #{rpc_handler => mtp_test_cmd_rpc}, Cfg),
    %% Disable upstream healthchecks
    application:set_env(?APP, upstream_healthchecks, []),
    Cfg1;
downstream_size_backpressure_case({post, Cfg}) ->
    stop_single(Cfg);
downstream_size_backpressure_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),

    %% Backpressure by size limit is defined in mtp_down_conn.erl:?MAX_NON_ACK_BYTES
    BPressureThreshold = ?MB(6),
    PacketSize = ?KB(400),
    NPackets = 4 * BPressureThreshold div PacketSize,
    Packet = crypto:strong_rand_bytes(PacketSize),
    Req = mtp_test_cmd_rpc:call(?MODULE, gen_rpc_replies,
                                #{packet => Packet, n => NPackets}),
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli1 = mtp_test_client:send(Req, Cli0),
    %% Wait for backpressure-in
    ?assertEqual(
       ok, mtp_test_metric:wait_for_value(
             count, [?APP, down_backpressure, total], [DcId, bytes], 1, 5000)),
    %% Upstream healthcheck should be disabled, otherwise it can interfere
    ?assertEqual(not_found,
                 mtp_test_metric:get_tags(
                   count, [?APP, healthcheck, total], [total_memory])),
    %% No backpressure-out, because we don't read any data
    ?assertEqual(not_found,
                 mtp_test_metric:get_tags(
                   count, [?APP, down_backpressure, total], [DcId, off])),
    %% Amount of bytes received by proxy will be bigger than amount sent to upstreams
    TgToProxy =
        mtp_test_metric:get_tags(
          count, [?APP, received, downstream, bytes], [DcId]),
    ProxyToClient =
        mtp_test_metric:get_tags(
          count, [?APP, sent, upstream, bytes], [?FUNCTION_NAME]),
    ?assert(TgToProxy > ProxyToClient),
    %% Read some data to release backpressure
    {ok, _RecvPackets, Cli2} = mtp_test_client:recv_all(Cli1, 1000),
    ?assertEqual(
       ok, mtp_test_metric:wait_for(
             count, [?APP, down_backpressure, total], [DcId, bytes],
             fun(V) -> is_integer(V) and (V > 0) end, 5000)),
    ok = mtp_test_client:close(Cli2),
    %% ct:pal("t->p ~p; p->c ~p; diff ~p",
    %%        [TgToProxy, ProxyToClient, TgToProxy - ProxyToClient]),
    %% [{_, Pid, _, _}] = supervisor:which_children(mtp_down_conn_sup),
    %% ct:pal("Down conn state: ~p", [sys:get_state(Pid)]),
    %% ct:pal("Metric: ~p", [sys:get_state(mtp_test_metric)]),
    ok.


%% @doc test downstream backpressure when count of non-acknowledged packets grows above threshold
downstream_qlen_backpressure_case({pre, Cfg}) ->
    application:load(mtproto_proxy),
    %% Reducing downstream socket buffer size. Otherwise we can get queue overflow from just single
    %% socket data packet
    application:set_env(mtproto_proxy, downstream_socket_buffer_size, 1024),
    Cfg1 = setup_single(?FUNCTION_NAME, ?LINE, #{rpc_handler => mtp_test_cmd_rpc}, Cfg),
    %% Disable upstream healthchecks
    application:set_env(?APP, upstream_healthchecks, []),
    Cfg1;
downstream_qlen_backpressure_case({post, Cfg}) ->
    stop_single(Cfg);
downstream_qlen_backpressure_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),

    SizeThreshold = ?MB(6),
    CountThreshold = 300,
    PacketSize = SizeThreshold div CountThreshold - 4048,
    PacketSizeAligned = PacketSize - (PacketSize rem 4),
    NPackets = 10 * CountThreshold,
    Packet = crypto:strong_rand_bytes(PacketSizeAligned),
    Req = mtp_test_cmd_rpc:call(?MODULE, gen_rpc_replies,
                                #{packet => Packet, n => NPackets}),
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli1 = mtp_test_client:send(Req, Cli0),
    %% Wait for backpressure-in
    ?assertEqual(
       ok, mtp_test_metric:wait_for_value(
             count, [?APP, down_backpressure, total], [DcId, count], 1, 5000)),
    %% Close connection to release backpressure
    ok = mtp_test_client:close(Cli1),
    ?assertEqual(
       ok, mtp_test_metric:wait_for_value(
             count, [?APP, in_connection_closed, total], [?FUNCTION_NAME], 1, 5000)),
    ?assertEqual(
       ok, mtp_test_metric:wait_for(
             count, [?APP, down_backpressure, total], [DcId, off],
             fun(V) -> is_integer(V) and (V > 0) end, 5000)),
    %% [{_, Pid, _, _}] = supervisor:which_children(mtp_down_conn_sup),
    %% ct:pal("Down conn state: ~p", [sys:get_state(Pid)]),
    %% ct:pal("Metric: ~p", [sys:get_state(mtp_test_metric)]),
    ok.


gen_rpc_replies(#{packet := Packet, n := N}, ConnId, St) ->
    Rpcs = [{proxy_ans, ConnId, Packet} || _ <- lists:seq(1, N)],
    {return, {rpc_multi, Rpcs, St#{ConnId => 1}}}.

%% TODO: send a lot, not read, and then close - assert connection IDs are cleaned up

%% Helpers

setup_single(Name, Offset, DcCfg0, Cfg) ->
    {ok, Pid} = mtp_test_metric:start_link(),
    PubKey = crypto:strong_rand_bytes(128),
    DcId = 1,
    Ip = {127, 0, 0, 1},
    DcConf = [{DcId, Ip, 10000 + Offset}],
    MtpPort = 10000 + Offset + 1,
    Secret = mtp_handler:hex(crypto:strong_rand_bytes(16)),
    Listeners = [#{name => Name,
                   port => MtpPort,
                   listen_ip => "127.0.0.1",
                   secret => Secret,
                   tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}],
    application:load(mtproto_proxy),
    Cfg1 = set_env([{ports, Listeners}], Cfg),
    {ok, DcCfg} = mtp_test_datacenter:start_dc(PubKey, DcConf, DcCfg0),
    application:load(mtproto_proxy),
    {ok, _} = application:ensure_all_started(mtproto_proxy),
    [{dc_id, DcId},
     {mtp_host, Ip},
     {mtp_port, MtpPort},
     {mtp_secret, Secret},
     {dc_conf, DcCfg},
     {metric, Pid}| Cfg1].

stop_single(Cfg) ->
    DcCfg = ?config(dc_conf, Cfg),
    MetricPid = ?config(metric, Cfg),
    ok = application:stop(mtproto_proxy),
    {ok, _} = mtp_test_datacenter:stop_dc(DcCfg),
    gen_server:stop(MetricPid),
    Cfg.


set_env(Env, Cfg) ->
    OldEnv =
        [begin
             %% OldV is undefined | {ok, V}
             OldV = application:get_env(mtproto_proxy, K),
             case V of
                 undefined -> application:unset_env(mtproto_proxy, K);
                 _ ->
                     application:set_env(mtproto_proxy, K, V)
             end,
             {K, OldV}
         end || {K, V} <- Env],
    [{mtp_env, OldEnv} | Cfg].

%% reset_env(Cfg) ->
%%     OldEnv = ?config(mtp_env, Cfg),
%%     [case V of
%%          undefined ->
%%              application:unset_env(mtproto_proxy, K);
%%          {ok, Val} ->
%%              application:set_env(mtproto_proxy, K, Val)
%%      end || {K, V} <- OldEnv].
