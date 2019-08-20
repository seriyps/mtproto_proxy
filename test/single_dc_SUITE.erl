%% @doc Basic tests with only one telegram DC
-module(single_dc_SUITE).

-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2]).

-export([config_change_case/1,
         downstream_size_backpressure_case/1,
         downstream_qlen_backpressure_case/1,
         echo_secure_case/1,
         echo_abridged_many_packets_case/1,
         echo_tls_case/1,
         ipv6_connect_case/1,
         packet_too_large_case/1,
         policy_max_conns_case/1,
         policy_whitelist_case/1,
         replay_attack_case/1,
         replay_attack_server_error_case/1
        ]).

-export([set_env/2,
         reset_env/1]).

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
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
echo_secure_case({post, Cfg}) ->
    stop_single(Cfg);
echo_secure_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli2 = ping(Cli),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_ok, total], [?FUNCTION_NAME, mtp_secure])),
    ok = mtp_test_client:close(Cli2),
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
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
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


%% @doc tests that it's possible to connect and communicate using fake-tls protocol
echo_tls_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
echo_tls_case({post, Cfg}) ->
    stop_single(Cfg);
echo_tls_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, {mtp_fake_tls, <<"example.com">>}),
    Cli1 = ping(Cli0),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_ok, total], [?FUNCTION_NAME, mtp_secure_fake_tls])),
    ok = mtp_test_client:close(Cli1).


%% @doc test that client trying to send too big packets will be force-disconnected
packet_too_large_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
packet_too_large_case({post, Cfg}) ->
    stop_single(Cfg);
packet_too_large_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    ErrCount = fun(Tag) ->
                       mtp_test_metric:get_tags(count, [?APP, protocol_error, total], [?FUNCTION_NAME, Tag])
               end,
    OkPacket = binary:copy(<<0>>, 64),
    BigPacket = binary:copy(<<0>>, 1024 * 1024 + 1024),
    Protocols = [
                 {mtp_intermediate, intermediate_max_size},
                 {mtp_abridged, abridged_max_size}
                ],
    lists:foreach(
      fun({Protocol, Metric}) ->
              ?assertEqual(not_found, ErrCount(Metric), Protocol),
              Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, Protocol),
              Cli1 = mtp_test_client:send(OkPacket, Cli0),
              {ok, OkPacket, Cli2} = mtp_test_client:recv_packet(Cli1, 5000),
              Cli3 = mtp_test_client:send(BigPacket, Cli2),
              ?assertEqual({error, closed}, mtp_test_client:recv_packet(Cli3, 5000), Protocol),
              ?assertEqual(1, ErrCount(Metric), Protocol)
      end, Protocols).


%% @doc test downstream backpressure when size of non-acknowledged packets grows above threshold
downstream_size_backpressure_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{rpc_handler => mtp_test_cmd_rpc}, Cfg),
    %% Disable upstream healthchecks
    set_env([{upstream_healthchecks, []},
             {downstream_backpressure,
              #{bytes_total => 6 * 1024 * 1024,
                packets_total => 1000}}], Cfg1);
downstream_size_backpressure_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
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
             count, [?APP, down_backpressure, total], [DcId, bytes_total], 1, 5000)),
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
             count, [?APP, down_backpressure, total], [DcId, bytes_total],
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
    %% socket data packet;
    %% Disable upstream healthchecks
    Cfg1 = set_env([{downstream_socket_buffer_size, 1024},
                    {upstream_healthchecks, []},
                    {downstream_backpressure,
                     #{bytes_total => 50 * 1024 * 1024,
                       packets_total => 300}}], Cfg),
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{rpc_handler => mtp_test_cmd_rpc}, Cfg1);
downstream_qlen_backpressure_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
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
             count, [?APP, down_backpressure, total], [DcId, count_total], 1, 5000),
       sys:get_state(mtp_test_metric)),
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


%% @doc test mtproto_proxy_app:config_change/3
config_change_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
config_change_case({post, Cfg}) ->
    stop_single(Cfg);
config_change_case(Cfg) when is_list(Cfg) ->
    %% test "max_connections"
    MaxConnsBefore = [{Listener, proplists:get_value(max_connections, Opts)}
                      || {Listener, Opts} <- mtproto_proxy_app:mtp_listeners()],
    NewMaxConns = 10,
    ok = mtproto_proxy_app:config_change([{max_connections, NewMaxConns}], [], []),
    MaxConnsAfter = [{Listener, proplists:get_value(max_connections, Opts)}
                     || {Listener, Opts} <- mtproto_proxy_app:mtp_listeners()],
    ?assertNotEqual(MaxConnsBefore, MaxConnsAfter),
    ?assert(lists:all(fun({_Listener, MaxConns}) ->
                              MaxConns == NewMaxConns
                      end, MaxConnsAfter),
            MaxConnsAfter),

    %% test downstream_socket_buffer_size
    GetBufferSizes =
        fun() ->
                lists:map(
                  fun({_, Pid, worker, [mtp_down_conn]}) ->
                          %% This is hacky and may brake in future erlang releases
                          {links, Links} = process_info(Pid, links),
                          [Port] = [L || L <- Links, is_port(L)],
                          {ok, [{buffer, BufSize}]} = inet:getopts(Port, [buffer]),
                          {Pid, BufSize}
                  end, supervisor:which_children(mtp_down_conn_sup))
        end,
    BufSizesBefore = GetBufferSizes(),
    NewBufSize = 512,
    ok = mtproto_proxy_app:config_change([{downstream_socket_buffer_size, NewBufSize}], [], []),
    BufSizesAfter = GetBufferSizes(),
    ?assertNotEqual(BufSizesBefore, BufSizesAfter),
    ?assert(lists:all(fun({_Conn, BufSize}) ->
                              BufSize == NewBufSize
                      end, BufSizesAfter),
           BufSizesAfter),

    %% test ports
    PortsBefore = mtproto_proxy_app:running_ports(),
    ?assertMatch([#{name := _,
                    listen_ip := _,
                    port := _,
                    secret := _,
                    tag := _}], PortsBefore),
    ok = mtproto_proxy_app:config_change([{ports, []}], [], []),
    ?assertEqual([], mtproto_proxy_app:running_ports()),
    ok = mtproto_proxy_app:config_change([{ports, PortsBefore}], [], []),
    ?assertEqual(PortsBefore, mtproto_proxy_app:running_ports()),
    ok.


%% @doc test replay attack protection.
%% Attempts to connect with the same 1st 64-byte packet should be rejected.
replay_attack_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
replay_attack_case({post, Cfg}) ->
    stop_single(Cfg);
replay_attack_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Seed = crypto:strong_rand_bytes(58),
    ErrCount = fun() ->
                       mtp_test_metric:get_tags(
                         count, [?APP, protocol_error, total], [?FUNCTION_NAME, replay_session_detected])
               end,
    ?assertEqual(not_found, ErrCount()),
    Cli1 = mtp_test_client:connect(Host, Port, Seed, Secret, DcId, mtp_secure),
    _Cli1_1 = mtp_test_client:send(crypto:strong_rand_bytes(64), Cli1),
    ?assertEqual(not_found, ErrCount()),
    Cli2 = mtp_test_client:connect(Host, Port, Seed, Secret, DcId, mtp_secure),
    ?assertEqual(
       ok, mtp_test_metric:wait_for_value(
             count, [?APP, protocol_error, total], [?FUNCTION_NAME, replay_session_detected], 1, 5000),
       {mtp_session_storage:status(),
        sys:get_state(mtp_test_metric)}),
    ?assertEqual(1, ErrCount()),
    ?assertEqual({error, closed}, mtp_test_client:recv_packet(Cli2, 1000)).

%% @doc test replay attack protection.
%% Server error responses are not proxied
replay_attack_server_error_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
replay_attack_server_error_case({post, Cfg}) ->
    stop_single(Cfg);
replay_attack_server_error_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    ErrCount = fun() ->
                       mtp_test_metric:get_tags(
                         count, [?APP, protocol_error, total], [?FUNCTION_NAME, srv_error_filtered])
               end,
    ?assertEqual(not_found, ErrCount()),
    Cli1 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    %% Let TG server echo error packet back, but packet will be filtered
    _Cli2 = mtp_test_client:send(<<108, 254, 255, 255>>, Cli1),
    ?assertEqual(
       ok, mtp_test_metric:wait_for_value(
             count, [?APP, protocol_error, total], [?FUNCTION_NAME, srv_error_filtered], 1, 5000),
       {mtp_session_storage:status(),
        sys:get_state(mtp_test_metric)}),
    ?assertEqual(1, ErrCount()).

%% TODO: send a lot, not read, and then close - assert connection IDs are cleaned up

%% @doc Test that it's possible to connect and communicate via IPv6
ipv6_connect_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, "::1", 10000 + ?LINE, #{}, Cfg);
ipv6_connect_case({post, Cfg}) ->
    stop_single(Cfg);
ipv6_connect_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    ConnCount = fun() ->
                        mtp_test_metric:get_tags(
                          count, [?APP, in_connection, total], [?FUNCTION_NAME])
                end,
    ?assertEqual(not_found, ConnCount()),
    ?assertEqual(8, tuple_size(Host)),
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli1 = ping(Cli0),
    ok = mtp_test_client:close(Cli1),
    ?assertEqual(1, ConnCount()),
    ok = mtp_test_metric:wait_for_value(
           count, [?APP, in_connection_closed, total], [?FUNCTION_NAME], 1, 5000).


%% @doc Test "max_connections" policy
policy_max_conns_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    %% Allow max 2 connections from IP
    set_env([{policy, [{max_connections, [port_name, client_ipv4], 2}]}], Cfg1);
policy_max_conns_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
policy_max_conns_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    SureClose =
        fun(Cli) ->
                PreClosed =
                    mtp_test_metric:get_tags(
                      count, [?APP, in_connection_closed, total], [?FUNCTION_NAME]),
                ok = mtp_test_client:close(Cli),
                ok = mtp_test_metric:wait_for_value(
                       count, [?APP, in_connection_closed, total], [?FUNCTION_NAME], PreClosed + 1, 5000)
        end,
    Key = [?FUNCTION_NAME, mtp_policy:convert(client_ipv4, {127, 0, 0, 1})],
    %% Open 2 connections, make sure 3rd one will be rejected
    Cli10 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli11 = ping(Cli10),
    ?assertEqual(1, mtp_policy_counter:get(Key)),
    Cli20 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    _Cli21 = ping(Cli20),
    ?assertEqual(2, mtp_policy_counter:get(Key)),
    Cli31 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    ?assertError({badmatch, {error, closed}}, ping(Cli31)),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_error, total], [?FUNCTION_NAME, policy_error])),
    ?assertEqual(2, mtp_policy_counter:get(Key)),
    %% Close 1st connection and try to connect again. This should work.
    SureClose(Cli11),
    ?assertEqual(1, mtp_policy_counter:get(Key)),
    Cli40 = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    _Cli41 = ping(Cli40),
    ?assertEqual(2, mtp_policy_counter:get(Key)),
    ok.

%% @doc tests that connections to whitelistsed domains are allowed and not from the list disallowed
policy_whitelist_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    %% Allow max 2 connections from IP
    Domain = <<"allowed.example.com">>,
    ok = mtp_policy_table:add(domain_whitelist, tls_domain, Domain),
    set_env([{policy, [{in_table, tls_domain, domain_whitelist}]}],
            [{domain, Domain} | Cfg1]);
policy_whitelist_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
policy_whitelist_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Domain = ?config(domain, Cfg),
    Cli01 = mtp_test_client:connect(Host, Port, Secret, DcId,
                                    {mtp_fake_tls, Domain}),
    _Cli02 = ping(Cli01),
    ?assertError({badmatch, {error, closed}},
                 begin
                     Cli11 = mtp_test_client:connect(Host, Port, Secret, DcId,
                                                     {mtp_fake_tls, <<"not-", Domain/binary>>}),
                     ping(Cli11)
                 end),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_error, total], [?FUNCTION_NAME, policy_error])),
    ok.

%% Helpers

setup_single(Name, MtpPort, DcCfg0, Cfg) ->
    setup_single(Name, "127.0.0.1", MtpPort, DcCfg0, Cfg).

setup_single(Name, MtpIpStr, MtpPort, DcCfg0, Cfg) ->
    {ok, Pid} = mtp_test_metric:start_link(),
    PubKey = crypto:strong_rand_bytes(128),
    DcId = 1,
    DcConf = [{DcId, {127, 0, 0, 1}, MtpPort + 10}],
    Secret = mtp_handler:hex(crypto:strong_rand_bytes(16)),
    Listeners = [#{name => Name,
                   port => MtpPort,
                   listen_ip => MtpIpStr,
                   secret => Secret,
                   tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}],
    application:load(mtproto_proxy),
    Cfg1 = set_env([{ports, Listeners}], Cfg),
    {ok, DcCfg} = mtp_test_datacenter:start_dc(PubKey, DcConf, DcCfg0),
    {ok, _} = application:ensure_all_started(mtproto_proxy),
    {ok, MtpIp} = inet:parse_address(MtpIpStr),
    [{dc_id, DcId},
     {mtp_host, MtpIp},
     {mtp_port, MtpPort},
     {mtp_secret, Secret},
     {dc_conf, DcCfg},
     {metric, Pid}| Cfg1].

stop_single(Cfg) ->
    DcCfg = ?config(dc_conf, Cfg),
    MetricPid = ?config(metric, Cfg),
    ok = application:stop(mtproto_proxy),
    ok = application:unload(mtproto_proxy),
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
    case proplists:get_value(mtp_env, Cfg) of
        undefined ->
            [{mtp_env, OldEnv} | Cfg];
        L ->
            [{mtp_env, OldEnv ++ L} | Cfg]
    end.

reset_env(Cfg) ->
    OldEnv = ?config(mtp_env, Cfg),
    [case V of
         undefined ->
             application:unset_env(mtproto_proxy, K);
         {ok, Val} ->
             application:set_env(mtproto_proxy, K, Val)
     end || {K, V} <- OldEnv].

ping(Cli0) ->
    Data = crypto:strong_rand_bytes(64),
    Cli1 = mtp_test_client:send(Data, Cli0),
    {ok, Packet, Cli2} = mtp_test_client:recv_packet(Cli1, 1000),
    ?assertEqual(Data, Packet),
    Cli2.
