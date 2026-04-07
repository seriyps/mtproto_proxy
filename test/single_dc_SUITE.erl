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
         echo_tls_long_hello_case/1,
         ipv6_connect_case/1,
         packet_too_large_case/1,
         policy_max_conns_case/1,
         policy_whitelist_case/1,
         replay_attack_case/1,
         replay_attack_server_error_case/1,
         domain_fronting_fixed_case/1,
         domain_fronting_off_case/1,
         domain_fronting_blacklist_case/1,
         domain_fronting_fragmented_case/1,
         domain_fronting_replay_case/1,
         per_sni_secrets_on_case/1,
         per_sni_secrets_wrong_secret_case/1,
         malformed_tls_hello_decode_error_case/1
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


%% @doc Test TLS handshake with long ClientHello (2000 bytes) to simulate newer Telegram clients
echo_tls_long_hello_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
echo_tls_long_hello_case({post, Cfg}) ->
    stop_single(Cfg);
echo_tls_long_hello_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    %% Test with 2000-byte ClientHello (newer Telegram clients send longer packets)
    Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId, {mtp_fake_tls, <<"example.com">>, 2000}),
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
    MaxConnsBefore = [{Listener, maps:get(max_connections, Opts)}
                      || {Listener, Opts} <- mtproto_proxy_app:mtp_listeners()],
    NewMaxConns = 10,
    ok = mtproto_proxy_app:config_change([{max_connections, NewMaxConns}], [], []),
    MaxConnsAfter = [{Listener, maps:get(max_connections, Opts)}
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
                timer:sleep(500),               %FIXME: sometimes metric returns not_found
                PreClosed =
                    case mtp_test_metric:get_tags(
                      count, [?APP, in_connection_closed, total], [?FUNCTION_NAME]) of
                        not_found -> 0;
                        N -> N
                    end,
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

%% @doc Domain fronting: wrong secret + fixed target -> connection forwarded to fronting host.
%% The proxy should transparently relay the raw ClientHello to the configured target
%% instead of closing the connection.
domain_fronting_fixed_case({pre, Cfg}) ->
    {ok, FrontLSock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, FrontPort} = inet:port(FrontLSock),
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    Cfg2 = set_env([{domain_fronting, "127.0.0.1:" ++ integer_to_list(FrontPort)}], Cfg1),
    [{front_lsock, FrontLSock} | Cfg2];
domain_fronting_fixed_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg),
    gen_tcp:close(?config(front_lsock, Cfg));
domain_fronting_fixed_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    FrontLSock = ?config(front_lsock, Cfg),
    WrongSecret = crypto:strong_rand_bytes(16),
    Domain = <<"example.com">>,
    ClientHello = mtp_fake_tls:make_client_hello(WrongSecret, Domain),
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}], 2000),
    ok = gen_tcp:send(Sock, ClientHello),
    %% Proxy should connect to our fronting server and forward the ClientHello
    {ok, FrontSock} = gen_tcp:accept(FrontLSock, 5000),
    {ok, Received} = gen_tcp:recv(FrontSock, byte_size(ClientHello), 5000),
    ?assertEqual(ClientHello, Received),
    %% Relay works both ways: send data from front -> client
    FrontReply = <<"HTTP/1.1 200 OK\r\n\r\n">>,
    ok = gen_tcp:send(FrontSock, FrontReply),
    {ok, ClientReceived} = gen_tcp:recv(Sock, byte_size(FrontReply), 5000),
    ?assertEqual(FrontReply, ClientReceived),
    gen_tcp:close(FrontSock),
    gen_tcp:close(Sock).

%% @doc Domain fronting disabled (off): wrong secret -> connection is closed, not forwarded.
domain_fronting_off_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
domain_fronting_off_case({post, Cfg}) ->
    stop_single(Cfg);
domain_fronting_off_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    WrongSecret = crypto:strong_rand_bytes(16),
    Domain = <<"example.com">>,
    ClientHello = mtp_fake_tls:make_client_hello(WrongSecret, Domain),
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}], 2000),
    ok = gen_tcp:send(Sock, ClientHello),
    %% Proxy must close the connection (fronting is off)
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 5000)),
    gen_tcp:close(Sock).

%% @doc Domain fronting with blacklisted SNI: connection must be closed, not forwarded.
domain_fronting_blacklist_case({pre, Cfg}) ->
    {ok, FrontLSock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, FrontPort} = inet:port(FrontLSock),
    BlacklistedDomain = <<"blocked.example.com">>,
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    ok = mtp_policy_table:add(df_blacklist, tls_domain, BlacklistedDomain),
    Cfg2 = set_env([{domain_fronting, "127.0.0.1:" ++ integer_to_list(FrontPort)},
                    {policy, [{not_in_table, tls_domain, df_blacklist}]}], Cfg1),
    [{front_lsock, FrontLSock}, {blacklisted_domain, BlacklistedDomain} | Cfg2];
domain_fronting_blacklist_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg),
    gen_tcp:close(?config(front_lsock, Cfg));
domain_fronting_blacklist_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    FrontLSock = ?config(front_lsock, Cfg),
    BlacklistedDomain = ?config(blacklisted_domain, Cfg),
    WrongSecret = crypto:strong_rand_bytes(16),
    ClientHello = mtp_fake_tls:make_client_hello(WrongSecret, BlacklistedDomain),
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}], 2000),
    ok = gen_tcp:send(Sock, ClientHello),
    %% Proxy must close the connection (domain is blacklisted)
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 5000)),
    %% Fronting server must NOT have received a connection
    ?assertEqual({error, timeout}, gen_tcp:accept(FrontLSock, 500)),
    gen_tcp:close(Sock).

%% @doc Domain fronting with fragmented ClientHello: proxy must still extract SNI and forward.
%% ClientHello is split into two sends to simulate fragmented TCP delivery.
domain_fronting_fragmented_case({pre, Cfg}) ->
    {ok, FrontLSock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, FrontPort} = inet:port(FrontLSock),
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    Cfg2 = set_env([{domain_fronting, "127.0.0.1:" ++ integer_to_list(FrontPort)}], Cfg1),
    [{front_lsock, FrontLSock} | Cfg2];
domain_fronting_fragmented_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg),
    gen_tcp:close(?config(front_lsock, Cfg));
domain_fronting_fragmented_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    FrontLSock = ?config(front_lsock, Cfg),
    WrongSecret = crypto:strong_rand_bytes(16),
    Domain = <<"example.com">>,
    ClientHello = mtp_fake_tls:make_client_hello(WrongSecret, Domain),
    %% Split at byte 10 (middle of TLS record header) to simulate TCP fragmentation.
    %% {nodelay, true} disables Nagle's algorithm so each send() produces a distinct segment.
    SplitAt = 10,
    <<Part1:SplitAt/binary, Part2/binary>> = ClientHello,
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}, {nodelay, true}], 2000),
    ok = gen_tcp:send(Sock, Part1),
    timer:sleep(50),
    ok = gen_tcp:send(Sock, Part2),
    %% Proxy must reassemble and still front us
    {ok, FrontSock} = gen_tcp:accept(FrontLSock, 5000),
    {ok, Received} = gen_tcp:recv(FrontSock, byte_size(ClientHello), 5000),
    ?assertEqual(ClientHello, Received),
    gen_tcp:close(FrontSock),
    gen_tcp:close(Sock).

%% @doc Replay attack: same TLS seed used twice -> replay_session_detected -> domain fronting.
%% The fronting server should receive a connection whose data starts with a TLS record.
domain_fronting_replay_case({pre, Cfg}) ->
    {ok, FrontLSock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, FrontPort} = inet:port(FrontLSock),
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    Cfg2 = set_env([{domain_fronting, "127.0.0.1:" ++ integer_to_list(FrontPort)}], Cfg1),
    [{front_lsock, FrontLSock} | Cfg2];
domain_fronting_replay_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg),
    gen_tcp:close(?config(front_lsock, Cfg));
domain_fronting_replay_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    FrontLSock = ?config(front_lsock, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Domain = <<"example.com">>,
    %% Build a deterministic ClientHello so we can replay it byte-for-byte
    Timestamp = erlang:system_time(second),
    SessionId = crypto:strong_rand_bytes(32),
    ClientHello = mtp_fake_tls:make_client_hello(Timestamp, SessionId, Secret, Domain),
    %% First connection: ClientHello digest not yet in storage → stored, ServerHello sent
    {ok, Sock1} = gen_tcp:connect(Host, Port, [binary, {active, false}], 2000),
    ok = gen_tcp:send(Sock1, ClientHello),
    {ok, _ServerHello} = gen_tcp:recv(Sock1, 0, 3000),
    gen_tcp:close(Sock1),
    timer:sleep(50),
    %% Second connection: same ClientHello → replay_session_detected fires BEFORE ServerHello.
    %% Send it fragmented with {nodelay, true} to cover the fragmentation+replay path.
    SplitAt = 10,
    <<Part1:SplitAt/binary, Part2/binary>> = ClientHello,
    {ok, Sock2} = gen_tcp:connect(Host, Port, [binary, {active, false}, {nodelay, true}], 2000),
    ok = gen_tcp:send(Sock2, Part1),
    timer:sleep(50),
    ok = gen_tcp:send(Sock2, Part2),
    %% Fronting server must accept — proxy forwards the ClientHello without sending a ServerHello
    {ok, FrontSock} = gen_tcp:accept(FrontLSock, 5000),
    {ok, Data} = gen_tcp:recv(FrontSock, 0, 5000),
    %% Data forwarded is the raw TLS ClientHello (0x16 = TLS handshake record)
    ?assertMatch(<<16#16, _/binary>>, Data),
    %% Proxy must NOT have sent a ServerHello to the client
    ?assertEqual({error, timeout}, gen_tcp:recv(Sock2, 0, 200)),
    gen_tcp:close(FrontSock),
    gen_tcp:close(Sock2).

%% @doc per_sni_secrets=on: client connecting with a correctly-derived secret succeeds.
per_sni_secrets_on_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    set_env([{per_sni_secrets, on}], Cfg1);
per_sni_secrets_on_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
per_sni_secrets_on_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    RawSecret = mtp_handler:unhex(?config(mtp_secret, Cfg)),
    Domain = <<"example.com">>,
    Salt = application:get_env(mtproto_proxy, per_sni_secret_salt,
                               <<"mtproto-proxy-per-sni-v1">>),
    DerivedSecret = mtp_fake_tls:derive_sni_secret(RawSecret, Domain, Salt),
    DerivedSecretHex = mtp_handler:hex(DerivedSecret),
    Cli0 = mtp_test_client:connect(Host, Port, DerivedSecretHex, DcId,
                                   {mtp_fake_tls, Domain}),
    Cli1 = ping(Cli0),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_ok, total], [?FUNCTION_NAME, mtp_secure_fake_tls])),
    ok = mtp_test_client:close(Cli1).

%% @doc per_sni_secrets=on: client connecting with the raw base secret is rejected.
per_sni_secrets_wrong_secret_case({pre, Cfg}) ->
    Cfg1 = setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg),
    set_env([{per_sni_secrets, on}], Cfg1);
per_sni_secrets_wrong_secret_case({post, Cfg}) ->
    stop_single(Cfg),
    reset_env(Cfg);
per_sni_secrets_wrong_secret_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    %% Using the raw base secret (not derived) must be rejected.
    ?assertError({badmatch, {error, closed}},
                 begin
                     Cli0 = mtp_test_client:connect(Host, Port, Secret, DcId,
                                                    {mtp_fake_tls, <<"example.com">>}),
                     ping(Cli0)
                 end),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_error, total], [?FUNCTION_NAME, tls_invalid_digest])).

%% @doc A structurally malformed ClientHello (ExtensionsLen=0 but data follows) must cause
%% the proxy to send a TLS fatal decode_error alert and then close the connection,
%% rather than crashing silently.
malformed_tls_hello_decode_error_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, 10000 + ?LINE, #{}, Cfg);
malformed_tls_hello_decode_error_case({post, Cfg}) ->
    stop_single(Cfg);
malformed_tls_hello_decode_error_case(Cfg) when is_list(Cfg) ->
    Host = ?config(mtp_host, Cfg),
    Port = ?config(mtp_port, Cfg),
    %% Build a ClientHello that is structurally valid at the TLS record layer
    %% (correct lengths, version bytes) but lies about ExtensionsLen=0 while
    %% trailing bytes follow — this is the exact pattern seen from real scanners.
    TlsPacketLen = 512,
    HelloLen = 508,          % TlsPacketLen - 4 (hello type + hello len field)
    Random = crypto:strong_rand_bytes(32),
    SessId = crypto:strong_rand_bytes(32),
    CipherSuites = <<19, 1>>,              % TLS_AES_128_GCM_SHA256, 2 bytes
    %% Padding fills the rest of the TLS frame after ExtensionsLen to hit TlsPacketLen exactly.
    %% Consumed so far inside the frame: hello_type(1)+hello_len(3)+version(2)+random(32)
    %%   +sessid_len(1)+sessid(32)+cs_len(2)+cs(2)+comp_len(1)+comp(1)+ext_len(2) = 79
    PaddingLen = TlsPacketLen - 79,
    Padding = binary:copy(<<0>>, PaddingLen),
    MalformedHello = <<22, 3, 1, TlsPacketLen:16,     % TLS record header (handshake, TLS1.0)
                       1, HelloLen:24,                  % ClientHello type + length
                       3, 3,                            % legacy version (TLS1.2)
                       Random/binary,                   % 32-byte random
                       32, SessId/binary,               % session ID
                       2:16, CipherSuites/binary,       % cipher suites
                       1, 0,                            % compression methods
                       0:16,                            % ExtensionsLen = 0 (lie)
                       Padding/binary>>,                % trailing bytes that should be extensions
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}], 2000),
    ok = gen_tcp:send(Sock, MalformedHello),
    %% Proxy must send back a TLS fatal decode_error alert (21, 3, 3, 0, 2, 2, 50)
    ExpectedAlert = mtp_fake_tls:tls_decode_error_alert(),
    {ok, Response} = gen_tcp:recv(Sock, byte_size(ExpectedAlert), 5000),
    ?assertEqual(ExpectedAlert, Response),
    %% Then close the connection
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 2000)),
    gen_tcp:close(Sock),
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_error, total], [?FUNCTION_NAME, tls_bad_client_hello])).

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
