%% @doc Tests for split-mode (front/back node) distributed setup.
%%
%% The CT node acts as the front node (Ranch listener + mtp_handler).
%% A peer node started with the `peer' module acts as the back node
%% (mtp_config + DC pool + mtp_down_conn).
%%
%% Both nodes run on the same host so 127.0.0.1 is reachable from both sides.
%% The fake telegram datacenter (HTTP config server + middle server) runs on
%% the CT node, which is fine because the back node can reach 127.0.0.1.
-module(split_dc_SUITE).

-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2]).

-export([echo_split_case/1,
         migration_split_case/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(APP, mtproto_proxy).

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
    %% peer:start_link requires the current node to be distributed.
    %% Start EPMD daemon first (no-op if already running), then enable
    %% distribution if rebar3 ct didn't already do so.
    os:cmd("epmd -daemon"),
    Distributed =
        case net_kernel:start([split_dc_test, shortnames]) of
            {ok, _}                       -> true;
            {error, {already_started, _}} -> false
        end,
    [{started_distribution, Distributed} | Cfg].

end_per_suite(Cfg) ->
    case ?config(started_distribution, Cfg) of
        true  -> net_kernel:stop();
        false -> ok
    end,
    Cfg.

init_per_testcase(Name, Cfg) ->
    ?MODULE:Name({pre, Cfg}).

end_per_testcase(Name, Cfg) ->
    ?MODULE:Name({post, Cfg}).

%%====================================================================
%% Test cases
%%====================================================================

%% @doc Full echo through a split front/back setup using mtp_secure protocol.
%% Verifies that data flows end-to-end across the distributed nodes and that
%% the front-node metrics are recorded correctly.
echo_split_case({pre, Cfg}) ->
    setup_split(?FUNCTION_NAME, 13000 + ?LINE, #{}, Cfg);
echo_split_case({post, Cfg}) ->
    stop_split(Cfg);
echo_split_case(Cfg) when is_list(Cfg) ->
    DcId   = ?config(dc_id, Cfg),
    Host   = ?config(mtp_host, Cfg),
    Port   = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli  = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
    Cli2 = ping(Cli),
    %% Front-node metrics: protocol negotiated and connection counted.
    ?assertEqual(
       1, mtp_test_metric:get_tags(
            count, [?APP, protocol_ok, total], [?FUNCTION_NAME, mtp_secure])),
    ok = mtp_test_client:close(Cli2),
    ok = mtp_test_metric:wait_for_value(
           count, [?APP, in_connection_closed, total], [?FUNCTION_NAME], 1, 5000),
    ok.

%% @doc Client survives a DC connection rotation in split mode.
%% mtp_handler (front node) migrates the client to a surviving DC connection
%% on the back node. The migration metric is emitted by mtp_handler, so it
%% is checked locally on the CT (front) node.
migration_split_case({pre, Cfg}) ->
    setup_split(?FUNCTION_NAME, 13000 + ?LINE,
                #{init_dc_connections => 2, rpc_handler => mtp_test_reporter_rpc}, Cfg);
migration_split_case({post, Cfg}) ->
    stop_split(Cfg);
migration_split_case(Cfg) when is_list(Cfg) ->
    DcId   = ?config(dc_id, Cfg),
    Host   = ?config(mtp_host, Cfg),
    Port   = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Pool   = mtp_dc_pool:dc_to_pool_name(DcId),
    BackNode = ?config(back_node, Cfg),
    register(mtp_test_rpc_sink, self()),
    try
        Cli  = mtp_test_client:connect(Host, Port, Secret, DcId, mtp_secure),
        Cli1 = ping(Cli),
        %% mtp_test_reporter_rpc runs inside the middle server (CT node), so
        %% {rpc_from, ServerPid, ConnId, Data} arrives in our mailbox directly.
        ServerPid = receive {rpc_from, Pid, _, _} -> Pid end,
        ok = mtp_test_middle_server:close_connection(ServerPid),
        %% mtp_handler lives on the front (CT) node — migration metric is local.
        ok = mtp_test_metric:wait_for_value(
               count, [?APP, downstream_migration, total],
               [?FUNCTION_NAME, DcId, ok], 1, 5000),
        Cli2 = ping(Cli1),
        %% Back-node pool must still track our one upstream.
        ?assertMatch(#{n_upstreams := 1}, gen_server:call({Pool, BackNode}, status)),
        ok = mtp_test_client:close(Cli2)
    after
        unregister(mtp_test_rpc_sink)
    end.

%%====================================================================
%% Setup / teardown helpers
%%====================================================================

setup_split(Name, MtpPort, DcCfg0, Cfg) ->
    PubKey = crypto:strong_rand_bytes(128),
    DcId   = 1,
    DcConf = [{DcId, {127, 0, 0, 1}, MtpPort + 10}],

    %% Start the fake DC (HTTP config server + middle server) on the CT node.
    %% This also sets proxy_secret_url / proxy_config_url / external_ip in the
    %% local app env (they are used by the back node, not the front).
    {ok, DcCfg} = mtp_test_datacenter:start_dc(PubKey, DcConf, DcCfg0),
    {ok, ProxySecretUrl} = application:get_env(?APP, proxy_secret_url),
    {ok, ProxyConfigUrl} = application:get_env(?APP, proxy_config_url),

    %% Start the metric store for the front (CT) node.
    {ok, FrontMetricPid} = mtp_test_metric:start_link(),

    try
        %% ---- Start back peer node ----
        %% Use the same code paths as the CT node so all modules are available.
        PeerName = list_to_atom("back_" ++ atom_to_list(Name)),
        {ok, BackPeer, BackNode} = peer:start_link(
                                     #{name => PeerName,
                                       args => ["-pa" | code:get_path()]}),
        try
            %% Configure the back node before starting the application.
            ok = rpc:call(BackNode, application, load, [?APP]),
            %% Unset ip_lookup_services so mtp_config doesn't fetch the real external
            %% IP and overwrite the "127.0.0.1" we set for external_ip below.
            ok = rpc:call(BackNode, application, unset_env, [?APP, ip_lookup_services]),
            BackEnv0 = [{node_role,         back},
                        {proxy_secret_url,  ProxySecretUrl},
                        {proxy_config_url,  ProxyConfigUrl},
                        {external_ip,       "127.0.0.1"},
                        {metric_backend,    mtp_test_metric}],
            BackEnv = case maps:find(init_dc_connections, DcCfg0) of
                          {ok, N} -> [{init_dc_connections, N} | BackEnv0];
                          error   -> BackEnv0
                      end,
            [ok = rpc:call(BackNode, application, set_env, [?APP, K, V]) || {K, V} <- BackEnv],
            {ok, BackMetricPid} = rpc:call(BackNode, mtp_test_metric, start_link, []),
            {ok, _} = rpc:call(BackNode, application, ensure_all_started, [?APP]),

            %% ---- Configure and start front (CT) node ----
            Secret = mtp_handler:hex(crypto:strong_rand_bytes(16)),
            Listeners = [#{name      => Name,
                           port      => MtpPort,
                           listen_ip => "127.0.0.1",
                           secret    => Secret,
                           tag       => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}],
            %% node_role and back_node override whatever test-sys.config set.
            application:set_env(?APP, node_role, front),
            application:set_env(?APP, back_node, BackNode),
            application:set_env(?APP, ports,     Listeners),
            {ok, _} = application:ensure_all_started(?APP),

            {ok, MtpIp} = inet:parse_address("127.0.0.1"),
            [{dc_id,            DcId},
             {mtp_host,         MtpIp},
             {mtp_port,         MtpPort},
             {mtp_secret,       Secret},
             {dc_conf,          DcCfg},
             {back_node,        BackNode},
             {back_peer,        BackPeer},
             {back_metric_pid,  BackMetricPid},
             {front_metric_pid, FrontMetricPid} | Cfg]
        catch E1:R1:ST1 ->
            peer:stop(BackPeer),
            erlang:raise(E1, R1, ST1)
        end
    catch E2:R2:ST2 ->
        gen_server:stop(FrontMetricPid),
        {ok, _} = mtp_test_datacenter:stop_dc(DcCfg),
        erlang:raise(E2, R2, ST2)
    end.

stop_split(Cfg) ->
    DcCfg          = ?config(dc_conf, Cfg),
    BackNode       = ?config(back_node, Cfg),
    BackPeer       = ?config(back_peer, Cfg),
    BackMetricPid  = ?config(back_metric_pid, Cfg),
    FrontMetricPid = ?config(front_metric_pid, Cfg),
    ok = application:stop(?APP),
    ok = application:unload(?APP),
    ok = rpc:call(BackNode, application, stop,   [?APP]),
    ok = rpc:call(BackNode, application, unload, [?APP]),
    %% Stop metric on back node before the peer process disappears.
    rpc:call(BackNode, gen_server, stop, [BackMetricPid]),
    ok = peer:stop(BackPeer),
    {ok, _} = mtp_test_datacenter:stop_dc(DcCfg),
    gen_server:stop(FrontMetricPid),
    Cfg.

%%====================================================================
%% Internal helpers
%%====================================================================

ping(Cli0) ->
    Data = crypto:strong_rand_bytes(64),
    Cli1 = mtp_test_client:send(Data, Cli0),
    {ok, Packet, Cli2} = mtp_test_client:recv_packet(Cli1, 3000),
    ?assertEqual(Data, Packet),
    Cli2.
