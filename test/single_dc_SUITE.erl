%% @doc Basic tests with only one telegram DC
-module(single_dc_SUITE).

-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2]).

-export([echo_secure_case/1,
         echo_abridged_many_packets_case/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

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

echo_secure_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, ?LINE, Cfg);
echo_secure_case({post, Cfg}) ->
    stop_single(Cfg);
echo_secure_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli = mtp_test_client:connect({127, 0, 0, 1}, Port, Secret, DcId, mtp_secure),
    Data = crypto:strong_rand_bytes(64),
    Cli1 = mtp_test_client:send(Data, Cli),
    {ok, Packet, Cli2} = mtp_test_client:recv_packet(Cli1, 1000),
    ok = mtp_test_client:close(Cli2),
    ?assertEqual(Data, Packet),
    ?assertEqual(1, mtp_test_metric:get_tags(
                      count, [mtproto_proxy,in_connection,total], [?FUNCTION_NAME])),
    %% race-condition
    %% ?assertEqual(1, mtp_test_metric:get_tags(
    %%                   count, [mtproto_proxy,in_connection_closed,total], [?FUNCTION_NAME])),
    ?assertEqual({1, 64, 64, 64},
                 mtp_test_metric:get_tags(
                   histogram, [mtproto_proxy,tg_packet_size,bytes],
                   [upstream_to_downstream])),
    ?assertMatch({1, _, _, _},                  % larger because of RPC headers
                 mtp_test_metric:get_tags(
                   histogram, [mtproto_proxy,tg_packet_size,bytes],
                   [downstream_to_upstream])).

echo_abridged_many_packets_case({pre, Cfg}) ->
    setup_single(?FUNCTION_NAME, ?LINE, Cfg);
echo_abridged_many_packets_case({post, Cfg}) ->
    stop_single(Cfg);
echo_abridged_many_packets_case(Cfg) when is_list(Cfg) ->
    DcId = ?config(dc_id, Cfg),
    Port = ?config(mtp_port, Cfg),
    Secret = ?config(mtp_secret, Cfg),
    Cli0 = mtp_test_client:connect({127, 0, 0, 1}, Port, Secret, DcId, mtp_secure),
    Packets =
        [crypto:strong_rand_bytes(4 * rand:uniform(50))
         || _ <- lists:seq(1, 15)],
    Cli2 = lists:foldl(fun mtp_test_client:send/2, Cli0, Packets),
    timer:sleep(10),                % TODO: some hook in proxy to find when sent
    {ok, RecvPackets, Cli} = mtp_test_client:recv_all(Cli2, 1000),
    ok = mtp_test_client:close(Cli),
    ?assertEqual(Packets, RecvPackets).

%% Helpers

setup_single(Name, Offset, Cfg) ->
    {ok, Pid} = mtp_test_metric:start_link(),
    PubKey = crypto:strong_rand_bytes(128),
    DcId = 1,
    DcConf = [{DcId, {127, 0, 0, 1}, 10000 + Offset}],
    MtpPort = 10000 + Offset + 1,
    Secret = mtp_handler:hex(crypto:strong_rand_bytes(16)),
    Listeners = [#{name => Name,
                   port => MtpPort,
                   listen_ip => "127.0.0.1",
                   secret => Secret,
                   tag => <<"dcbe8f1493fa4cd9ab300891c0b5b326">>}],
    application:load(mtproto_proxy),
    Cfg1 = set_env([{ports, Listeners}], Cfg),
    {ok, DcCfg} = mtp_test_datacenter:start_dc(PubKey, DcConf, #{}),
    application:load(mtproto_proxy),
    {ok, _} = application:ensure_all_started(mtproto_proxy),
    [{dc_id, DcId},
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
