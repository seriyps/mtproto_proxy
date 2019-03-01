%% Fake telegram server
%% Secret = crypto:strong_rand_bytes(128).
%% DcConf = [{1, {127, 0, 0, 1}, 8888}, {2, {127, 0, 0, 1}, 8889}].
%% Cfg = mtp_test_midle_server:dc_list_to_config(DcConf).
%% mtp_test_midle_server:start_config_server({127, 0, 0, 1}, 3333, Secret, Cfg).
%% mtp_test_midle_server:start(dc1, #{port => 8888, ip => {127, 0, 0, 1}, secret => Secret}).
%% mtp_test_midle_server:start(dc2, #{port => 8889, ip => {127, 0, 0, 1}, secret => Secret}).
%% application:ensure_all_started(mtproto_proxy).
-module(mtp_test_midle_server).
-behaviour(ranch_protocol).
-behaviour(gen_statem).

-export([start_dc/0,
         start_dc/3,
         stop_dc/1,
         start/2,
         stop/1,
         start_config_server/5,
         stop_config_server/1]).
-export([dc_list_to_config/1]).
-export([start_link/4,
         ranch_init/1]).
-export([do/1]).
-export([init/1,
         callback_mode/0,
         %% handle_call/3,
         %% handle_cast/2,
         %% handle_info/2,
         code_change/3,
         terminate/2
        ]).
-export([wait_nonce/3,
         wait_handshake/3,
         on_tunnel/3]).

-include_lib("inets/include/httpd.hrl").
-record(hs_state,
        {sock,
         transport,
         secret,
         codec :: mtp_codec:codec(),
         cli_nonce,
         cli_ts,
         sender_pid,
         peer_pid,
         srv_nonce}).
-record(t_state,
        {sock,
         transport,
         codec,
         clients = #{} :: #{}}).

-define(RPC_NONCE, 170,135,203,122).
-define(RPC_HANDSHAKE, 245,238,130,118).
-define(RPC_FLAGS, 0, 0, 0, 0).

-define(SECRET_PATH, "/getProxySecret").
-define(CONFIG_PATH, "/getProxyConfig").

-type state_name() :: wait_nonce | wait_handshake | on_tunnel.

start_dc() ->
    Secret = crypto:strong_rand_bytes(128),
    DcConf = [{1, {127, 0, 0, 1}, 8888}],
    {ok, _Cfg} = mtp_test_midle_server:start_dc(Secret, DcConf, #{}).

start_dc(Secret, DcConf, Acc) ->
    Cfg = mtp_test_midle_server:dc_list_to_config(DcConf),
    {ok, Acc1} = start_config_server({127, 0, 0, 1}, 3333, Secret, Cfg, Acc),
    Ids =
        [begin
             Id = {?MODULE, DcId},
             {ok, _Pid} = start(Id, #{port => Port, ip => Ip, secret => Secret}),
             Id
         end || {DcId, Ip, Port} <- DcConf],
    {ok, Acc1#{srv_ids => Ids}}.

stop_dc(#{srv_ids := Ids} = Acc) ->
    Acc1 = stop_config_server(Acc),
    ok = lists:foreach(fun stop/1, Ids),
    {ok, maps:without([srv_ids], Acc1)}.

%%
%% Inets HTTPD to use as a mock for https://core.telegram.org
%%

%% Api
start_config_server(Ip, Port, Secret, DcConfig, Acc) ->
    Netloc = lists:flatten(io_lib:format("http://~s:~w", [inet:ntoa(Ip), Port])),
    Env = [{proxy_secret_url,
            Netloc ++ ?SECRET_PATH},
           {proxy_config_url,
            Netloc ++ ?CONFIG_PATH},
           {external_ip, "127.0.0.1"},
           {init_dc_connections, 1},
           {num_acceptors, 4},
           {ip_lookup_services, undefined}],
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
    {ok, Pid} =
        inets:start(httpd,
                    [{port, Port},
                     {server_name, "mtp_config"},
                     {server_root, "/tmp"},
                     {document_root, code:priv_dir(mtproto_proxy)},

                     {bind_address, Ip},
                     {modules, [?MODULE]},
                     {mtp_secret, Secret},
                     {mtp_dc_conf, DcConfig}]),
    {ok, Acc#{env => OldEnv,
              httpd_pid => Pid}}.

stop_config_server(#{env := Env, httpd_pid := Pid} = Acc) ->
    [case V of
         undefined ->
             application:unset_env(mtproto_proxy, K);
         {ok, Val} ->
             application:set_env(mtproto_proxy, K, Val)
     end || {K, V} <- Env],
    inets:stop(httpd, Pid),
    {ok, maps:without([env, httpd_pid], Acc)}.

dc_list_to_config(List) ->
    <<
      <<(list_to_binary(
           io_lib:format("proxy_for ~w ~s:~w;~n", [DcId, inet:ntoa(Ip), Port])
          ))/binary>>
      || {DcId, Ip, Port} <- List
      >>.

%% Inets callback
do(#mod{request_uri = ?CONFIG_PATH, config_db = Db}) ->
    [{_, DcConf}] = ets:lookup(Db, mtp_dc_conf),
    {break, [{response, {200, binary_to_list(DcConf)}}]};
do(#mod{request_uri = ?SECRET_PATH, config_db = Db}) ->
    [{_, Secret}] = ets:lookup(Db, mtp_secret),
    {break, [{response, {200, binary_to_list(Secret)}}]}.

%%
%% Mtproto telegram server
%%

%% Api
start(Id, Opts) ->
    {ok, _} = application:ensure_all_started(ranch),
    ranch:start_listener(
      Id, ranch_tcp,
      #{socket_opts => [{ip, {127, 0, 0, 1}},
                        {port, maps:get(port, Opts)}],
        num_acceptors => 2,
        max_connections => 100},
      ?MODULE, Opts).

stop(Id) ->
    ranch:stop_listener(Id).

%% Callbacks

start_link(Ref, _, Transport, Opts) ->
    {ok, proc_lib:spawn_link(?MODULE, ranch_init, [{Ref, Transport, Opts}])}.

ranch_init({Ref, Transport, Opts}) ->
    {ok, Socket} = ranch:handshake(Ref),
    {ok, StateName, StateData} = init({Socket, Transport, Opts}),
    ok = Transport:setopts(Socket, [{active, once}]),
    gen_statem:enter_loop(?MODULE, [], StateName, StateData).

init({Socket, Transport, Opts}) ->
    Codec = mtp_codec:new(mtp_noop_codec, mtp_noop_codec:new(),
                          mtp_full, mtp_full:new(-2, -2)),
    {ok, wait_nonce, #hs_state{sock = Socket,
                               transport = Transport,
                               secret = maps:get(secret, Opts),
                               codec = Codec}}.

callback_mode() ->
    state_functions.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%
%% State handlers
%%

wait_nonce(info, {tcp, _Sock, TcpData},
           #hs_state{codec = Codec0, secret = Key,
                     transport = Transport, sock = Sock} = S) ->
    %% Hope whole protocol packet fit in 1 TCP packet
    {ok, PacketData, Codec1} = mtp_codec:try_decode_packet(TcpData, Codec0),
    <<KeySelector:4/binary, _/binary>> = Key,
    {nonce, KeySelector, Schema, CryptoTs, CliNonce} = mtp_rpc:decode_nonce(PacketData),
    SrvNonce = crypto:strong_rand_bytes(16),
    Answer = mtp_rpc:encode_nonce({nonce, KeySelector, Schema, CryptoTs, SrvNonce}),
    %% Send non-encrypted nonce
    {ok, #hs_state{codec = Codec2} = S1} = hs_send(Answer, S#hs_state{codec = Codec1}),
    %% Generate keys
    {ok, {CliIp, CliPort}} = Transport:peername(Sock),
    {ok, {MyIp, MyPort}} = Transport:sockname(Sock),
    CliIpBin = mtp_obfuscated:bin_rev(mtp_rpc:inet_pton(CliIp)),
    MyIpBin = mtp_obfuscated:bin_rev(mtp_rpc:inet_pton(MyIp)),

    Args = #{srv_n => SrvNonce, clt_n => CliNonce, clt_ts => CryptoTs,
             srv_ip => MyIpBin, srv_port => MyPort,
             clt_ip => CliIpBin, clt_port => CliPort, secret => Key},
    {DecKey, DecIv} = mtp_down_conn:get_middle_key(Args#{purpose => <<"CLIENT">>}),
    {EncKey, EncIv} = mtp_down_conn:get_middle_key(Args#{purpose => <<"SERVER">>}),
    %% Add encryption layer to codec
    {_, _, PacketMod, PacketState} = mtp_codec:decompose(Codec2),
    CryptoState = mtp_aes_cbc:new(EncKey, EncIv, DecKey, DecIv, 16),
    Codec3 = mtp_codec:new(mtp_aes_cbc, CryptoState,
                           PacketMod, PacketState),

    {next_state, wait_handshake,
     activate(S1#hs_state{codec = Codec3,
                          cli_nonce = CliNonce,
                          cli_ts = CryptoTs,
                          srv_nonce = SrvNonce})};
wait_nonce(Type, Event, S) ->
    handle_event(Type, Event, ?FUNCTION_NAME, S).


wait_handshake(info, {tcp, _Sock, TcpData},
               #hs_state{codec = Codec0} = S) ->
    {ok, PacketData, Codec1} = mtp_codec:try_decode_packet(TcpData, Codec0),
    {handshake, SenderPID, PeerPID} = mtp_rpc:decode_handshake(PacketData),
    Answer = mtp_rpc:encode_handshake({handshake, SenderPID, PeerPID}),
    {ok, #hs_state{sock = Sock,
                   transport = Transport,
                   codec = Codec2}} = hs_send(Answer, S#hs_state{codec = Codec1}),
    {next_state, on_tunnel,
     activate(#t_state{sock = Sock,
                       transport = Transport,
                       codec = Codec2,
                       clients = #{}})}.

on_tunnel(info, {tcp, _Sock, TcpData}, #t_state{codec = Codec0} = S) ->
    {ok, S2, Codec1} =
        mtp_codec:fold_packets(
          fun(Packet, S1) ->
                  handle_rpc(mtp_rpc:srv_decode_packet(Packet), S1)
          end, S, TcpData, Codec0),
    {keep_state, activate(S2#t_state{codec = Codec1})}.

handle_event(info, {tcp_closed, _Sock}, _EventName, _S) ->
    {stop, normal}.

%% Helpers

hs_send(Packet, #hs_state{transport = Transport, sock = Sock,
                          codec = Codec} = St) ->
    %% lager:debug("Up>Down: ~w", [Packet]),
    {Encoded, Codec1} = mtp_codec:encode_packet(Packet, Codec),
    ok = Transport:send(Sock, Encoded),
    {ok, St#hs_state{codec = Codec1}}.

t_send(Packet, #t_state{transport = Transport, sock = Sock,
                        codec = Codec} = St) ->
    %% lager:debug("Up>Down: ~w", [Packet]),
    {Encoded, Codec1} = mtp_codec:encode_packet(Packet, Codec),
    ok = Transport:send(Sock, Encoded),
    {ok, St#t_state{codec = Codec1}}.

activate(#hs_state{transport = Transport, sock = Sock} = S) ->
    ok = Transport:setopts(Sock, [{active, once}]),
    S;
activate(#t_state{transport = Transport, sock = Sock} = S) ->
    ok = Transport:setopts(Sock, [{active, once}]),
    S.

handle_rpc({data, ConnId, Data}, #t_state{clients = Clients} = S) ->
    %% Echo data back
    %% TODO: interptet Data to power some test scenarios, eg, client might
    %% ask to close it's connection
    {ok, S1} = t_send(mtp_rpc:srv_encode_packet({proxy_ans, ConnId, Data}), S),
    Cnt = maps:get(ConnId, Clients, 0),
    %% Increment can fail if there is a tombstone for this client
    S1#t_state{clients = Clients#{ConnId => Cnt + 1}};
handle_rpc({remote_closed, ConnId}, #t_state{clients = Clients} = S) ->
    is_integer(maps:get(ConnId, Clients))
        orelse error({unexpected_closed, ConnId}),
    S#t_state{clients = Clients#{ConnId := tombstone}}.
