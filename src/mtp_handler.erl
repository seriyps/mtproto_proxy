%%% @author Sergey Prokhorov <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey Prokhorov
%%% @doc
%%% MTProto proxy network layer
%%% @end
%%% Created :  9 Apr 2018 by Sergey Prokhorov <me@seriyps.ru>

-module(mtp_handler).
-behaviour(gen_server).
-behaviour(ranch_protocol).

%% API
-export([start_link/4]).
-export([hex/1, unhex/1]).
-export([keys_str/0]).

%% Callbacks
-export([ranch_init/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(MAX_SOCK_BUF_SIZE, 1024 * 300).    % Decrease if CPU is cheaper than RAM
-define(MAX_UP_INIT_BUF_SIZE, 1024 * 1024).     %1mb

-define(APP, mtproto_proxy).

-record(state,
        {stage = init :: stage(),
         stage_state = <<>> :: any(),
         up_acc = <<>> :: any(),

         secret :: binary(),
         proxy_tag :: binary(),

         up_sock :: gen_tcp:socket(),
         up_transport :: transport(),
         up_codec = ident :: mtp_layer:layer(),

         down_sock :: gen_tcp:socket(),
         down_codec = ident :: mtp_layer:layer(),

         started_at :: pos_integer(),
         timer_state = init :: init | hibernate | stop,
         timer :: gen_timeout:tout()}).

-type transport() :: module().
-type stage() :: init | tunnel.


%% APIs

start_link(Ref, Socket, Transport, Opts) ->
    metric:count_inc([?APP, in_connection, total], 1, #{}),
    {ok, proc_lib:spawn_link(?MODULE, ranch_init, [{Ref, Socket, Transport, Opts}])}.

keys_str() ->
    [{Name, Port, hex(Secret)}
     || {Name, Port, Secret} <- application:get_env(?APP, ports, [])].

%% Callbacks

%% Custom gen_server init
ranch_init({Ref, Socket, Transport, _} = Opts) ->
    case init(Opts) of
        {ok, State} ->
            ok = ranch:accept_ack(Ref),
            ok = Transport:setopts(Socket,
                                   [{active, once},
                                    %% {recbuf, ?MAX_SOCK_BUF_SIZE},
                                    %% {sndbuf, ?MAX_SOCK_BUF_SIZE},
                                    {buffer, ?MAX_SOCK_BUF_SIZE}
                                   ]),
            gen_server:enter_loop(?MODULE, [], State);
        error ->
            metric:count_inc([?APP, in_connection_closed, total], 1, #{}),
            exit(normal)
    end.

init({_Ref, Socket, Transport, [Secret, Tag]}) ->
    case Transport:peername(Socket) of
        {ok, {Ip, Port}} ->
            lager:info("New connection ~s:~p", [inet:ntoa(Ip), Port]),
            {TimeoutKey, TimeoutDefault} = state_timeout(init),
            Timer = gen_timeout:new(
                      #{timeout => {env, ?APP, TimeoutKey, TimeoutDefault}}),
            State = #state{up_sock = Socket,
                           secret = unhex(Secret),
                           proxy_tag = unhex(Tag),
                           up_transport = Transport,
                           started_at = erlang:system_time(second),
                           timer = Timer},
            {ok, State};
        {error, Reason} ->
            lager:info("Can't read peername: ~p", [Reason]),
            error
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({tcp, Sock, Data}, #state{up_sock = Sock,
                                      up_transport = Transport} = S) ->
    %% client -> proxy
    track(rx, Data),
    case handle_upstream_data(Data, S) of
        {ok, S1} ->
            ok = Transport:setopts(Sock, [{active, once}]),
            {noreply, bump_timer(S1)};
        {error, Reason} ->
            lager:info("handle_data error ~p", [Reason]),
            {stop, normal, S}
    end;
handle_info({tcp_closed, Sock}, #state{up_sock = Sock} = S) ->
    lager:debug("upstream sock closed"),
    {stop, normal, maybe_close_down(S)};
handle_info({tcp_error, Sock, Reason}, #state{up_sock = Sock} = S) ->
    lager:info("upstream sock error: ~p", [Reason]),
    {stop, Reason, maybe_close_down(S)};

handle_info({tcp, Sock, Data}, #state{down_sock = Sock} = S) ->
    %% telegram server -> proxy
    track(tx, Data),
    try handle_downstream_data(Data, S) of
        {ok, S1} ->
            ok = inet:setopts(Sock, [{active, once}]),
            {noreply, bump_timer(S1)};
        {error, Reason} ->
            lager:error("Error sending tunnelled data to in socket: ~p", [Reason]),
            {stop, normal, S}
    catch throw:rpc_close ->
            lager:info("downstream closed by RPC"),
            #state{up_sock = USock, up_transport = UTrans} = S,
            ok = UTrans:close(USock),
            {stop, normal, maybe_close_down(S)}
    end;
handle_info({tcp_closed, Sock}, #state{down_sock = Sock,
                                       up_sock = USock, up_transport = UTrans} = S) ->
    lager:debug("downstream sock closed"),
    ok = UTrans:close(USock),
    {stop, normal, S};
handle_info({tcp_error, Sock, Reason}, #state{down_sock = Sock,
                                              up_sock = USock, up_transport = UTrans} = S) ->
    lager:info("downstream sock error: ~p", [Reason]),
    ok = UTrans:close(USock),
    {stop, Reason, S};


handle_info(timeout, #state{timer = Timer, timer_state = TState} = S) ->
    case gen_timeout:is_expired(Timer) of
        true when TState == stop;
                  TState == init ->
            metric:count_inc([?APP, inactive_timeout, total], 1, #{}),
            lager:info("inactive timeout in state ~p", [TState]),
            {stop, normal, S};
        true when TState == hibernate ->
            metric:count_inc([?APP, inactive_hibernate, total], 1, #{}),
            {noreply, switch_timer(S, stop), hibernate};
        false ->
            Timer1 = gen_timeout:reset(Timer),
            {noreply, S#state{timer = Timer1}}
    end;
handle_info(Other, S) ->
    lager:warning("Unexpected handle_info ~p", [Other]),
    {noreply, S}.

terminate(_Reason, #state{}) ->
    metric:count_inc([?APP, in_connection_closed, total], 1, #{}),
    lager:debug("terminate ~p", [_Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

maybe_close_down(#state{down_sock = undefined} = S) -> S;
maybe_close_down(#state{down_sock = Out} = S) ->
    gen_tcp:close(Out),
    S#state{down_sock = undefined}.

bump_timer(#state{timer = Timer, timer_state = TState} = S) ->
    Timer1 = gen_timeout:bump(Timer),
    case TState of
        stop ->
            switch_timer(S#state{timer = Timer1}, hibernate);
        _ ->
            S#state{timer = Timer1}
    end.

switch_timer(#state{timer_state = TState} = S, TState) ->
    S;
switch_timer(#state{timer_state = FromState, timer = Timer} = S, ToState) ->
    metric:count_inc([?APP, timer_switch, total], 1,
                     #{labels => [FromState, ToState]}),
    {NewTimeKey, NewTimeDefault} = state_timeout(ToState),
    Timer1 = gen_timeout:set_timeout(
               {env, ?APP, NewTimeKey, NewTimeDefault}, Timer),
    S#state{timer_state = ToState,
            timer = Timer1}.

state_timeout(init) ->
    {init_timeout_sec, 60};
state_timeout(hibernate) ->
    {hibernate_timeout_sec, 60};
state_timeout(stop) ->
    {ready_timeout_sec, 1200}.


%% Stream handlers

%% Handle telegram client -> proxy stream
handle_upstream_data(<<Header:64/binary, Rest/binary>>, #state{stage = init, stage_state = <<>>,
                                                               secret = Secret} = S) ->
    case mtp_obfuscated:from_header(Header, Secret) of
        {ok, DcId, ObfuscatedCodec} ->
            ObfuscatedLayer = mtp_layer:new(mtp_obfuscated, ObfuscatedCodec),
            AbridgedLayer = mtp_layer:new(mtp_abridged, mtp_abridged:new()),
            UpCodec = mtp_layer:new(mtp_wrap, mtp_wrap:new(AbridgedLayer,
                                                           ObfuscatedLayer)),
            handle_upstream_header(
              DcId,
              S#state{up_codec = UpCodec,
                      up_acc = Rest,
                      stage_state = undefined});
        Err ->
            Err
    end;
handle_upstream_data(Bin, #state{stage = init, stage_state = <<>>} = S) ->
    {ok, S#state{stage_state = Bin}};
handle_upstream_data(Bin, #state{stage = init, stage_state = Buf} = S) ->
    handle_upstream_data(<<Buf/binary, Bin/binary>> , S#state{stage_state = <<>>});
handle_upstream_data(Bin, #state{stage = tunnel,
                                 up_codec = UpCodec} = S) ->
    {ok, S3, UpCodec1} =
        mtp_layer:fold_packets(
          fun(Decoded, S1) ->
                  metric:histogram_observe(
                    [?APP, tg_packet_size, bytes],
                    byte_size(Decoded),
                    #{labels => [upstream_to_downstream]}),
                  {ok, S2} = down_send(Decoded, S1),
                  S2
          end, S, Bin, UpCodec),
    {ok, S3#state{up_codec = UpCodec1}};
handle_upstream_data(Bin, #state{stage = Stage, up_acc = Acc} = S) when Stage =/= init,
                                                                        Stage =/= tunnel ->
    %% We are in downstream handshake; it would be better to leave socked in passive mode,
    %% but let's do it in next iteration
    ((byte_size(Bin) + byte_size(Acc)) < ?MAX_UP_INIT_BUF_SIZE)
        orelse error(upstream_buffer_overflow),
    {ok, S#state{up_acc = <<Acc/binary, Bin/binary>>}}.


%% Handle telegram server -> proxy stream
handle_downstream_data(Bin, #state{stage = down_handshake_1,
                                   down_codec = DownCodec} = S) ->
    case mtp_layer:try_decode_packet(Bin, DownCodec) of
        {ok, Packet, DownCodec1} ->
            down_handshake2(Packet, S#state{down_codec = DownCodec1});
        {incomplete, DownCodec1} ->
            {ok, S#state{down_codec = DownCodec1}}
    end;
handle_downstream_data(Bin, #state{stage = down_handshake_2,
                                   proxy_tag = ProxyTag,
                                   down_codec = DownCodec} = S) ->
    case mtp_layer:try_decode_packet(Bin, DownCodec) of
        {ok, Packet, DownCodec1} ->
            %% TODO: There might be something in downstream buffers after stage3,
            %% would be nice to run foldl
            {ok, S1} = down_handshake3(Packet, ProxyTag, S#state{down_codec = DownCodec1}),
            S2 = #state{up_acc = UpAcc} =  switch_timer(S1, hibernate),
            %% Flush upstream accumulator
            handle_upstream_data(UpAcc, S2#state{up_acc = []});
        {incomplete, DownCodec1} ->
            {ok, S#state{down_codec = DownCodec1}}
    end;
handle_downstream_data(Bin, #state{stage = tunnel,
                                   down_codec = DownCodec} = S) ->
    {ok, S3, DownCodec1} =
        mtp_layer:fold_packets(
          fun(Decoded, S1) ->
                  metric:histogram_observe(
                    [?APP, tg_packet_size, bytes],
                    byte_size(Decoded),
                    #{labels => [downstream_to_upstream]}),
                  {ok, S2} = up_send(Decoded, S1),
                  S2
          end, S, Bin, DownCodec),
    {ok, S3#state{down_codec = DownCodec1}}.


up_send(Packet, #state{stage = tunnel,
                       up_codec = UpCodec,
                       up_sock = Sock,
                       up_transport = Transport} = S) ->
    {Encoded, UpCodec1} = mtp_layer:encode_packet(Packet, UpCodec),
    metric:rt([?APP, upstream_send_duration, seconds],
              fun() ->
                      ok = Transport:send(Sock, Encoded)
              end),
    {ok, S#state{up_codec = UpCodec1}}.

down_send(Packet, #state{down_sock = Sock,
                         down_codec = DownCodec} = S) ->
    {Encoded, DownCodec1} = mtp_layer:encode_packet(Packet, DownCodec),
    metric:rt([?APP, downstream_send_duration, seconds],
              fun() ->
                      ok = gen_tcp:send(Sock, Encoded)
              end),
    {ok, S#state{down_codec = DownCodec1}}.


%% Internal


handle_upstream_header(DcId, S) ->
    {Addr, Port} = mtp_config:get_downstream_safe(DcId),

    case connect(Addr, Port) of
        {ok, Sock} ->
            AddrStr = inet:ntoa(Addr),
            metric:count_inc([?APP, out_connect_ok, total], 1,
                             #{labels => [AddrStr]}),
            lager:info("Connected to ~s:~p", [AddrStr, Port]),
            down_handshake1(S#state{down_sock = Sock});
        {error, Reason} = Err ->
            metric:count_inc([?APP, out_connect_error, total], 1, #{labels => [Reason]}),
            Err
    end.

-define(CONN_TIMEOUT, 10000).
-define(SEND_TIMEOUT, 60 * 1000).

connect(Host, Port) ->
    SockOpts = [{active, once},
                {packet, raw},
                binary,
                {send_timeout, ?SEND_TIMEOUT},
                %% {nodelay, true},
                {keepalive, true}],
    case metric:rt([?APP, downstream_connect_duration, seconds],
                   fun() ->
                           gen_tcp:connect(Host, Port, SockOpts, ?CONN_TIMEOUT)
                   end) of
        {ok, Sock} ->
            ok = inet:setopts(Sock, [%% {recbuf, ?MAX_SOCK_BUF_SIZE},
                                     %% {sndbuf, ?MAX_SOCK_BUF_SIZE},
                                     {buffer, ?MAX_SOCK_BUF_SIZE}]),
            {ok, Sock};
        {error, _} = Err ->
            Err
    end.

-define(RPC_NONCE, <<170,135,203,122>>).
-define(RPC_HANDSHAKE, <<245,238,130,118>>).
-define(RPC_FLAGS, <<0, 0, 0, 0>>).

down_handshake1(S) ->
    RpcNonce = ?RPC_NONCE,
    <<KeySelector:4/binary, _/binary>> = Key = mtp_config:get_secret(),
    CryptoTs = os:system_time(seconds),
    Nonce = crypto:strong_rand_bytes(16),
    Msg = <<RpcNonce/binary,
            KeySelector/binary,
            1:32/little,                        %AES
            CryptoTs:32/little,
            Nonce/binary>>,
    Full = mtp_full:new(-2, -2),
    S1 = S#state{down_codec = mtp_layer:new(mtp_full, Full),
                 stage = down_handshake_1,
                 stage_state = {KeySelector, Nonce, CryptoTs, Key}},
    down_send(Msg, S1).

down_handshake2(<<Type:4/binary, KeySelector:4/binary, Schema:32/little, _CryptoTs:4/binary,
                  SrvNonce:16/binary>>, #state{stage_state = {MyKeySelector, CliNonce, MyTs, Key},
                                               down_sock = Sock,
                                               down_codec = DownCodec} = S) ->
    (Type == ?RPC_NONCE) orelse error({wrong_rpc_type, Type}),
    (Schema == 1) orelse error({wrong_schema, Schema}),
    (KeySelector == MyKeySelector) orelse error({wrong_key_selector, KeySelector}),
    {ok, {DownIp, DownPort}} = inet:peername(Sock),
    {MyIp, MyPort} = get_external_ip(Sock),
    DownIpBin = mtp_obfuscated:bin_rev(mtp_rpc:inet_pton(DownIp)),
    MyIpBin = mtp_obfuscated:bin_rev(mtp_rpc:inet_pton(MyIp)),
    Args = #{srv_n => SrvNonce, clt_n => CliNonce, clt_ts => MyTs,
             srv_ip => DownIpBin, srv_port => DownPort,
             clt_ip => MyIpBin, clt_port => MyPort, secret => Key},
    {EncKey, EncIv} = get_middle_key(Args#{purpose => <<"CLIENT">>}),
    {DecKey, DecIv} = get_middle_key(Args#{purpose => <<"SERVER">>}),
    CryptoCodec = mtp_layer:new(mtp_aes_cbc, mtp_aes_cbc:new(EncKey, EncIv, DecKey, DecIv, 16)),
    DownCodec1 = mtp_layer:new(mtp_wrap, mtp_wrap:new(DownCodec, CryptoCodec)),
    SenderPID = PeerPID = <<"IPIPPRPDTIME">>,
    Handshake = [?RPC_HANDSHAKE,
                 ?RPC_FLAGS,
                 SenderPID,
                 PeerPID],
    down_send(Handshake, S#state{down_codec = DownCodec1,
                                 stage = down_handshake_2,
                                 stage_state = {MyIp, MyPort, SenderPID}}).

get_middle_key(#{srv_n := Nonce, clt_n := MyNonce, clt_ts := MyTs, srv_ip := SrvIpBinBig, srv_port := SrvPort,
                 clt_ip := CltIpBinBig, clt_port := CltPort, secret := Secret, purpose := Purpose} = _Args) ->
    Msg =
        <<Nonce/binary,
          MyNonce/binary,
          MyTs:32/little,
          SrvIpBinBig/binary,
          CltPort:16/little,
          Purpose/binary,
          CltIpBinBig/binary,
          SrvPort:16/little,
          Secret/binary,
          Nonce/binary,
          %% IPv6
          MyNonce/binary
        >>,
    <<_, ForMd51/binary>> = Msg,
    <<_, _, ForMd52/binary>> = Msg,
    <<Key1:12/binary, _/binary>> = crypto:hash(md5, ForMd51),
    ShaSum = crypto:hash(sha, Msg),
    Key = <<Key1/binary, ShaSum/binary>>,
    IV = crypto:hash(md5, ForMd52),
    {Key, IV}.


down_handshake3(<<Type:4/binary, _Flags:4/binary, _SenderPid:12/binary, PeerPid:12/binary>>,
                ProxyTag,
                #state{stage_state = {MyIp, MyPort, PrevSenderPid},
                       down_codec = DownCodec,
                       up_sock = Sock,
                       up_transport = Transport} = S) ->
    (Type == ?RPC_HANDSHAKE) orelse error({wrong_rpc_type, Type}),
    (PeerPid == PrevSenderPid) orelse error({wrong_sender_pid, PeerPid}),
    {ok, {ClientIp, ClientPort}} = Transport:peername(Sock),
    RpcCodec = mtp_layer:new(mtp_rpc, mtp_rpc:new(ClientIp, ClientPort, MyIp, MyPort, ProxyTag)),
    DownCodec1 = mtp_layer:new(mtp_wrap, mtp_wrap:new(RpcCodec, DownCodec)),
    {ok, S#state{down_codec = DownCodec1,
                 stage = tunnel,
                 stage_state = undefined}}.
%% Internal

get_external_ip(Sock) ->
    {ok, {MyIp, MyPort}} = inet:sockname(Sock),
    case application:get_env(?APP, external_ip) of
        {ok, IpStr} ->
            {ok, IP} = inet:parse_ipv4strict_address(IpStr),
            {IP, MyPort};
        undefined ->
            {MyIp, MyPort}
    end.

hex(Bin) ->
    <<begin
         if N < 10 ->
                 <<($0 + N)>>;
            true ->
                 <<($W + N)>>
         end
     end || <<N:4>> <= Bin>>.

unhex(Chars) ->
    UnHChar = fun(C) when C < $W -> C - $0;
                 (C) when C > $W -> C - $W
              end,
    << <<(UnHChar(C)):4>> || <<C>> <= Chars>>.


track(Direction, Data) ->
    Size = byte_size(Data),
    metric:count_inc([?APP, tracker, bytes], Size, #{labels => [Direction]}),
    metric:histogram_observe([?APP, tracker_packet_size, bytes], Size, #{labels => [Direction]}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-define(PROXY_SECRET,
        <<196,249,250,202,150,120,230,187,72,173,108,126,44,229,192,210,68,48,100,
          93,85,74,221,235,85,65,158,3,77,166,39,33,208,70,234,171,110,82,171,20,
          169,90,68,62,207,179,70,62,121,160,90,102,97,42,223,156,174,218,139,233,
          168,13,166,152,111,176,166,255,56,122,248,77,136,239,58,100,19,113,62,92,
          51,119,246,225,163,212,125,153,245,224,197,110,236,232,240,92,84,196,144,
          176,121,227,27,239,130,255,14,232,242,176,163,39,86,210,73,197,242,18,105,
          129,108,183,6,27,38,93,178,18>>).

middle_key_test() ->
    Args = #{srv_port => 80,
             srv_ip => mtp_obfuscated:bin_rev(mtp_rpc:inet_pton({149, 154, 162, 38})),
             srv_n => <<247,40,210,56,65,12,101,170,216,155,14,253,250,238,219,226>>,
             clt_n => <<24,49,53,111,198,10,235,180,230,112,92,78,1,201,106,105>>,
             clt_ip => mtp_obfuscated:bin_rev(mtp_rpc:inet_pton({80, 211, 29, 34})),
             clt_ts => 1528396015,
             clt_port => 54208,
             purpose => <<"CLIENT">>,
             secret => ?PROXY_SECRET
            },
    Key = <<165,158,127,49,41,232,187,69,38,29,163,226,183,146,28,67,225,224,134,191,207,152,255,166,152,66,169,196,54,135,50,188>>,
    IV = <<33,110,125,221,183,121,160,116,130,180,156,249,52,111,37,178>>,
    ?assertEqual(
       {Key, IV},
       get_middle_key(Args)).

-endif.
