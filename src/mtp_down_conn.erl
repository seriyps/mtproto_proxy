%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Process holding connection to downstream and doing multiplexing
%%% @end
%%% Created : 14 Oct 2018 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_down_conn).

-behaviour(gen_server).

%% API
-export([start_link/2,
         upstream_new/3,
         upstream_closed/2,
         shutdown/1,
         send/2,
         ack/3,
         set_config/3]).
-ifdef(TEST).
-export([get_middle_key/1]).
-endif.

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-export_type([handle/0, upstream_opts/0]).

-include_lib("hut/include/hut.hrl").

-define(SERVER, ?MODULE).
-define(APP, mtproto_proxy).
-define(CONN_TIMEOUT, 10000).
-define(SEND_TIMEOUT, 15000).
-define(HANDSHAKE_TIMEOUT, 8000).
-define(MAX_SOCK_BUF_SIZE, 1024 * 500).    % Decrease if CPU is cheaper than RAM
-define(MAX_CODEC_BUFFERS, 5 * 1024 * 1024).
-define(DEFAULT_CLIENTS_PER_CONN, 300).

-ifndef(OTP_RELEASE).                           % pre-OTP21
-define(WITH_STACKTRACE(T, R, S), T:R -> S = erlang:get_stacktrace(), ).
-else.
-define(WITH_STACKTRACE(T, R, S), T:R:S ->).
-endif.

-type handle() :: pid().
-type upstream_opts() :: #{addr := mtp_config:netloc_v4v6(), % IP/Port of TG client
                           ad_tag => binary()}.
-type upstream() :: {
                _UpsStatic ::{_ConnId :: mtp_rpc:conn_id(),
                              _Addr :: binary(),
                              _AdTag :: binary() | undefined},
                _NonAckCount :: non_neg_integer(),
                _NonAckBytes :: non_neg_integer()
               }.
-type stage() :: init | handshake_1 | handshake_2 | tunnel.

-record(state, {stage = init :: stage(),
                stage_state = [] :: any(),
                sock :: gen_tcp:socket() | undefined,
                addr_bin :: binary() | undefined,           % my external ip:port
                codec :: mtp_codec:codec() | undefined,
                upstreams = #{} :: #{mtp_handler:handle() => upstream()},
                upstreams_rev = #{} :: #{mtp_rpc:conn_id() => mtp_handler:handle()},
                overflow_passive = false :: boolean(),
                non_ack_count = 0 :: non_neg_integer(),
                non_ack_bytes = 0 :: non_neg_integer(),
                backpressure_conf :: {
                  %%ovarall max num non acked packets
                  non_neg_integer(),
                  %%ovarall max non acked bytes
                  non_neg_integer(),
                  %%max non acked packets per-upstream
                  non_neg_integer() | float() | undefined,
                  %%max non-acked bytes per-upstream
                  non_neg_integer() | undefined},
                pool :: pid(),
                dc_id :: mtp_config:dc_id(),
                netloc :: mtp_config:netloc() | undefined   % telegram server ip:port
               }).

start_link(Pool, DcId) ->
    gen_server:start_link(?MODULE, [Pool, DcId], []).

%% To be called by mtp_dc_pool
upstream_new(Conn, Upstream, #{addr := _} = Opts) ->
    gen_server:cast(Conn, {upstream_new, Upstream, Opts}).

%% To be called by mtp_dc_pool
upstream_closed(Conn, Upstream) ->
    gen_server:cast(Conn, {upstream_closed, Upstream}).

%% To be called by mtp_dc_pool
shutdown(Conn) ->
    gen_server:cast(Conn, shutdown).

%% To be called by upstream
-spec send(handle(), iodata()) -> ok | {error, unknown_upstream}.
send(Conn, Data) ->
    gen_server:call(Conn, {send, Data}, ?SEND_TIMEOUT * 2).

-spec ack(handle(), pos_integer(), pos_integer()) -> ok.
ack(Conn, Count, Size) ->
    gen_server:cast(Conn, {ack, self(), Count, Size}).

-spec set_config(handle(), atom(), any()) -> {ok, OldValue :: any()} | ignored.
set_config(Conn, Option, Value) ->
    gen_server:call(Conn, {set_config, Option, Value}).

init([Pool, DcId]) ->
    self() ! do_connect,
    BpOpts = application:get_env(?APP, downstream_backpressure, #{}),
    UpsPerDown = application:get_env(?APP, clients_per_dc_connection, ?DEFAULT_CLIENTS_PER_CONN),
    BackpressureConf = build_backpressure_conf(UpsPerDown, BpOpts),
    {ok, #state{backpressure_conf = BackpressureConf,
                pool = Pool,
                dc_id = DcId}}.

handle_call({send, Data}, {Upstream, _}, State) ->
    {Res, State1} = handle_send(Data, Upstream, State),
    {reply, Res, State1};
handle_call({set_config, Name, Value}, _From, State) ->
    {Response, State1} =
        case Name of
            downstream_socket_buffer_size when is_integer(Value),
                                               Value >= 512 ->
                {ok, [{buffer, OldSize}]} = inet:getopts(State#state.sock, [buffer]),
                ok = inet:setopts(State#state.sock, [{buffer, Value}]),
                {{ok, OldSize}, State};
            downstream_backpressure when is_map(Value) ->
                UpsPerDown = application:get_env(?APP, clients_per_dc_connection, ?DEFAULT_CLIENTS_PER_CONN),
                try build_backpressure_conf(UpsPerDown, Value) of
                    BpConfig ->
                        {{ok, State#state.backpressure_conf},
                          State#state{backpressure_conf = BpConfig}}
                catch Type:Reason ->
                        ?log(error, "~p: not updating downstream_backpressure: ~p",
                             [Type, Reason]),
                        {ignored, State}
                end;
            _ ->
                ?log(warning, "set_config ~p=~p ignored", [Name, Value]),
                {ignored, State}
        end,
    {reply, Response, State1}.

handle_cast({ack, Upstream, Count, Size}, State) ->
    {noreply, handle_ack(Upstream, Count, Size, State)};
handle_cast({upstream_new, Upstream, Opts}, State) ->
    {noreply, handle_upstream_new(Upstream, Opts, State)};
handle_cast({upstream_closed, Upstream}, State) ->
    {ok, St} = handle_upstream_closed(Upstream, State),
    {noreply, St};
handle_cast(shutdown, State) ->
    {stop, shutdown, State}.

handle_info({tcp, Sock, Data}, #state{sock = Sock, dc_id = DcId} = S) ->
    mtp_metric:count_inc([?APP, received, downstream, bytes], byte_size(Data), #{labels => [DcId]}),
    mtp_metric:histogram_observe([?APP, tracker_packet_size, bytes], byte_size(Data), #{labels => [downstream]}),
    {ok, S1} = handle_downstream_data(Data, S),
    activate_if_no_overflow(S1),
    {noreply, S1};
handle_info({tcp_closed, Sock}, #state{sock = Sock} = State) ->
    {stop, downstream_socket_closed, State};
handle_info({tcp_error, Sock, Reason}, #state{sock = Sock} = State) ->
    {stop, {downstream_tcp_error, Reason}, State};
handle_info(do_connect, #state{dc_id = DcId} = State) ->
    try
        {ok, St1} = connect(DcId, State),
        {noreply, St1}
    catch ?WITH_STACKTRACE(Class, Reason, Stack)
            ?log(error, "Down connect to dc=~w error: ~s",
                 [DcId, lager:pr_stacktrace(Stack, {Class, Reason})]), %XXX lager-specific
            erlang:send_after(300, self(), do_connect),
            {noreply, State}
    end;
handle_info(handshake_timeout, #state{stage = Stage, dc_id = DcId} = St) ->
    case Stage of
        tunnel ->
            %% race-condition between deadline timer and actual handshake completion
            %% (so, handshake completed exactly at deadline time)
            {noreply, St};
        _ ->
            {stop, {downstream_handshake_timeout, DcId, Stage}, St}
    end.


terminate(_Reason, #state{upstreams = Ups}) ->
    %% Should I do this or dc_pool? Maybe only when reason is 'normal'?
    ?log(warning, "Downstream terminates with reason ~p; len(upstreams)=~p",
         [_Reason, map_size(Ups)]),
    Self = self(),
    lists:foreach(
      fun(Upstream) ->
              ok = mtp_handler:send(Upstream, {close_ext, Self})
      end, maps:keys(Ups)),
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Send packet from upstream to downstream
handle_send(Data, Upstream, #state{upstreams = Ups,
                                   addr_bin = ProxyAddr} = St) ->
    case Ups of
        #{Upstream := {UpstreamStatic, _, _}} ->
            Packet = mtp_rpc:encode_packet({data, Data}, {UpstreamStatic, ProxyAddr}),
            down_send(Packet, St);
        _ ->
            ?log(warning, "Upstream=~p not found", [Upstream]),
            {{error, unknown_upstream}, St}
    end.

%% New upstream connected
handle_upstream_new(Upstream, Opts, #state{upstreams = Ups,
                                           upstreams_rev = UpsRev} = St) ->
    ConnId = erlang:unique_integer(),
    {Ip, Port} = maps:get(addr, Opts),
    AdTag = maps:get(ad_tag, Opts, undefined),
    UpsStatic = {ConnId, iolist_to_binary(mtp_rpc:encode_ip_port(Ip, Port)), AdTag},
    Ups1 = Ups#{Upstream => {UpsStatic, 0, 0}},
    UpsRev1 = UpsRev#{ConnId => Upstream},
    ?log(debug, "New upstream=~p conn_id=~p", [Upstream, ConnId]),
    St#state{upstreams = Ups1,
             upstreams_rev = UpsRev1}.

%% Upstream process is exited (or about to exit)
handle_upstream_closed(Upstream, #state{upstreams = Ups,
                                        upstreams_rev = UpsRev} = St) ->
    %% See "mtproto-proxy.c:remove_ext_connection
    case maps:take(Upstream, Ups) of
        {{{ConnId, _, _}, _, _}, Ups1} ->
            St1 = non_ack_cleanup_upstream(Upstream, St),
            UpsRev1 = maps:remove(ConnId, UpsRev),
            St2 = St1#state{upstreams = Ups1,
                            upstreams_rev = UpsRev1},
            Packet = mtp_rpc:encode_packet(remote_closed, ConnId),
            down_send(Packet, St2);
        error ->
            %% It happens when we get rpc_close_ext
            ?log(info, "Unknown upstream ~p", [Upstream]),
            {ok, St}
    end.


handle_downstream_data(Bin, #state{stage = tunnel,
                                   codec = DownCodec} = S) ->
    {ok, S3, DownCodec1} =
        mtp_codec:fold_packets(
          fun(Decoded, S1, Codec1) ->
                  mtp_metric:histogram_observe(
                    [?APP, tg_packet_size, bytes],
                    byte_size(Decoded),
                    #{labels => [downstream_to_upstream]}),
                  S2 = handle_rpc(mtp_rpc:decode_packet(Decoded), S1#state{codec = Codec1}),
                  {S2, S2#state.codec}
          end, S, Bin, DownCodec),
    {ok, S3#state{codec = DownCodec1}};
handle_downstream_data(Bin, #state{stage = handshake_1,
                                   codec = DownCodec} = S) ->
    case mtp_codec:try_decode_packet(Bin, DownCodec) of
        {ok, Packet, DownCodec1} ->
            down_handshake2(Packet, S#state{codec = DownCodec1});
        {incomplete, DownCodec1} ->
            {ok, S#state{codec = DownCodec1}}
    end;
handle_downstream_data(Bin, #state{stage = handshake_2,
                                   codec = DownCodec} = S) ->
    case mtp_codec:try_decode_packet(Bin, DownCodec) of
        {ok, Packet, DownCodec1} ->
            %% TODO: There might be something in downstream buffers after stage3,
            %% would be nice to run foldl
            down_handshake3(Packet, S#state{codec = DownCodec1});
        {incomplete, DownCodec1} ->
            {ok, S#state{codec = DownCodec1}}
    end.

-spec handle_rpc(mtp_rpc:packet(), #state{}) -> #state{}.
handle_rpc({proxy_ans, ConnId, Data}, St) ->
    up_send({proxy_ans, self(), Data}, ConnId, St);
handle_rpc({close_ext, ConnId}, St) ->
    #state{upstreams = Ups,
           upstreams_rev = UpsRev} = St1 = up_send({close_ext, self()}, ConnId, St),
    case maps:take(ConnId, UpsRev) of
        {Upstream, UpsRev1} ->
            St2 = non_ack_cleanup_upstream(Upstream, St1),
            Ups1 = maps:remove(Upstream, Ups),
            St2#state{upstreams = Ups1,
                      upstreams_rev = UpsRev1};
        error ->
            ?log(warning, "Unknown upstream ~p", [ConnId]),
            St1
    end;
handle_rpc({simple_ack, ConnId, Confirm}, S) ->
    up_send({simple_ack, self(), Confirm}, ConnId, S).

-spec down_send(iodata(), #state{}) -> {ok, #state{}}.
down_send(Packet, #state{sock = Sock, codec = Codec, dc_id = DcId} = St) ->
    %% ?log(debug, "Up>Down: ~w", [Packet]),
    {Encoded, Codec1} = mtp_codec:encode_packet(Packet, Codec),
    mtp_metric:rt(
      [?APP, downstream_send_duration, seconds],
      fun() ->
              ok = gen_tcp:send(Sock, Encoded),
              mtp_metric:count_inc(
                [?APP, sent, downstream, bytes],
                iolist_size(Encoded), #{labels => [DcId]})
      end, #{labels => [DcId]}),
    {ok, St#state{codec = Codec1}}.


up_send(Packet, ConnId, #state{upstreams_rev = UpsRev} = St) ->
    case maps:find(ConnId, UpsRev) of
        {ok, Upstream} ->
            ok = mtp_handler:send(Upstream, Packet),
            case Packet of
                {proxy_ans, _, Data} ->
                    non_ack_bump(Upstream, iolist_size(Data), St);
                _ ->
                    St
            end;
        error ->
            ?log(warning, "Unknown connection_id=~w", [ConnId]),
            %% WHY!!!?
            %% ClosedPacket = mtp_rpc:encode_packet(remote_closed, ConnId),
            %% {ok, St1} = down_send(ClosedPacket, St),
            St
    end.


%%
%% Backpressure
%%

build_backpressure_conf(UpstreamsPerDownstream, BpConf) ->
    BytesTotal = maps:get(bytes_total, BpConf, UpstreamsPerDownstream * 30 * 1024),
    PacketsTotal = maps:get(packets_total, BpConf, UpstreamsPerDownstream * 2),
    BytesPerUpstream = maps:get(bytes_per_upstream, BpConf, undefined),
    PacketsPerUpstream = maps:get(packets_per_upstream, BpConf, undefined),
    (is_integer(BytesTotal)
     andalso (BytesTotal > 1024)
     andalso is_integer(PacketsTotal)
     andalso (PacketsTotal > 10))
        orelse error({invalid_downstream_backpressure, BpConf}),
    ((undefined == BytesPerUpstream)
     orelse (is_integer(BytesPerUpstream)
             andalso BytesPerUpstream >= 1024))
        orelse error({invalid_bytes_per_upstream, BytesPerUpstream}),
    ((undefined == PacketsPerUpstream)
     orelse (is_number(PacketsPerUpstream)
             andalso PacketsPerUpstream >= 1))
        orelse error({invalid_bytes_per_upstream, PacketsPerUpstream}),
    {PacketsTotal, BytesTotal, PacketsPerUpstream, BytesPerUpstream}.

%% Bumb counters of non-acked packets
non_ack_bump(Upstream, Size, #state{non_ack_count = Cnt,
                                    non_ack_bytes = Oct,
                                    upstreams = Ups} = St) ->
    {UpsStatic, UpsCnt, UpsOct} = maps:get(Upstream, Ups),
    maybe_deactivate(
      St#state{non_ack_count = Cnt + 1,
               non_ack_bytes = Oct + Size,
               upstreams = Ups#{Upstream := {UpsStatic,
                                             UpsCnt + 1,
                                             UpsOct + Size}}}).

%% Do we have too much unconfirmed packets?
is_overflow(#state{non_ack_count = Cnt,
                   backpressure_conf = {MaxCount, _, _, _}}) when Cnt > MaxCount ->
    count_total;
is_overflow(#state{non_ack_bytes = Oct,
                   backpressure_conf = {_, MaxOct, _, _}}) when Oct > MaxOct ->
    bytes_total;
is_overflow(#state{non_ack_count = Cnt,
                   upstreams = Ups,
                   backpressure_conf = {_, _, MaxPerConCnt, _}}) when
      is_number(MaxPerConCnt),
      Cnt > (map_size(Ups) * MaxPerConCnt) ->
    count_per_upstream;
is_overflow(#state{non_ack_bytes = Oct,
                   upstreams = Ups,
                   backpressure_conf = {_, _, _, MaxPerConOct}}) when
      is_integer(MaxPerConOct),
      Oct > (map_size(Ups) * MaxPerConOct) ->
    bytes_per_upstream;
is_overflow(_) ->
    false.

%% If we are not overflown and socket is passive, activate it
activate_if_no_overflow(#state{overflow_passive = false, sock = Sock}) ->
    ok = inet:setopts(Sock, [{active, once}]),
    true;
activate_if_no_overflow(_) ->
    false.


%% Decrement counters and activate socket only if overflow was just resolved
handle_ack(Upstream, Count, Size, #state{non_ack_count = Cnt,
                                         non_ack_bytes = Oct,
                                         upstreams = Ups} = St) ->
    case maps:get(Upstream, Ups, undefined) of
        undefined ->
            %% all upstream's counters should already be handled by cleanup_upstream
            St;
        {UpsStatic, UpsCnt, UpsOct} ->
            maybe_activate(
              St#state{non_ack_count = Cnt - Count,
                       non_ack_bytes = Oct - Size,
                       upstreams = Ups#{Upstream := {UpsStatic,
                                                     UpsCnt - Count,
                                                     UpsOct - Size}}})
    end.

maybe_deactivate(#state{overflow_passive = false, dc_id = Dc} = St) ->
    case is_overflow(St) of
        false ->
            %% Was not overflow and still not
            St;
        Type ->
            %% Was not overflow, now overflowed
            mtp_metric:count_inc([?APP, down_backpressure, total], 1,
                                 #{labels => [Dc, Type]}),
            St#state{overflow_passive = true}
    end;
maybe_deactivate(St) ->
    St.

%% Activate socket if we changed state from overflow to ok
maybe_activate(#state{overflow_passive = true, sock = Sock, dc_id = Dc} = St) ->
    case is_overflow(St) of
        false ->
            %% Was overflow, but now resolved
            ok = inet:setopts(Sock, [{active, once}]),
            mtp_metric:count_inc([?APP, down_backpressure, total], 1,
                                 #{labels => [Dc, off]}),
            St#state{overflow_passive = false};
        _ ->
            %% Still overflow
            St
    end;
maybe_activate(#state{} = St) ->
    St.

%% Reset counters for upstream that was terminated
non_ack_cleanup_upstream(Upstream, #state{non_ack_count = Cnt,
                                          non_ack_bytes = Oct,
                                          upstreams = Ups} = St) ->
    {_, UpsCnt, UpsOct} = maps:get(Upstream, Ups),
    maybe_activate(
      St#state{non_ack_count = Cnt - UpsCnt,
               non_ack_bytes = Oct - UpsOct}).


%%
%% Connect / handshake
%%

connect(DcId, S) ->
    {ok, {Host, Port}} = mtp_config:get_netloc(DcId),
    case tcp_connect(Host, Port) of
        {ok, Sock} ->
            mtp_metric:count_inc([?APP, out_connect_ok, total], 1,
                                 #{labels => [DcId]}),
            AddrStr = inet:ntoa(Host),
            ?log(info, "~s:~p: TCP connected", [AddrStr, Port]),
            down_handshake1(S#state{sock = Sock,
                                    netloc = {Host, Port}});
        {error, Reason} = Err ->
            mtp_metric:count_inc([?APP, out_connect_error, total], 1,
                                 #{labels => [DcId, Reason]}),
            {Err, S}
    end.

tcp_connect(Host, Port) ->
    BufSize = application:get_env(?APP, downstream_socket_buffer_size,
                                  ?MAX_SOCK_BUF_SIZE),
    SockOpts = [{active, once},
                {packet, raw},
                {mode, binary},
                {buffer, BufSize},
                {send_timeout, ?SEND_TIMEOUT},
                %% {nodelay, true},
                {keepalive, true}],
    case gen_tcp:connect(Host, Port, SockOpts, ?CONN_TIMEOUT) of
        {ok, Sock} ->
            {ok, Sock};
        {error, _} = Err ->
            Err
    end.

down_handshake1(S) ->
    <<KeySelector:4/binary, _/binary>> = Key = mtp_config:get_secret(),
    CryptoTs = os:system_time(seconds),
    Nonce = crypto:strong_rand_bytes(16),
    Schema = 1,                                 %AES
    Msg = mtp_rpc:encode_nonce({nonce, KeySelector, Schema, CryptoTs, Nonce}),
    Deadline = erlang:send_after(?HANDSHAKE_TIMEOUT, self(), handshake_timeout),
    CheckCRC = application:get_env(?APP, mtp_full_check_crc32, true),
    S1 = S#state{stage = handshake_1,
                 %% Use fake encryption codec
                 codec = mtp_codec:new(mtp_noop_codec, mtp_noop_codec:new(),
                                       mtp_full, mtp_full:new(-2, -2, CheckCRC),
                                       false, undefined, ?MAX_CODEC_BUFFERS),
                 stage_state = {Deadline, KeySelector, Nonce, CryptoTs, Key}},
    down_send(Msg, S1).

down_handshake2(Pkt, #state{stage_state = {Deadline, MyKeySelector, CliNonce, MyTs, Key},
                            codec = Codec1,
                            sock = Sock} = S) ->
    {nonce, KeySelector, Schema, _CryptoTs, SrvNonce} = mtp_rpc:decode_nonce(Pkt),
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
    CryptoState = mtp_aes_cbc:new(EncKey, EncIv, DecKey, DecIv, 16),
    Codec = mtp_codec:replace(crypto, mtp_aes_cbc, CryptoState, Codec1),
    SenderPID = PeerPID = <<"IPIPPRPDTIME">>,
    Handshake = mtp_rpc:encode_handshake({handshake, SenderPID, PeerPID}),
    down_send(Handshake,
              S#state{codec = Codec,
                      stage = handshake_2,
                      addr_bin = iolist_to_binary(mtp_rpc:encode_ip_port(MyIp, MyPort)),
                      stage_state = {Deadline, SenderPID}}).

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


down_handshake3(Pkt, #state{stage_state = {Deadline, PrevSenderPid}, pool = Pool, dc_id = DcId,
                            netloc = {Addr, Port}} = S) ->
    erlang:cancel_timer(Deadline),
    {handshake, _SenderPid, PeerPid} = mtp_rpc:decode_handshake(Pkt),
    (PeerPid == PrevSenderPid) orelse error({wrong_sender_pid, PeerPid}),
    ok = mtp_dc_pool:ack_connected(Pool, self()),
    ?log(info, "~s:~w: dc=~w handshake complete", [inet:ntoa(Addr), Port, DcId]),
    {ok, S#state{stage = tunnel,
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
