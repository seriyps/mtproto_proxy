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
-export([start_link/4, send/2]).
-export([hex/1, unhex/1]).
-export([keys_str/0]).

%% Callbacks
-export([ranch_init/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-export_type([handle/0]).

-type handle() :: pid().

-define(MAX_SOCK_BUF_SIZE, 1024 * 50).    % Decrease if CPU is cheaper than RAM
-define(MAX_UP_INIT_BUF_SIZE, 1024 * 1024).     %1mb

-define(HEALTH_CHECK_INTERVAL, 5000).

-define(APP, mtproto_proxy).

-record(state,
        {stage = init :: stage(),
         stage_state = <<>> :: any(),
         acc = <<>> :: any(),

         secret :: binary(),
         listener :: atom(),

         sock :: gen_tcp:socket(),
         transport :: transport(),
         codec :: mtp_codec:codec() | undefined,

         down :: mtp_down_conn:handle() | undefined,
         dc_id :: {DcId :: integer(), Pool :: pid()} | undefined,

         ad_tag :: binary(),
         addr :: mtp_config:netloc(),           % IP/Port of remote side
         started_at :: pos_integer(),
         timer_state = init :: init | hibernate | stop,
         timer :: gen_timeout:tout(),
         last_queue_check :: integer()}).

-type transport() :: module().
-type stage() :: init | tunnel.


%% APIs

start_link(Ref, _Socket, Transport, Opts) ->
    {ok, proc_lib:spawn_link(?MODULE, ranch_init, [{Ref, Transport, Opts}])}.

keys_str() ->
    [{Name, Port, hex(Secret)}
     || {Name, Port, Secret} <- application:get_env(?APP, ports, [])].

-spec send(pid(), mtp_rpc:packet()) -> ok.
send(Upstream, Packet) ->
    gen_server:cast(Upstream, Packet).

%% Callbacks

%% Custom gen_server init
ranch_init({Ref, Transport, Opts}) ->
    {ok, Socket} = ranch:handshake(Ref),
    case init({Socket, Transport, Opts}) of
        {ok, State} ->
            BufSize = application:get_env(?APP, upstream_socket_buffer_size,
                                          ?MAX_SOCK_BUF_SIZE),
            ok = Transport:setopts(
                   Socket,
                   [{active, once},
                    %% {recbuf, ?MAX_SOCK_BUF_SIZE},
                    %% {sndbuf, ?MAX_SOCK_BUF_SIZE},
                    {buffer, BufSize}
                   ]),
            gen_server:enter_loop(?MODULE, [], State);
        {stop, error} ->
            exit(normal)
    end.

init({Socket, Transport, [Name, Secret, Tag]}) ->
    mtp_metric:count_inc([?APP, in_connection, total], 1, #{labels => [Name]}),
    case Transport:peername(Socket) of
        {ok, {Ip, Port}} ->
            lager:info("~s: new connection ~s:~p", [Name, inet:ntoa(Ip), Port]),
            {TimeoutKey, TimeoutDefault} = state_timeout(init),
            Timer = gen_timeout:new(
                      #{timeout => {env, ?APP, TimeoutKey, TimeoutDefault}}),
            NowMs = erlang:system_time(millisecond),
            State = #state{sock = Socket,
                           secret = unhex(Secret),
                           listener = Name,
                           transport = Transport,
                           ad_tag = unhex(Tag),
                           addr = {Ip, Port},
                           started_at = NowMs,
                           timer = Timer,
                           last_queue_check = NowMs},
            {ok, State};
        {error, Reason} ->
            mtp_metric:count_inc([?APP, in_connection_closed, total], 1, #{labels => [Name]}),
            lager:info("Can't read peername: ~p", [Reason]),
            {stop, error}
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast({proxy_ans, Down, Data}, #state{down = Down} = S) ->
    %% telegram server -> proxy
    {ok, S1} = up_send(Data, S),
    ok = mtp_down_conn:ack(Down, 1, iolist_size(Data)),
    maybe_check_health(bump_timer(S1));
handle_cast({close_ext, Down}, #state{down = Down, sock = USock, transport = UTrans} = S) ->
    lager:debug("asked to close connection by downstream"),
    ok = UTrans:close(USock),
    {stop, normal, S#state{down = undefined}};
handle_cast({simple_ack, Down, Confirm}, #state{down = Down} = S) ->
    lager:info("Simple ack: ~p, ~p", [Down, Confirm]),
    {noreply, S};
handle_cast(Other, State) ->
    lager:warning("Unexpected msg ~p", [Other]),
    {noreply, State}.

handle_info({tcp, Sock, Data}, #state{sock = Sock, transport = Transport,
                                      listener = Listener} = S) ->
    %% client -> proxy
    Size = byte_size(Data),
    mtp_metric:count_inc([?APP, received, upstream, bytes], Size, #{labels => [Listener]}),
    mtp_metric:histogram_observe([?APP, tracker_packet_size, bytes], Size, #{labels => [upstream]}),
    case handle_upstream_data(Data, S) of
        {ok, S1} ->
            ok = Transport:setopts(Sock, [{active, once}]),
            %% Consider checking health here as well
            {noreply, bump_timer(S1)};
        {error, Reason} ->
            lager:info("handle_data error ~p", [Reason]),
            {stop, normal, S}
    end;
handle_info({tcp_closed, Sock}, #state{sock = Sock} = S) ->
    lager:debug("upstream sock closed"),
    {stop, normal, maybe_close_down(S)};
handle_info({tcp_error, Sock, Reason}, #state{sock = Sock} = S) ->
    lager:warning("upstream sock error: ~p", [Reason]),
    {stop, normal, maybe_close_down(S)};

handle_info(timeout, #state{timer = Timer, timer_state = TState, listener = Listener} = S) ->
    case gen_timeout:is_expired(Timer) of
        true when TState == stop;
                  TState == init ->
            mtp_metric:count_inc([?APP, inactive_timeout, total], 1, #{labels => [Listener]}),
            lager:info("inactive timeout in state ~p", [TState]),
            {stop, normal, S};
        true when TState == hibernate ->
            mtp_metric:count_inc([?APP, inactive_hibernate, total], 1, #{labels => [Listener]}),
            {noreply, switch_timer(S, stop), hibernate};
        false ->
            Timer1 = gen_timeout:reset(Timer),
            {noreply, S#state{timer = Timer1}}
    end;
handle_info(Other, S) ->
    lager:warning("Unexpected msg ~p", [Other]),
    {noreply, S}.

terminate(_Reason, #state{started_at = Started, listener = Listener} = S) ->
    maybe_close_down(S),
    mtp_metric:count_inc([?APP, in_connection_closed, total], 1, #{labels => [Listener]}),
    Lifetime = erlang:system_time(millisecond) - Started,
    mtp_metric:histogram_observe(
      [?APP, session_lifetime, seconds],
      erlang:convert_time_unit(Lifetime, millisecond, native), #{labels => [Listener]}),
    lager:info("terminate ~p", [_Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

maybe_close_down(#state{down = undefined} = S) -> S;
maybe_close_down(#state{dc_id = {_DcId, Pool}} = S) ->
    mtp_dc_pool:return(Pool, self()),
    S#state{down = undefined}.

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
switch_timer(#state{timer_state = FromState, timer = Timer, listener = Listener} = S, ToState) ->
    mtp_metric:count_inc([?APP, timer_switch, total], 1,
                     #{labels => [Listener, FromState, ToState]}),
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
handle_upstream_data(Bin, #state{stage = tunnel,
                                 codec = UpCodec} = S) ->
    {ok, S3, UpCodec1} =
        mtp_codec:fold_packets(
          fun(Decoded, S1, Codec1) ->
                  mtp_metric:histogram_observe(
                    [?APP, tg_packet_size, bytes],
                    byte_size(Decoded),
                    #{labels => [upstream_to_downstream]}),
                  {ok, S2} = down_send(Decoded, S1#state{codec = Codec1}),
                  {S2, S2#state.codec}
          end, S, Bin, UpCodec),
    {ok, S3#state{codec = UpCodec1}};
handle_upstream_data(<<Header:64/binary, Rest/binary>>, #state{stage = init, stage_state = <<>>,
                                                               secret = Secret, listener = Listener} = S) ->
    case mtp_obfuscated:from_header(Header, Secret) of
        {ok, DcId, PacketLayerMod, CryptoCodecSt} ->
            mtp_metric:count_inc([?APP, protocol_ok, total],
                                 1, #{labels => [Listener, PacketLayerMod]}),
            PacketCodec = PacketLayerMod:new(),
            Codec = mtp_codec:new(mtp_obfuscated, CryptoCodecSt,
                                  PacketLayerMod, PacketCodec),
            handle_upstream_header(
              DcId,
              S#state{codec = Codec,
                      acc = Rest,
                      stage_state = undefined});
        {error, Reason} = Err ->
            mtp_metric:count_inc([?APP, protocol_error, total],
                                 1, #{labels => [Reason]}),
            Err
    end;
handle_upstream_data(Bin, #state{stage = init, stage_state = <<>>} = S) ->
    {ok, S#state{stage_state = Bin}};
handle_upstream_data(Bin, #state{stage = init, stage_state = Buf} = S) ->
    handle_upstream_data(<<Buf/binary, Bin/binary>> , S#state{stage_state = <<>>}).


up_send(Packet, #state{stage = tunnel,
                       codec = UpCodec,
                       sock = Sock,
                       transport = Transport,
                       listener = Listener} = S) ->
    %% lager:debug(">Up: ~p", [Packet]),
    {Encoded, UpCodec1} = mtp_codec:encode_packet(Packet, UpCodec),
    mtp_metric:rt([?APP, upstream_send_duration, seconds],
              fun() ->
                      case Transport:send(Sock, Encoded) of
                          ok ->
                              mtp_metric:count_inc(
                                [?APP, sent, upstream, bytes],
                                iolist_size(Encoded), #{labels => [Listener]}),
                              ok;
                          {error, Reason} ->
                              is_atom(Reason) andalso
                                  mtp_metric:count_inc(
                                    [?APP, upstream_send_error, total], 1,
                                    #{labels => [Listener, Reason]}),
                              lager:warning("Upstream send error: ~p", [Reason]),
                              throw({stop, normal, S})
                      end
              end, #{labels => [Listener]}),
    {ok, S#state{codec = UpCodec1}}.

down_send(Packet, #state{down = Down} = S) ->
    %% lager:debug(">Down: ~p", [Packet]),
    case mtp_down_conn:send(Down, Packet) of
        ok ->
            {ok, S};
        {error, unknown_upstream} ->
            handle_unknown_upstream(S)
    end.

handle_unknown_upstream(#state{down = Down, sock = USock, transport = UTrans} = S) ->
    %% there might be a race-condition between packets from upstream socket and
    %% downstream's 'close_ext' message. Most likely because of slow up_send
    ok = UTrans:close(USock),
    receive
        {'$gen_cast', {close_ext, Down}} ->
            lager:debug("asked to close connection by downstream"),
            throw({stop, normal, S#state{down = undefined}})
    after 0 ->
            throw({stop, got_unknown_upstream, S})
    end.


%% Internal


handle_upstream_header(DcId, #state{acc = Acc, ad_tag = Tag, addr = Addr} = S) ->
    Opts = #{ad_tag => Tag,
             addr => Addr},
    {RealDcId, Pool, Downstream} = mtp_config:get_downstream_safe(DcId, Opts),
    handle_upstream_data(
      Acc,
      switch_timer(
        S#state{down = Downstream,
                dc_id = {RealDcId, Pool},
                acc = <<>>,
                stage = tunnel},
        hibernate)).


%% @doc Terminate if message queue is too big
maybe_check_health(#state{last_queue_check = LastCheck} = S) ->
    NowMs = erlang:system_time(millisecond),
    Delta = NowMs - LastCheck,
    case Delta < ?HEALTH_CHECK_INTERVAL of
        true ->
            {noreply, S};
        false ->
            case check_health() of
                ok ->
                    {noreply, S#state{last_queue_check = NowMs}};
                overflow ->
                    {stop, normal, S}
            end
    end.

%% 1. If proc queue > qlen - stop
%% 2. If proc total memory > gc - do GC and go to 3
%% 3. If proc total memory > total_mem - stop
check_health() ->
    %% see .app.src
    Defaults = [{qlen, 300},
                {gc, 409600},
                {total_mem, 3145728}],
    Checks = application:get_env(?APP, upstream_healthchecks, Defaults),
    do_check_health(Checks, calc_health()).

do_check_health([{qlen, Limit} | _], #{message_queue_len := QLen} = Health) when QLen > Limit ->
    mtp_metric:count_inc([?APP, healthcheck, total], 1,
                         #{labels => [message_queue_len]}),
    lager:warning("Upstream too large queue_len=~w, health=~p", [QLen, Health]),
    overflow;
do_check_health([{gc, Limit} | Other], #{total_mem := TotalMem}) when TotalMem > Limit ->
    %% Maybe it doesn't makes sense to do GC if queue len is more than, eg, 50?
    %% In this case allmost all memory will be in msg queue
    mtp_metric:count_inc([?APP, healthcheck, total], 1,
                         #{labels => [force_gc]}),
    erlang:garbage_collect(self()),
    do_check_health(Other, calc_health());
do_check_health([{total_mem, Limit} | _Other], #{total_mem := TotalMem} = Health) when
      TotalMem > Limit ->
    mtp_metric:count_inc([?APP, healthcheck, total], 1,
                         #{labels => [total_memory]}),
    lager:warning("Process too large total_mem=~p, health=~p",
                  [TotalMem / 1024, Health]),
    overflow;
do_check_health([_Ok | Other], Health) ->
    do_check_health(Other, Health);
do_check_health([], _) ->
    ok.

calc_health() ->
    [{_, QLen}, {_, Mem}, {_, BinInfo}] =
        erlang:process_info(self(), [message_queue_len, memory, binary]),
    RefcBinSize = sum_binary(BinInfo),
    TotalMem = Mem + RefcBinSize,
    #{message_queue_len => QLen,
      memory => Mem,
      refc_bin_size => RefcBinSize,
      refc_bin_count => length(BinInfo),
      total_mem => TotalMem}.

sum_binary(BinInfo) ->
    trunc(lists:foldl(fun({_, Size, RefC}, Sum) ->
                              Sum + (Size / RefC)
                      end, 0, BinInfo)).

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
