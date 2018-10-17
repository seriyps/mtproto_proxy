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

-define(APP, mtproto_proxy).

-record(state,
        {stage = init :: stage(),
         stage_state = <<>> :: any(),
         acc = <<>> :: any(),

         secret :: binary(),

         sock :: gen_tcp:socket(),
         transport :: transport(),
         codec = ident :: mtp_layer:layer(),

         down :: gen_tcp:socket(),
         dc_id :: integer(),

         ad_tag :: binary(),
         addr :: mtp_config:netloc(),           % IP/Port of remote side
         started_at :: pos_integer(),
         timer_state = init :: init | hibernate | stop,
         timer :: gen_timeout:tout()}).

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
        error ->
            mtp_metric:count_inc([?APP, in_connection_closed, total], 1, #{}),
            exit(normal)
    end.

init({Socket, Transport, [Name, Secret, Tag]}) ->
    mtp_metric:set_context_labels([Name]),
    mtp_metric:count_inc([?APP, in_connection, total], 1, #{}),
    case Transport:peername(Socket) of
        {ok, {Ip, Port}} ->
            lager:info("~s: new connection ~s:~p", [Name, inet:ntoa(Ip), Port]),
            {TimeoutKey, TimeoutDefault} = state_timeout(init),
            Timer = gen_timeout:new(
                      #{timeout => {env, ?APP, TimeoutKey, TimeoutDefault}}),
            State = #state{sock = Socket,
                           secret = unhex(Secret),
                           transport = Transport,
                           ad_tag = unhex(Tag),
                           addr = {Ip, Port},
                           started_at = erlang:system_time(millisecond),
                           timer = Timer},
            {ok, State};
        {error, Reason} ->
            lager:info("Can't read peername: ~p", [Reason]),
            error
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast({proxy_ans, Down, Data}, #state{down = Down} = S) ->
    %% telegram server -> proxy
    case up_send(Data, S) of
        {ok, S1} ->
            {noreply, bump_timer(S1)};
        {error, Reason} ->
            lager:error("Error sending tunnelled data to in socket: ~p", [Reason]),
            {stop, normal, S}
    end;
handle_cast({close_ext, Down}, #state{down = Down, sock = USock, transport = UTrans} = S) ->
    lager:debug("asked to close connection by downstream"),
    ok = UTrans:close(USock),
    {stop, normal, S};
handle_cast({simple_ack, Down, Confirm}, #state{down = Down} = S) ->
    lager:info("Simple ack: ~p, ~p", [Down, Confirm]),
    {noreply, S};
handle_cast(Other, State) ->
    lager:warning("Unexpected msg ~p", [Other]),
    {noreply, State}.

handle_info({tcp, Sock, Data}, #state{sock = Sock,
                                      transport = Transport} = S) ->
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
handle_info({tcp_closed, Sock}, #state{sock = Sock} = S) ->
    lager:debug("upstream sock closed"),
    {stop, normal, maybe_close_down(S)};
handle_info({tcp_error, Sock, Reason}, #state{sock = Sock} = S) ->
    lager:info("upstream sock error: ~p", [Reason]),
    {stop, Reason, maybe_close_down(S)};

handle_info(timeout, #state{timer = Timer, timer_state = TState} = S) ->
    case gen_timeout:is_expired(Timer) of
        true when TState == stop;
                  TState == init ->
            mtp_metric:count_inc([?APP, inactive_timeout, total], 1, #{}),
            lager:info("inactive timeout in state ~p", [TState]),
            {stop, normal, S};
        true when TState == hibernate ->
            mtp_metric:count_inc([?APP, inactive_hibernate, total], 1, #{}),
            {noreply, switch_timer(S, stop), hibernate};
        false ->
            Timer1 = gen_timeout:reset(Timer),
            {noreply, S#state{timer = Timer1}}
    end;
handle_info(Other, S) ->
    lager:warning("Unexpected msg ~p", [Other]),
    {noreply, S}.

terminate(_Reason, #state{started_at = Started} = S) ->
    maybe_close_down(S),
    mtp_metric:count_inc([?APP, in_connection_closed, total], 1, #{}),
    Lifetime = erlang:system_time(millisecond) - Started,
    mtp_metric:histogram_observe(
      [?APP, session_lifetime, seconds],
      erlang:convert_time_unit(Lifetime, millisecond, native), #{}),
    lager:debug("terminate ~p", [_Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

maybe_close_down(#state{down = undefined} = S) -> S;
maybe_close_down(#state{dc_id = DcId} = S) ->
    {ok, Pool} = mtp_config:get_downstream_pool(DcId),
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
switch_timer(#state{timer_state = FromState, timer = Timer} = S, ToState) ->
    mtp_metric:count_inc([?APP, timer_switch, total], 1,
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
handle_upstream_data(Bin, #state{stage = tunnel,
                                 codec = UpCodec} = S) ->
    {ok, S3, UpCodec1} =
        mtp_layer:fold_packets(
          fun(Decoded, S1) ->
                  mtp_metric:histogram_observe(
                    [?APP, tg_packet_size, bytes],
                    byte_size(Decoded),
                    #{labels => [upstream_to_downstream]}),
                  {ok, S2} = down_send(Decoded, S1),
                  S2
          end, S, Bin, UpCodec),
    {ok, S3#state{codec = UpCodec1}};
handle_upstream_data(<<Header:64/binary, Rest/binary>>, #state{stage = init, stage_state = <<>>,
                                                               secret = Secret} = S) ->
    case mtp_obfuscated:from_header(Header, Secret) of
        {ok, DcId, PacketLayerMod, ObfuscatedCodec} ->
            mtp_metric:count_inc([?APP, protocol_ok, total],
                                 1, #{labels => [PacketLayerMod]}),
            ObfuscatedLayer = mtp_layer:new(mtp_obfuscated, ObfuscatedCodec),
            PacketLayer = mtp_layer:new(PacketLayerMod, PacketLayerMod:new()),
            UpCodec = mtp_layer:new(mtp_wrap, mtp_wrap:new(PacketLayer,
                                                           ObfuscatedLayer)),
            handle_upstream_header(
              DcId,
              S#state{codec = UpCodec,
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
                       transport = Transport} = S) ->
    lager:debug(">TG: ~p", [Packet]),
    {Encoded, UpCodec1} = mtp_layer:encode_packet(Packet, UpCodec),
    mtp_metric:rt([?APP, upstream_send_duration, seconds],
              fun() ->
                      case Transport:send(Sock, Encoded) of
                          ok -> ok;
                          {error, Reason} ->
                              is_atom(Reason) andalso
                                  mtp_metric:count_inc(
                                    [?APP, upstream_send_error, total], 1,
                                    #{labels => [Reason]}),
                              lager:warning("Upstream send error: ~p", [Reason]),
                              throw({stop, normal, S})
                      end
              end),
    {ok, S#state{codec = UpCodec1}}.

down_send(Packet, #state{down = Down} = S) ->
    lager:debug("<TG: ~p", [Packet]),
    ok = mtp_down_conn:send(Down, Packet),
    {ok, S}.


%% Internal


handle_upstream_header(DcId, #state{acc = Acc, ad_tag = Tag, addr = Addr} = S) ->
    Opts = #{ad_tag => Tag,
             addr => Addr},
    {RealDcId, _Pool, Downstream} = mtp_config:get_downstream_safe(DcId, Opts),
    handle_upstream_data(
      Acc,
      switch_timer(
        S#state{down = Downstream,
                dc_id = RealDcId,
                acc = <<>>,
                stage = tunnel},
        hibernate)).

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
    mtp_metric:count_inc([?APP, tracker, bytes], Size, #{labels => [Direction]}),
    mtp_metric:histogram_observe([?APP, tracker_packet_size, bytes], Size, #{labels => [Direction]}).
