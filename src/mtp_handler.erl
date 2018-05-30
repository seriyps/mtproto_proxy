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
-export([hex/1]).
-export([key_str/0]).

%% Callbacks
-export([ranch_init/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(MAX_SOCK_BUF_SIZE, 1024 * 300).    % Decrease if CPU is cheaper than RAM
-define(APP, mtproto_proxy).

-record(state,
        {stage = init :: stage(),
         init_buf = <<>> :: binary(),
         up_sock :: gen_tcp:socket(),
         up_transport :: transport(),
         up_codec :: mtp_obfuscated:codec(),
         down_sock :: gen_tcp:socket(),
         started :: pos_integer(),
         timer_state = init :: init | hibernate | stop,
         timer :: gen_timeout:tout()}).

-type transport() :: module().
-type stage() :: init | tunnel.


%% APIs

start_link(Ref, Socket, Transport, Opts) ->
    {ok, proc_lib:spawn_link(?MODULE, ranch_init, [{Ref, Socket, Transport, Opts}])}.

key_str() ->
    {ok, Secret} = application:get_env(?APP, secret),
    hex(Secret).

%% Callbacks

%% Custom gen_server init
ranch_init({Ref, Socket, Transport, _} = Opts) ->
    case init(Opts) of
        {ok, State} ->
            ok = ranch:accept_ack(Ref),
            ok = Transport:setopts(Socket,
                                   [{active, once},
                                    {buffer, ?MAX_SOCK_BUF_SIZE}
                                   ]),
            gen_server:enter_loop(?MODULE, [], State);
        error ->
            exit(normal)
    end.

init({_Ref, Socket, Transport, _}) ->
    case Transport:peername(Socket) of
        {ok, {Ip, Port}} ->
            lager:info("New connection ~s:~p", [inet:ntoa(Ip), Port]),
            {TimeoutKey, TimeoutDefault} = state_timeout(init),
            Timer = gen_timeout:new(
                      #{timeout => {env, ?APP, TimeoutKey, TimeoutDefault}}),
            State = #state{up_sock = Socket,
                           up_transport = Transport,
                           started = erlang:system_time(second),
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
    {stop, normal, maybe_close_out(S)};
handle_info({tcp_error, Sock, Reason}, #state{up_sock = Sock} = S) ->
    lager:info("upstream sock error: ~p", [Reason]),
    {stop, Reason, maybe_close_out(S)};

handle_info({tcp, Sock, Data}, #state{down_sock = Sock} = S) ->
    %% telegram server -> proxy
    case handle_downstream_data(Data, S) of
        {ok, S1} ->
            ok = inet:setopts(Sock, [{active, once}]),
            {noreply, bump_timer(S1)};
        {error, Reason} ->
            lager:error("Error sending tunnelled data to in socket: ~p", [Reason]),
            {stop, normal, S}
    end;
handle_info({tcp_closed, Sock}, #state{down_sock = Sock,
                                       up_sock = ISock, up_transport = ITrans} = S) ->
    lager:debug("downstream sock closed"),
    ok = ITrans:close(ISock),
    {stop, normal, S};
handle_info({tcp_error, Sock, Reason}, #state{down_sock = Sock,
                                              up_sock = ISock, up_transport = ITrans} = S) ->
    lager:info("downstream sock error: ~p", [Reason]),
    ok = ITrans:close(ISock),
    {stop, Reason, S};


handle_info(timeout, #state{timer = Timer, timer_state = TState} = S) ->
    case gen_timeout:is_expired(Timer) of
        true when TState == stop;
                  TState == init ->
            lager:info("inactive timeout in state ~p", [TState]),
            {stop, normal, S};
        true when TState == hibernate ->
            {noreply, switch_timer(S, stop), hibernate};
        false ->
            Timer1 = gen_timeout:reset(Timer),
            {noreply, S#state{timer = Timer1}}
    end;
handle_info(Other, S) ->
    lager:warning("Unexpected handle_info ~p", [Other]),
    {noreply, S}.

terminate(_Reason, #state{}) ->
    lager:debug("terminate ~p", [_Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

maybe_close_out(#state{down_sock = undefined} = S) -> S;
maybe_close_out(#state{down_sock = Out} = S) ->
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
switch_timer(#state{timer_state = _FromState, timer = Timer} = S, ToState) ->
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
handle_upstream_data(<<Header:64/binary, Rest/binary>>, #state{stage = init, init_buf = <<>>} = S) ->
    {ok, Secret} = application:get_env(?APP, secret),
    case mtp_obfuscated:from_header(Header, Secret) of
        {ok, Endpoint, Codec} ->
            case handle_upstream_header(Endpoint, Codec, S) of
                {ok, S1} ->
                    handle_upstream_data(Rest, S1);
                Err ->
                    Err
            end;
        Err ->
            Err
    end;
handle_upstream_data(Bin, #state{stage = init, init_buf = <<>>} = S) ->
    {ok, S#state{init_buf = Bin}};
handle_upstream_data(Bin, #state{stage = init, init_buf = Buf} = S) ->
    handle_upstream_data(<<Buf/binary, Bin/binary>> , S#state{init_buf = <<>>});
handle_upstream_data(Bin, #state{stage = tunnel,
                                 up_codec = UpCodec,
                                 down_sock = Sock} = S) ->
    {Decoded, UpCodec1} = mtp_obfuscated:decrypt(Bin, UpCodec),
    ok = gen_tcp:send(Sock, Decoded),
    {ok, S#state{up_codec = UpCodec1}}.


%% Handle telegram server -> proxy stream
handle_downstream_data(Bin, #state{stage = tunnel,
                                   up_codec = UpCodec,
                                   up_sock = Sock,
                                   up_transport = Transport} = S) ->
    {Encoded, UpCodec1} = mtp_obfuscated:encrypt(Bin, UpCodec),
    ok = Transport:send(Sock, Encoded),
    {ok, S#state{up_codec = UpCodec1}}.


%% Packet handlers


%% Internal


handle_upstream_header(Endpoint, UpCodec, S) ->
    case connect(Endpoint, 443) of
        {ok, Sock} ->
            EndpointStr = inet:ntoa(Endpoint),
            lager:info("Connected to ~s:~p", [EndpointStr, 443]),
            ok = gen_tcp:send(Sock, <<239>>),
            {ok, S#state{stage = tunnel,
                         down_sock = Sock,
                         up_codec = UpCodec}};
        {error, _Reason} = Err ->
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
    case gen_tcp:connect(Host, Port, SockOpts, ?CONN_TIMEOUT) of
        {ok, Sock} ->
            ok = inet:setopts(Sock, [{buffer, ?MAX_SOCK_BUF_SIZE}]),
            {ok, Sock};
        {error, _} = Err ->
            Err
    end.


%% Internal

hex(Bin) ->
    [begin
         if N < 10 ->
                 48 + N;
            true ->
                 87 + N
         end
     end || <<N:4>> <= Bin].
