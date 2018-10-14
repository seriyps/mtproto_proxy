%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Process that manages pool of connections to telegram datacenter
%%% and is responsible for load-balancing between them
%%% @end
%%% TODO: monitoring of DC connections! Make 100% sure they are killed when pool
%%% is killed. Maybe link?
%%% Created : 14 Oct 2018 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_dc_pool).

-behaviour(gen_server).

%% API
-export([start_link/1,
         get/3,
         return/2,
         add_connection/1,
         ack_connected/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(APP, mtproto_proxy).

-type upstream() :: mtp_handler:handle().
-type downstream() :: mtp_down_conn:handle().
-type ds_store() :: psq:psq().

-record(state,
        {dc_id :: mtp_config:dc_id(),
         upstreams = #{} :: #{upstream() => downstream()},
         pending_downstreams = [] :: [pid()],
         downstreams :: ds_store()
        }).

%%%===================================================================
%%% API
%%%===================================================================
start_link(DcId) ->
    gen_server:start_link({via, mtp_config, DcId}, ?MODULE, DcId, []).

get(Pool, Upstream, #{addr := _} = Opts) ->
    gen_server:call(Pool, {get, Upstream, Opts}).

return(Pool, Upstream) ->
    gen_server:cast(Pool, {return, Upstream}).

add_connection(Pool) ->
    gen_server:call(Pool, add_connection, 10000).

ack_connected(Pool, Downstream) ->
    gen_server:cast(Pool, {connected, Downstream}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init(DcId) ->
    InitConnections = application:get_env(mtproto_proxy, init_dc_connections, 4),
    PendingConnections = [do_connect(DcId) || _ <- lists:seq(1, InitConnections)],
    Connections = recv_pending(PendingConnections),
    Downstreams = ds_new(Connections),
    {ok, #state{dc_id = DcId, downstreams = Downstreams}}.

handle_call({get, Upstream, Opts}, _From, State) ->
    {Downstream, State1} = handle_get(Upstream, Opts, State),
    {reply, Downstream, State1};
handle_call(add_connection, _From, State) ->
    State1 = connect(State),
    {reply, ok, State1}.

handle_cast({return, Upstream}, State) ->
    {noreply, handle_return(Upstream, State)};
handle_cast({connected, Pid}, State) ->
    {noreply, handle_connected(Pid, State)}.

handle_info({'DOWN', MonitorRef, process, Pid, _Reason}, State) ->
    %% TODO: monitor downstream connections as well
    {noreply, handle_down(MonitorRef, Pid, State)}.
terminate(_Reason, #state{downstreams = Ds}) ->
    ds_foreach(
      fun(Pid) ->
              mtp_down_conn:shutdown(Pid)
      end, Ds),
    %% upstreams will be killed by connection itself
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Handle async connection ack
handle_connected(Pid, #state{pending_downstreams = Pending,
                             downstreams = Ds} = St) ->
    Pending1 = lists:delete(Pid, Pending),
    Downstreams1 = ds_add_downstream(Pid, Ds),
    St#state{pending_downstreams = Pending1,
             downstreams = Downstreams1}.

handle_get(Upstream, Opts, #state{downstreams = Ds,
                                  upstreams = Us} = St) ->
    {Downstream, N, Ds1} = ds_get(Ds),
    MonRef = erlang:monitor(process, Upstream),
    %% if N > X and len(pending) < Y -> connect()
    Us1 = Us#{Upstream => {Downstream, MonRef}},
    ok = mtp_down_conn:upstream_new(Downstream, Upstream, Opts),
    {Downstream, maybe_spawn_connection(
                   N,
                   St#state{downstreams = Ds1,
                            upstreams = Us1})}.

handle_return(Upstream, #state{downstreams = Ds,
                               upstreams = Us} = St) ->
    {{Downstream, MonRef}, Us1} = maps:take(Upstream, Us),
    ok = mtp_down_conn:upstream_closed(Downstream, Upstream),
    erlang:demonitor(MonRef, [flush]),
    Ds1 = ds_return(Downstream, Ds),
    St#state{downstreams = Ds1,
             upstreams = Us1}.

handle_down(MonRef, MaybeUpstream, #state{downstreams = Ds,
                                          upstreams = Us} = St) ->
    case maps:take(MaybeUpstream, Us) of
        {{Downstream, MonRef}, Us1} ->
            ok = mtp_down_conn:upstream_closed(Downstream, MaybeUpstream),
            Ds1 = ds_return(Downstream, Ds),
            St#state{downstreams = Ds1,
                     upstreams = Us1};
        error ->
            lager:warning("Unexpected DOWN. ref=~p, pid=~p", [MonRef, MaybeUpstream]),
            St
    end.

maybe_spawn_connection(CurrentMin, #state{pending_downstreams = Pending} = St) ->
    %% TODO: shrinking (by timer)
    case application:get_env(?APP, clients_per_dc_connection) of
        {ok, N} when CurrentMin > N,
                     Pending == [] ->
            ToSpawn = 2,
            lists:foldl(
              fun(_, S) ->
                      connect(S)
              end, St, lists:seq(1, ToSpawn));
        _ ->
            St
    end.

%% Initiate new async connection
connect(#state{pending_downstreams = Pending,
               dc_id = DcId} = St) ->
    %% Should monitor connection PIDs as well!
    Pid = do_connect(DcId),
    St#state{pending_downstreams = [Pid | Pending]}.

%% Asynchronous connect
do_connect(DcId) ->
    {ok, Pid} = mtp_down_conn_sup:start_conn(self(), DcId),
    Pid.

%% Block until all async connections are acked
recv_pending(Pids) ->
    [receive
         {'$gen_cast', {connected, Pid}} -> Pid
     after 10000 ->
             exit({timeout, receive Smth -> Smth after 0 -> none end})
     end || Pid <- Pids].

%% New downstream connection storage
-spec ds_new([downstream()]) -> ds_store().
ds_new(Connections) ->
    Psq = pid_psq:new(),
    %% TODO: add `from_list` function
    lists:foldl(
      fun(Conn, Psq1) ->
              pid_psq:add(Conn, Psq1)
      end, Psq, Connections).

-spec ds_foreach(fun( (downstream()) -> any() ), ds_store()) -> ok.
ds_foreach(Fun, St) ->
    psq:fold(
      fun(_, _N, Pid, _) ->
              Fun(Pid)
      end, ok, St).

%% Add new downstream to storage
-spec ds_add_downstream(downstream(), ds_store()) -> ds_store().
ds_add_downstream(Conn, St) ->
    pid_psq:add(Conn, St).

%% Get least loaded downstream connection
-spec ds_get(ds_store()) -> {downstream(), pos_integer(), ds_store()}.
ds_get(St) ->
    %% TODO: should return real number of connections
    {ok, {{Conn, N}, St1}} = pid_psq:get_min_priority(St),
    {Conn, N, St1}.

%% Return connection back to storage
-spec ds_return(downstream(), ds_store()) -> ds_store().
ds_return(Pid, St) ->
    {ok, St1} = pid_psq:dec_priority(Pid, St),
    St1.
