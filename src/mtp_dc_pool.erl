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
         ack_connected/2,
         status/1,
         valid_dc_id/1,
         dc_to_pool_name/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-export_type([status/0]).

-include_lib("hut/include/hut.hrl").

-define(SERVER, ?MODULE).
-define(APP, mtproto_proxy).
-define(BURST_MAX, 10).
-define(DEFAULT_INIT_CONNS, 2).
-define(DEFAULT_CLIENTS_PER_CONN, 300).

-type upstream() :: mtp_handler:handle().
-type downstream() :: mtp_down_conn:handle().
-type ds_store() :: psq:psq().
-type status() :: #{n_downstreams := non_neg_integer(),
                    n_upstreams := non_neg_integer(),
                    min := non_neg_integer(),
                    max := non_neg_integer(),
                    dc_id := mtp_config:dc_id()}.

-record(state,
        {dc_id :: mtp_config:dc_id(),
         %% This one might be really big:
         upstreams = #{} :: #{upstream() => {downstream(), Monitor :: reference()}},
         %% On-demand downstreams are started asynchronously;
         pending_downstreams = [] :: [pid()],
         %% Downstream storage that allows to choose the one with minimal
         %% number of connections
         %% Should be relatively small
         downstreams :: ds_store(),
         downstream_monitors = #{} :: #{reference() => downstream()}
        }).

%%%===================================================================
%%% API
%%%===================================================================
start_link(DcId) ->
    gen_server:start_link({local, dc_to_pool_name(DcId)}, ?MODULE, DcId, []).

valid_dc_id(DcId) ->
    is_integer(DcId) andalso
        -10 < DcId andalso
        10 > DcId.

dc_to_pool_name(DcId)  ->
    valid_dc_id(DcId) orelse error(invalid_dc_id, [DcId]),
    binary_to_atom(<<"mtp_dc_pool_", (integer_to_binary(DcId))/binary>>, utf8).

-spec get(pid(), upstream(), #{addr := mtp_config:netloc_v4v6(),
                               ad_tag => binary()}) -> downstream() | {error, atom()}.
get(Pool, Upstream, #{addr := _} = Opts) ->
    gen_server:call(Pool, {get, Upstream, Opts}).

return(Pool, Upstream) ->
    gen_server:cast(Pool, {return, Upstream}).

add_connection(Pool) ->
    gen_server:call(Pool, add_connection, 10000).

ack_connected(Pool, Downstream) ->
    gen_server:cast(Pool, {connected, Downstream}).

-spec status(pid()) -> status().
status(Pool) ->
    gen_server:call(Pool, status).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init(DcId) ->
    InitConnections = application:get_env(?APP, init_dc_connections, ?DEFAULT_INIT_CONNS),
    State = #state{dc_id = DcId,
                   downstreams = ds_new([])},
    State1 = connect_many(InitConnections, State),
    State2 = wait_pending(State1),
    {ok, State2}.

handle_call({get, Upstream, Opts}, _From, State) ->
    case handle_get(Upstream, Opts, State) of
        {empty, State1} ->
            {reply, {error, empty}, State1};
        {Downstream, State1} ->
            {reply, Downstream, State1}
    end;
handle_call(add_connection, _From, State) ->
    State1 = connect(State),
    {reply, ok, State1};
handle_call(status, _From, #state{downstreams = Ds,
                                  upstreams = Us,
                                  dc_id = DcId} = State) ->
    {NDowns, NUps, Min, Max} =
        ds_fold(
          fun(_Pid, N, {NDowns, NUps, Min, Max}) ->
                  {NDowns + 1, NUps + N, min(Min, N), max(Max, N)}
          end, {0, 0, map_size(Us), 0}, Ds),
    {reply, #{n_downstreams => NDowns,
              n_upstreams => NUps,
              min => Min,
              max => Max,
              dc_id => DcId}, State}.

handle_cast({return, Upstream}, State) ->
    {noreply, handle_return(Upstream, State)};
handle_cast({connected, Pid}, State) ->
    {noreply, handle_connected(Pid, State)}.

handle_info({'DOWN', MonitorRef, process, Pid, Reason}, State) ->
    {noreply, handle_down(MonitorRef, Pid, Reason, State)}.
terminate(_Reason, #state{downstreams = Ds}) ->
    ds_fold(
      fun(Pid, _, _) ->
              mtp_down_conn:shutdown(Pid)
      end, ok, Ds),
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
    case ds_get(Ds) of
        {Downstream, N, Ds1} ->
            MonRef = erlang:monitor(process, Upstream),
            Us1 = Us#{Upstream => {Downstream, MonRef}},
            ok = mtp_down_conn:upstream_new(Downstream, Upstream, Opts),
            {Downstream, maybe_spawn_connection(
                           N,
                           St#state{downstreams = Ds1,
                                    upstreams = Us1})};
        empty ->
            {empty, maybe_restart_connection(St)}
    end.

handle_return(Upstream, #state{downstreams = Ds,
                               upstreams = Us} = St) ->
    {{Downstream, MonRef}, Us1} = maps:take(Upstream, Us),
    ok = mtp_down_conn:upstream_closed(Downstream, Upstream),
    erlang:demonitor(MonRef, [flush]),
    Ds1 = ds_return(Downstream, Ds),
    St#state{downstreams = Ds1,
             upstreams = Us1}.

handle_down(MonRef, Pid, Reason, #state{downstreams = Ds,
                                        downstream_monitors = DsM,
                                        upstreams = Us,
                                        pending_downstreams = Pending} = St) ->
    case maps:take(Pid, Us) of
        {{Downstream, MonRef}, Us1} ->
            ok = mtp_down_conn:upstream_closed(Downstream, Pid),
            Ds1 = ds_return(Downstream, Ds),
            St#state{downstreams = Ds1,
                     upstreams = Us1};
        error ->
            case maps:take(MonRef, DsM) of
                {Pid, DsM1} ->
                    Pending1 = lists:delete(Pid, Pending),
                    Ds1 = ds_remove(Pid, Ds),
                    ?log(error, "Downstream=~p is down. reason=~p", [Pid, Reason]),
                    maybe_restart_connection(
                      St#state{pending_downstreams = Pending1,
                               downstreams = Ds1,
                               downstream_monitors = DsM1});
                _ ->
                    ?log(error, "Unexpected DOWN. ref=~p, pid=~p, reason=~p", [MonRef, Pid, Reason]),
                    St
            end
    end.

maybe_restart_connection(#state{pending_downstreams = Pending,
                                downstream_monitors = DsM} = St) ->
    MinConnections = application:get_env(?APP, init_dc_connections, ?DEFAULT_INIT_CONNS),
    NumOpen = map_size(DsM),
    NumPending = length(Pending),
    case (NumOpen + NumPending) < MinConnections of
        true ->
            %% We have less than minimum connections. Just spawn new one
            connect(St);
        false ->
            %% We have more than minimum connections.
            %% Don't spawn anything, because it will be done on-demand
            St
    end.


maybe_spawn_connection(CurrentMin, #state{pending_downstreams = Pending} = St) ->
    %% if N > X and len(pending) < Y -> connect()
    %% TODO: shrinking (by timer)
    ToSpawn =
        case application:get_env(?APP, clients_per_dc_connection, ?DEFAULT_CLIENTS_PER_CONN) of
            N when CurrentMin > N,
                   Pending == [] ->
                2;
            N when CurrentMin > (N * 1.5),
                   length(Pending) < ?BURST_MAX ->
                %% To survive initial bursts
                ?BURST_MAX - length(Pending);
            _ ->
                0
        end,
    connect_many(ToSpawn, St).

connect_many(ToSpawn, St) ->
    lists:foldl(
      fun(_, S) ->
              connect(S)
      end, St, lists:seq(1, ToSpawn)).

%% Initiate new async connection
connect(#state{pending_downstreams = Pending,
               downstream_monitors = DsM,
               dc_id = DcId} = St) ->
    Pid = do_connect(DcId),
    MonRef = erlang:monitor(process, Pid),
    St#state{pending_downstreams = [Pid | Pending],
             downstream_monitors = DsM#{MonRef => Pid}}.

%% Asynchronous connect
do_connect(DcId) ->
    {ok, Pid} = mtp_down_conn_sup:start_conn(self(), DcId),
    Pid.

%% Block until all async connections are acked
wait_pending(#state{pending_downstreams = Pending,
                    downstream_monitors = DsM} = St) ->
    lists:foldl(
      fun(Pid, #state{pending_downstreams = [Pid | Remaining],
                      downstreams = Ds} = St1) ->
              receive
                  {'$gen_cast', {connected, Pid}} -> Pid;
                  {'DOWN', MonitorRef, process, Pid, Reason} ->
                      %% maybe try to re-connect?
                      (maps:get(MonitorRef, DsM, undefined) == Pid)
                          orelse exit({unexpected_down,
                                       MonitorRef, Pid, Reason}),
                      exit({connection_failed, Pid, Reason})
              after 10000 ->
                      exit({timeout, receive Smth -> Smth after 0 -> none end})
              end,
              St1#state{pending_downstreams = Remaining,
                        downstreams = ds_add_downstream(Pid, Ds)}
      end, St, Pending).

%% New downstream connection storage
-spec ds_new([downstream()]) -> ds_store().
ds_new(Connections) ->
    Psq = pid_psq:new(),
    %% TODO: add `from_list` function
    lists:foldl(
      fun(Conn, Psq1) ->
              pid_psq:add(Conn, Psq1)
      end, Psq, Connections).

-spec ds_fold(fun( (downstream(), integer(), Acc) -> Acc ), Acc, ds_store()) -> Acc when
      Acc :: any().
ds_fold(Fun, Acc0, St) ->
    psq:fold(
      fun(_, N, Pid, Acc) ->
              Fun(Pid, N, Acc)
      end, Acc0, St).

%% Add new downstream to storage
-spec ds_add_downstream(downstream(), ds_store()) -> ds_store().
ds_add_downstream(Conn, St) ->
    pid_psq:add(Conn, St).

%% Get least loaded downstream connection
-spec ds_get(ds_store()) -> {downstream(), pos_integer(), ds_store()} | empty.
ds_get(St) ->
    %% TODO: should return real number of connections
    case pid_psq:get_min_priority(St) of
        {ok, {{Conn, N}, St1}} ->
            {Conn, N, St1};
        undefined ->
            empty
    end.

%% Return connection back to storage
-spec ds_return(downstream(), ds_store()) -> ds_store().
ds_return(Pid, St) ->
    %% It may return 'undefined' if down_conn crashed
    case pid_psq:dec_priority(Pid, St) of
        {ok, St1} ->
            St1;
        undefined ->
            ?log(warning, "Attempt to release unknown connection ~p", [Pid]),
            St
    end.

-spec ds_remove(downstream(), ds_store()) -> ds_store().
ds_remove(Downstream, St) ->
    pid_psq:delete(Downstream, St).
