%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2019, Sergey
%%% @doc
%%% Storage for `max_connections` policy.
%%% It's quite simple wrapper for public ETS counter.
%%% @end
%%% Created : 20 Aug 2019 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_policy_counter).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([increment/1,
         decrement/1,
         get/1,
         flush/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-type key() :: [mtp_policy:db_val()].

-define(TAB, ?MODULE).

-record(state, {tab :: ets:tid()}).

%%%===================================================================
%%% API
%%%===================================================================
-spec increment(key()) -> integer().
increment(Key) ->
    ets:update_counter(?TAB, Key, 1, {Key, 0}).

-spec decrement(key()) -> integer().
decrement(Key) ->
    try ets:update_counter(?TAB, Key, -1) of
        New when New =< 0 ->
            ets:delete(?TAB, Key),
            0;
        New -> New
    catch error:badarg ->
            %% already removed
            0
    end.

-spec get(key()) -> non_neg_integer().
get(Key) ->
    case ets:lookup(?TAB, Key) of
        [] -> 0;
        [{_, V}] -> V
    end.

%% @doc Clean all counters
flush() ->
    gen_server:call(?MODULE, flush).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    Tab = ets:new(?TAB, [named_table, {write_concurrency, true}, public]),
    {ok, #state{tab = Tab}}.

handle_call(flush, _From, #state{tab = Tab} = State) ->
    true = ets:delete_all_objects(Tab),
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
