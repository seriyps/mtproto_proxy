%% @doc simple metric backend to be used in tests.
%% XXX: DON'T USE IN PRODUCTION! It can become bottleneck!
-module(mtp_test_metric).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([notify/4]).
-export([get/2,
         get/3,
         get_tags/3,
         wait_for_value/5,
         wait_for/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {count = #{},
                gauge = #{},
                histogram = #{}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

notify(Type, Name, Value, Extra) ->
    try gen_server:call(?MODULE, {notify, Type, Name, Value, Extra})
    catch _:Reason ->
            {error, Reason}
    end.

get(Type, Name) ->
    get(Type, Name, #{}).

get(Type, Name, Extra) ->
    gen_server:call(?MODULE, {get, Type, Name, Extra}).

get_tags(Type, Name, Tags) ->
    get(Type, Name, #{labels => Tags}).

wait_for_value(Type, Name, Tags, Value, Timeout) ->
    Now = erlang:monotonic_time(millisecond),
    Test = fun(Current) -> Current == Value end,
    wait_for_till(Type, Name, #{labels => Tags}, Test, Now + Timeout).

wait_for(Type, Name, Tags, Test, Timeout) ->
    Now = erlang:monotonic_time(millisecond),
    wait_for_till(Type, Name, #{labels => Tags}, Test, Now + Timeout).

wait_for_till(Type, Name, Extra, Test, Deadline) ->
    case Test(get(Type, Name, Extra)) of
        true -> ok;
        false ->
            Now = erlang:monotonic_time(millisecond),
            case Now >= Deadline of
                true ->
                    timeout;
                false ->
                    timer:sleep(10),
                    wait_for_till(Type, Name, Extra, Test, Deadline)
            end
    end.


init([]) ->
    {ok, #state{}}.

handle_call({notify, count, Name, Value, Extra}, _From, #state{count = C} = State) ->
    K = {Name, Extra},
    V1 =
        case maps:find(K, C) of
            {ok, V0} ->
                V0 + Value;
            error ->
                Value
        end,
    {reply, ok, State#state{count = C#{K => V1}}};
handle_call({notify, gauge, Name, Value, Extra}, _From, #state{gauge = G} = State) ->
    K = {Name, Extra},
    {reply, ok, State#state{gauge = G#{K => Value}}};
handle_call({notify, histogram, Name, Value, Extra}, _From, #state{histogram = H} = State) ->
    K = {Name, Extra},
    V1 =
        case maps:find(K, H) of
            {ok, {Count, Total, Min, Max}} ->
                {Count + 1,
                 Total + Value,
                 erlang:min(Min, Value),
                 erlang:max(Max, Value)};
            error ->
                {1,
                 Value,
                 Value,
                 Value}
        end,
    {reply, ok, State#state{histogram = H#{K => V1}}};
handle_call({get, Type, Name, Extra}, _From, State) ->
    K = {Name, Extra},
    Tab = case Type of
              count -> State#state.count;
              gauge -> State#state.gauge;
              histogram -> State#state.histogram
          end,
    {reply, maps:get(K, Tab, not_found), State}.

handle_cast(_Msg, State) ->
    {noreply, State}.
handle_info(_Info, State) ->
    {noreply, State}.
terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
