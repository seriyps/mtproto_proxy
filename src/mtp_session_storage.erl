%%%-------------------------------------------------------------------
%%% @doc
%%% Storage to store last used sessions to protect from replay-attacks
%%% used in some countries to detect mtproto proxy.
%%%
%%% Data is stored in ?DATA_TAB and there is additional index table ?HISTOGRAM_TAB, where
%%% we store "secondary index" histogram: how many sessions have been added in each 5 minute
%%% interval. It is used to make periodic cleanup procedure more efficient.
%%% @end
%%% Created : 19 May 2019 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_session_storage).

-behaviour(gen_server).

%% API
-export([start_link/0,
         check_add/1,
         status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("hut/include/hut.hrl").

-define(DATA_TAB, ?MODULE).
-define(HISTOGRAM_TAB, mtp_session_storage_histogram).

%% 5-minute buckets
-define(HISTOGRAM_BUCKET_SIZE, 300).
-define(CHECK_INTERVAL, 60).

-record(state, {data_tab = ets:tid(),
                histogram_tab = ets:tid(),
                clean_timer = gen_timeout:tout()}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Add secret to the storage. Returns `new' if it was never used and `used' if it was
%% already used before.
-spec check_add(binary()) -> new | used.
check_add(Packet) when byte_size(Packet) == 64 ->
    Now = erlang:system_time(second),
    check_add_at(Packet, Now).

check_add_at(Packet, Now) ->
    Record = {fingerprint(Packet), Now},
    HistogramBucket = bucket(Now),
    ets:update_counter(?HISTOGRAM_TAB, HistogramBucket, 1, {HistogramBucket, 0}),
    case ets:insert_new(?DATA_TAB, Record) of
        true ->
            new;
        false ->
            %% TODO: should decrement old record's histogram counter, but skip this for simplicity
            ets:insert(?DATA_TAB, Record),
            used
    end.

-spec status() -> #{tab_size := non_neg_integer(),
                    tab_memory_kb := non_neg_integer(),
                    histogram_buckets := non_neg_integer(),
                    histogram_size := non_neg_integer(),
                    histogram_oldest := non_neg_integer()}.
status() ->
    gen_server:call(?MODULE, status).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    {DataTab, HistTab} = new_storage(),
    Timer = gen_timeout:new(#{timeout => ?CHECK_INTERVAL}),
    {ok, #state{data_tab = DataTab,
                histogram_tab = HistTab,
                clean_timer = Timer}}.

handle_call(status, _From, #state{data_tab = DataTid, histogram_tab = HistTid} = State) ->
    Now = erlang:system_time(second),
    Size = ets:info(DataTid, size),
    Memory = tab_memory(DataTid),
    MemoryKb = round(Memory / 1024),
    HistSize = ets:info(HistTid, size),
    {HistOldest, HistTotal} =
        ets:foldl(fun({Bucket, Count}, {Oldest, Total}) ->
                          {erlang:min(Oldest, bucket_to_ts(Bucket)), Total + Count}
                  end, {Now, 0}, HistTid),
    Status = #{tab_size => Size,
               tab_memory_kb => MemoryKb,
               histogram_buckets => HistSize,
               histogram_size => HistTotal,
               histogram_oldest_ts => HistOldest,
               histogram_oldest_age => Now - HistOldest},
    {reply, Status, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(timeout, #state{data_tab = DataTab, histogram_tab = HistTab, clean_timer = Timer0} = State) ->
    Timer =
        case gen_timeout:is_expired(Timer0) of
            true ->
                Opts = application:get_env(mtproto_proxy, replay_check_session_storage_opts,
                                           #{max_age_minutes => 360}),
                Cleans = clean_storage(DataTab, HistTab, Opts),
                Remaining = ets:info(DataTab, size),
                ?log(info, "storage cleaned: ~p; remaining: ~p", [Cleans, Remaining]),
                gen_timeout:bump(gen_timeout:reset(Timer0));
            false ->
                gen_timeout:reset(Timer0)
        end,
    {noreply, State#state{clean_timer = Timer}}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

fingerprint(<<_:8/binary, KeyIV:(32 + 16)/binary, _:8/binary>>) ->
    %% It would be better to use whole 64b packet as fingerprint, but will use only
    %% 48b Key + IV part to save some space.
    binary:copy(KeyIV).

bucket(Timestamp) ->
    Timestamp div ?HISTOGRAM_BUCKET_SIZE.

bucket_to_ts(BucketTime) ->
    BucketTime * ?HISTOGRAM_BUCKET_SIZE.

bucket_next(BucketTime) ->
    BucketTime + 1.


new_storage() ->
    DataTab = ets:new(?DATA_TAB, [set, public, named_table, {write_concurrency, true}]),
    HistTab = ets:new(?HISTOGRAM_TAB, [set, public, named_table, {write_concurrency, true}]),
    {DataTab, HistTab}.


clean_storage(DataTid, HistogramTid, CleanOpts) ->
    lists:filtermap(fun(Check) -> do_clean(DataTid, HistogramTid, CleanOpts, Check) end,
                    [space, count, max_age]).

do_clean(DataTid, HistTid, #{max_memory_mb := MaxMem}, space) ->
    TabMemBytes = tab_memory(DataTid),
    MaxMemBytes = MaxMem * 1024 * 1024,
    case TabMemBytes > MaxMemBytes of
        true ->
            PercentToShrink = (TabMemBytes - MaxMemBytes) / TabMemBytes,
            Removed = shrink_percent(DataTid, HistTid, PercentToShrink),
            {true, {space, Removed}};
        false ->
            false
    end;
do_clean(DataTid, HistTid, #{max_items := MaxItems}, count) ->
    Count = ets:info(DataTid, size),
    case Count > MaxItems of
        true ->
            PercentToShrink = (Count - MaxItems) / Count,
            Removed = shrink_percent(DataTid, HistTid, PercentToShrink),
            {true, {count, Removed}};
        false ->
            false
    end;
do_clean(DataTid, HistTid, #{max_age_minutes := MaxAge}, max_age) ->
    %% First scan histogram table, because it's cheaper
    CutBucket = bucket(erlang:system_time(second) - (MaxAge * 60)),
    HistMs = ets:fun2ms(fun({BucketTs, _}) when BucketTs =< CutBucket -> true end),
    case ets:select_count(HistTid, HistMs) of
        0 ->
            false;
        _ ->
            Removed = remove_older(CutBucket, DataTid, HistTid),
            {true, {max_age, Removed}}
    end.


tab_memory(Tid) ->
    WordSize = erlang:system_info(wordsize),
    Words = ets:info(Tid, memory),
    Words * WordSize.

shrink_percent(DataTid, HistTid, Percent) when Percent < 1,
                                               Percent >= 0 ->
    Count = ets:info(DataTid, size),
    ToRemove = trunc(Count * Percent),
    HistByTime = lists:sort(ets:tab2list(HistTid)), % oldest first
    CutBucketTime = find_cut_bucket(HistByTime, ToRemove, 0),
    remove_older(CutBucketTime, DataTid, HistTid).

%% Find the timestamp such that if we remove buckets that are older than this timestamp then we
%% will remove at least `ToRemove' items.
find_cut_bucket([{BucketTime, _}], _, _) ->
    BucketTime;
find_cut_bucket([{BucketTime, Count} | Tail], ToRemove, Total) ->
    NewTotal = Total + Count,
    case NewTotal >= ToRemove of
        true ->
            BucketTime;
        false ->
            find_cut_bucket(Tail, ToRemove, NewTotal)
    end.

%% @doc remove records that are in CutBucketTime bucket or older.
%% Returns number of removed data records.
-spec remove_older(integer(), ets:tid(), ets:tid()) -> non_neg_integer().
remove_older(CutBucketTime, DataTid, HistTid) ->
    %%  | --- | --- | --- | --
    %%  ^ oldest bucket
    %%        ^ 2nd bucket
    %%              ^ 3rd bucket
    %%                    ^ current bucket
    %%  If CutBucketTime is 2nd bucket, following will be removed:
    %%  | --- | ---
    EdgeBucketTime = bucket_next(CutBucketTime),
    HistMs = ets:fun2ms(fun({BucketTs, _}) when BucketTs < EdgeBucketTime -> true end),
    DataCutTime = bucket_to_ts(EdgeBucketTime),
    DataMs = ets:fun2ms(fun({_, Time}) when Time =< DataCutTime -> true end),
    ets:select_delete(HistTid, HistMs),
    ets:select_delete(DataTid, DataMs).
