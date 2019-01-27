%%% @author Sergey Prokhorov <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey Prokhorov
%%% @doc
%%%
%%% @end
%%% Created :  9 Apr 2018 by Sergey Prokhorov <me@seriyps.ru>

-module(gen_timeout).

-export([new/1,
         set_timeout/2,
         bump/1,
         reset/1,
         is_expired/1,
         time_to_message/1,
         time_left/1]).
-export([upgrade/1]).
-export_type([tout/0, opts/0]).

-record(timeout,
        {ref :: reference() | undefined,
         last_bump :: integer(),
         message :: any(),
         unit = second :: erlang:time_unit(),
         timeout :: timeout_type()}).

-type timeout_type() ::
        non_neg_integer()
      | {env, App :: atom(), Name :: atom(), Default :: non_neg_integer()}.

-type opts() :: #{message => any(),
                  unit => erlang:time_unit(),
                  timeout := timeout_type()}.

-opaque tout() :: #timeout{}.

-define(MS_PER_SEC, 1000).

-spec new(opts()) -> tout().
new(Opts) ->
    Default = #{message => timeout,
                unit => second},
    #{message := Message,
      timeout := Timeout,
      unit := Unit} = maps:merge(Default, Opts),
    %% TODO: get rid of 2 system_time/1 calls in `new + reset`
    reset(#timeout{message = Message,
                   unit = Unit,
                   last_bump = erlang:system_time(Unit),
                   timeout = Timeout}).

-spec set_timeout(timeout_type(), tout()) -> tout().
set_timeout(Timeout, S) ->
    reset(S#timeout{timeout = Timeout}).

-spec bump(tout()) -> tout().
bump(#timeout{unit = Unit} = S) ->
    S#timeout{last_bump = erlang:system_time(Unit)}.

-spec reset(tout()) -> tout().
reset(#timeout{ref = Ref, message = Message, unit = Unit} = S) ->
    (is_reference(Ref))
        andalso erlang:cancel_timer(Ref),
    SendAfter = max(time_left(S), 0),
    After = erlang:convert_time_unit(SendAfter, Unit, millisecond),
    Ref1 = erlang:send_after(After, self(), Message),
    S#timeout{ref = Ref1}.

-spec is_expired(tout()) -> boolean().
is_expired(S) ->
    time_left(S) =< 0.

-spec time_to_message(tout()) -> non_neg_integer() | false.
time_to_message(#timeout{ref = Ref}) ->
    erlang:read_timer(Ref).

-spec time_left(tout()) -> integer().
time_left(#timeout{last_bump = LastBump, unit = Unit} = S) ->
    Timeout = get_timeout(S),
    Now = erlang:system_time(Unit),
    ExpiresAt = LastBump + Timeout,
    ExpiresAt - Now.

upgrade({timeout, Ref, LastBump, Message, Timeout}) ->
    Timeout1 = case Timeout of
                   {sec, Val} -> Val;
                   _ -> Timeout
               end,
    #timeout{ref = Ref,
             last_bump = LastBump,
             message = Message,
             timeout = Timeout1,
             unit = second}.

%% Internal

get_timeout(#timeout{timeout = {env, App, Name, Default}}) ->
    application:get_env(App, Name, Default);
get_timeout(#timeout{timeout = Sec}) ->
    Sec.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

new_expire_test() ->
    T = new(#{timeout => 100,
              unit => millisecond,
              message => ?FUNCTION_NAME}),
    ?assertNot(is_expired(T)),
    ?assert(time_left(T) > 0),
    ?assert(time_to_message(T) > 0),
    ok= recv(?FUNCTION_NAME),
    ?assert(time_left(T) =< 0),
    ?assert(is_expired(T)).

reset_test() ->
    T = new(#{timeout => 100,
              unit => millisecond,
              message => ?FUNCTION_NAME}),
    ?assertNot(is_expired(T)),
    T1 = reset(T),
    ?assertNot(is_expired(T1)),
    ok = recv(?FUNCTION_NAME),
    ?assert(is_expired(T1)).

bump_test() ->
    T = new(#{timeout => 1000,
              unit => millisecond,
              message => ?FUNCTION_NAME}),
    ?assertNot(is_expired(T)),
    TimeToMessage0 = time_to_message(T),
    timer:sleep(600),
    T1 = bump(T),
    ?assert((TimeToMessage0 - 600) >= time_to_message(T1),
            "Bump doesn't affect timer message"),
    timer:sleep(500),
    %% Got message, but not yet expired
    ?assertEqual(false, time_to_message(T1)),
    ?assertNot(is_expired(T1)),
    ok = recv(?FUNCTION_NAME),
    ?assertNot(is_expired(T1)),
    T2 = reset(T1),
    ok = recv(?FUNCTION_NAME),
    ?assert(is_expired(T2)).

recv(What) ->
    receive What -> ok
    after 5000 ->
            error({timeout, What})
    end.

-endif.
