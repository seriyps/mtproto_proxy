%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2018, sergey
%%% @doc
%%% Interface for logging metrics (CODE WIPED)
%%% @end
%%% Created : 15 May 2018 by sergey <me@seriyps.ru>

-module(metric).

-export([count_inc/3,
         gauge_set/3,
         rt/2,
         histogram_observe/3]).

count_inc(_Name, _Value, _Extra) ->
    noop.

gauge_set(_Name, _Value, _Extra) ->
    noop.

histogram_observe(_Name, _Value, _Extra) ->
    noop.

rt(_Name, Fun) ->
    Fun().
