%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2018, sergey
%%% @doc
%%% Backend-agnostic interface for logging metrics.
%%% Made with prometheus.erl in mind, but might be used with smth else
%%% @end
%%% Created : 15 May 2018 by sergey <me@seriyps.ru>

-module(mtp_metric).

-export([count_inc/3,
         gauge_set/3,
         histogram_observe/3,
         rt/2,
         set_context_labels/1]).

-export([passive_metrics/0,
         active_metrics/0]).

-define(APP, mtproto_proxy).
-define(PD_KEY, {?MODULE, context_labels}).

-type metric_type() :: gauge | count | histogram.
-type metric_name() :: [atom()].
-type metric_doc() :: string().


set_context_labels(Tags) when is_list(Tags) ->
    erlang:put(?PD_KEY, Tags).

count_inc(Name, Value, Extra) ->
    notify(count, Name, Value, Extra).

gauge_set(Name, Value, Extra) ->
    notify(gauge, Name, Value, Extra).

histogram_observe(Name, Value, Extra) ->
    notify(histogram, Name, Value, Extra).

rt(Name, Fun) ->
    Start = erlang:monotonic_time(),
    try
        Fun()
    after
        notify(histogram, Name, erlang:monotonic_time() - Start, #{})
    end.


notify(Type, Name, Value, Extra) ->
    case application:get_env(?APP, metric_backend) of
        {ok, Mod} ->
            Extra1 = case erlang:get(?PD_KEY) of
                         undefined -> Extra;
                         ContextLabels ->
                             MsgLabels = maps:get(labels, Extra, []),
                             Extra#{labels => ContextLabels ++ MsgLabels}
                     end,
            Mod:notify(Type, Name, Value, Extra1);
        _ ->
            false
    end.

-spec passive_metrics() -> [{metric_type(), metric_name(), metric_doc(),
                             [{Labels, Value}]}]
                               when
      Labels :: #{atom() => binary() | atom()},
      Value :: integer() | float().
passive_metrics() ->
    [{gauge, [?APP, connections, count],
      "Count of ranch connections",
      [{#{listener => H}, proplists:get_value(all_connections, P)}
       || {H, P} <- ranch:info(),
          proplists:get_value(protocol, P) == mtp_handler]}].

-spec active_metrics() -> [{metric_type(), metric_name(), metric_doc(), Opts}]
                              when
      Opts :: #{duration_units => atom(),
                buckets => [number()],
                labels => [atom()]}.
active_metrics() ->
    [{count, [?APP, in_connection, total],
      "MTP incoming connection",
      #{labels => [listener]}},
     {count, [?APP, in_connection_closed, total],
      "MTP incoming connection closed",
      #{labels => [listener]}},
     {histogram, [?APP, session_lifetime, seconds],
      "Time from in connection open to session process termination",
      #{duration_unit => seconds,
        buckets => [0.2, 0.5, 1, 5, 10, 30, 60, 150, 300, 600, 1200],
        labels => [listener]
       }},

     {count, [?APP, inactive_timeout, total],
      "Connection closed by timeout because of no activity",
      #{labels => [listener]}},
     {count, [?APP, inactive_hibernate, total],
      "Connection goes to hibernate by timeout because of no activity",
      #{labels => [listener]}},
     {count, [?APP, timer_switch, total],
      "Connection timeout mode switches",
      #{labels => [listener, from, to]}},

     {count, [?APP, tracker, bytes],
      "Bytes transmitted according to tracker",
      #{labels => [listener, direction]}},
     {histogram, [?APP, tracker_packet_size, bytes],
      "Proxied packet size",
      #{labels => [listener, direction],
        buckets => {exponential, 8, 4, 8}}},

     {histogram, [?APP, tg_packet_size, bytes],
      "Proxied telegram protocol packet size",
      #{labels => [listener, direction],
        buckets => {exponential, 8, 4, 8}}},

     {count, [?APP, protocol_error, total],
      "Proxy protocol errors",
      #{labels => [listener, reason]}},
     {count, [?APP, protocol_ok, total],
      "Proxy upstream protocol type",
      #{labels => [listener, protocol]}},

     {count, [?APP, out_connect_ok, total],
      "Proxy out connections",
      #{labels => [listener, dc_id]}},
     {count, [?APP, out_connect_error, total],
      "Proxy out connect errors",
      #{labels => [listener, reason]}},


     {histogram, [?APP, upstream_send_duration, seconds],
      "Duration of tcp send calls to upstream",
      #{duration_unit => seconds,
        %% buckets => ?MS_BUCKETS
        labels => [listener]
       }},
     {histogram, [?APP, downstream_connect_duration, seconds],
      "Duration of tcp connect to downstream",
      #{duration_unit => seconds,
        %% buckets => ?MS_BUCKETS
        labels => [listener]
       }},
     {histogram, [?APP, downstream_send_duration, seconds],
      "Duration of tcp send calls to downstream",
      #{duration_unit => seconds,
        %% buckets => ?MS_BUCKETS
        labels => [listener]
       }},
     {count, [?APP, upstream_send_error, total],
      "Count of tcp send errors to upstream",
      #{labels => [listener, reason]}},
     {count, [?APP, downstream_send_error, total],
      "Count of tcp send errors to downstream",
      #{labels => [listener, reason]}}
    ].
