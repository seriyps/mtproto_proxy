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
         rt/2, rt/3]).

-export([passive_metrics/0,
         active_metrics/0]).

-define(APP, mtproto_proxy).
-define(PD_KEY, {?MODULE, context_labels}).

-type metric_type() :: gauge | count | histogram.
-type metric_name() :: [atom()].
-type metric_doc() :: string().

count_inc(Name, Value, Extra) ->
    notify(count, Name, Value, Extra).

gauge_set(Name, Value, Extra) ->
    notify(gauge, Name, Value, Extra).

histogram_observe(Name, Value, Extra) ->
    notify(histogram, Name, Value, Extra).

rt(Name, Fun) ->
    rt(Name, Fun, #{}).

rt(Name, Fun, Extra) ->
    Start = erlang:monotonic_time(),
    try
        Fun()
    after
        notify(histogram, Name, erlang:monotonic_time() - Start, Extra)
    end.


notify(Type, Name, Value, Extra) ->
    case get_backend() of
        undefined ->
            false;
        Mod ->
            Mod:notify(Type, Name, Value, Extra)
    end.

get_backend() ->
    %% Cache resutl of application:get_env in process dict because it's on the hot path
    case erlang:get(metric_backend) of
        undefined ->
            case application:get_env(?APP, metric_backend) of
                {ok, Mod} when Mod =/= false;
                               Mod =/= undefined ->
                    erlang:put(metric_backend, Mod),
                    Mod;
                _ ->
                    erlang:put(metric_backend, false),
                    undefined
            end;
        false ->
            undefined;
        Mod ->
            Mod
    end.

-spec passive_metrics() -> [{metric_type(), metric_name(), metric_doc(),
                             [{Labels, Value}]}]
                               when
      Labels :: #{atom() => binary() | atom()},
      Value :: integer() | float().
passive_metrics() ->
    DownStatus = mtp_config:status(),
    [{gauge, [?APP, dc_num_downstreams],
      "Count of connections to downstream",
      [{#{dc => DcId}, NDowns}
       || #{n_downstreams := NDowns, dc_id := DcId} <- DownStatus]},
     {gauge, [?APP, dc_num_upstreams],
      "Count of upstreams connected to DC",
      [{#{dc => DcId}, NUps}
       || #{n_upstreams := NUps, dc_id := DcId} <- DownStatus]},
     {gauge, [?APP, dc_upstreams_per_downstream],
      "Count of upstreams connected to DC",
      lists:flatmap(
        fun(#{min := Min,
              max := Max,
              dc_id := DcId}) ->
                [{#{dc => DcId, meter => min}, Min},
                 {#{dc => DcId, meter => max}, Max}]
        end,  DownStatus)}
    |
    [{gauge, [?APP, connections, count],
      "Count of ranch connections",
      [{#{listener => H}, proplists:get_value(all_connections, P)}
       || {H, P} <- mtproto_proxy_app:mtp_listeners()]}] ].

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
     {count, [?APP, healthcheck, total],
      "Upstream self-healthcheck triggered some action",
      #{labels => [action]}},

     {count, [?APP, received, downstream, bytes],
      "Bytes transmitted from downstream socket",
      #{labels => [dc_id]}},
     {count, [?APP, received, upstream, bytes],
      "Bytes transmitted from upstream socket",
      #{labels => [listener]}},
     {count, [?APP, sent, downstream, bytes],
      "Bytes sent to downstream socket",
      #{labels => [dc_id]}},
     {count, [?APP, sent, upstream, bytes],
      "Bytes sent to upstream socket",
      #{labels => [listener]}},

     {histogram, [?APP, tracker_packet_size, bytes],
      "Received packet size",
      #{labels => [direction],
        buckets => {exponential, 8, 4, 8}}},

     {histogram, [?APP, tg_packet_size, bytes],
      "Proxied telegram protocol packet size",
      #{labels => [direction],
        buckets => {exponential, 8, 4, 8}}},

     {count, [?APP, protocol_error, total],
      "Proxy protocol errors",
      #{labels => [listener, reason]}},
     {count, [?APP, protocol_ok, total],
      "Proxy upstream protocol type",
      #{labels => [listener, protocol]}},

     {count, [?APP, out_connect_ok, total],
      "Proxy out connections",
      #{labels => [dc_id]}},
     {count, [?APP, out_connect_error, total],
      "Proxy out connect errors",
      #{labels => [dc_id, reason]}},


     {count, [?APP, down_backpressure, total],
      "Times downstream backpressure state was changed",
      #{labels => [dc_id, state]}},
     {histogram, [?APP, upstream_send_duration, seconds],
      "Duration of tcp send calls to upstream",
      #{duration_unit => seconds,
        %% buckets => ?MS_BUCKETS
        labels => [listener]
       }},
     {histogram, [?APP, downstream_send_duration, seconds],
      "Duration of tcp send calls to downstream",
      #{duration_unit => seconds,
        %% buckets => ?MS_BUCKETS
        labels => [dc]
       }},
     {count, [?APP, upstream_send_error, total],
      "Count of tcp send errors to upstream",
      #{labels => [listener, reason]}}
    ].
