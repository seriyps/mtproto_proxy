%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Worker that updates datacenter config and proxy secret from
%%% https://core.telegram.org/getProxySecret
%%% and
%%% https://core.telegram.org/getProxyConfig
%%% @end
%%% Created : 10 Jun 2018 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_config).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([get_downstream_safe/2,
         get_downstream_pool/1,
         get_netloc/1,
         get_netloc_safe/1,
         get_secret/0,
         status/0,
         update/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-export_type([netloc_v4v6/0]).

-type dc_id() :: integer().
-type netloc() :: {inet:ip4_address(), inet:port_number()}.
-type netloc_v4v6() :: {inet:ip_address(), inet:port_number()}.

-include_lib("hut/include/hut.hrl").

-define(TAB, ?MODULE).
-define(IPS_KEY(DcId), {id, DcId}).
-define(IDS_KEY, dc_ids).
-define(SECRET_URL, "https://core.telegram.org/getProxySecret").
-define(CONFIG_URL, "https://core.telegram.org/getProxyConfig").

-define(APP, mtproto_proxy).

-record(state, {tab :: ets:tid(),
                timer :: gen_timeout:tout()}).

-ifndef(OTP_RELEASE).                           % pre-OTP21
-define(WITH_STACKTRACE(T, R, S), T:R -> S = erlang:get_stacktrace(), ).
-else.
-define(WITH_STACKTRACE(T, R, S), T:R:S ->).
-endif.

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec get_downstream_safe(dc_id(), mtp_down_conn:upstream_opts()) ->
                                 {dc_id(), pid(), mtp_down_conn:handle()}.
get_downstream_safe(DcId, Opts) ->
    case get_downstream_pool(DcId) of
        {ok, Pool} ->
            case mtp_dc_pool:get(Pool, self(), Opts) of
                Downstream when is_pid(Downstream) ->
                    {DcId, Pool, Downstream};
                {error, empty} ->
                    %% TODO: maybe sleep and retry?
                    error({pool_empty, DcId, Pool})
            end;
        not_found ->
            [{?IDS_KEY, L}] = ets:lookup(?TAB, ?IDS_KEY),
            NewDcId = random_choice(L),
            get_downstream_safe(NewDcId, Opts)
    end.

get_downstream_pool(DcId) ->
    try whereis(mtp_dc_pool:dc_to_pool_name(DcId)) of
        undefined -> not_found;
        Pid when is_pid(Pid) -> {ok, Pid}
    catch error:invalid_dc_id ->
            not_found
    end.

-spec get_netloc_safe(dc_id()) -> {dc_id(), netloc()}.
get_netloc_safe(DcId) ->
    case get_netloc(DcId) of
        {ok, Addr} -> {DcId, Addr};
        not_found ->
            [{?IDS_KEY, L}] = ets:lookup(?TAB, ?IDS_KEY),
            NewDcId = random_choice(L),
            %% Get random DC; it might return 0 and recurse aggain
            get_netloc_safe(NewDcId)
    end.

get_netloc(DcId) ->
    Key = ?IPS_KEY(DcId),
    case ets:lookup(?TAB, Key) of
        [] ->
            not_found;
        [{Key, [{_, _} = IpPort]}] ->
            {ok, IpPort};
        [{Key, L}] ->
            IpPort = random_choice(L),
            {ok, IpPort}
    end.


-spec get_secret() -> binary().
get_secret() ->
    [{_, Key}] = ets:lookup(?TAB, key),
    Key.

-spec status() -> [mtp_dc_pool:status()].
status() ->
    [{?IDS_KEY, L}] = ets:lookup(?TAB, ?IDS_KEY),
    lists:map(
      fun(DcId) ->
              {ok, Pid} = get_downstream_pool(DcId),
              mtp_dc_pool:status(Pid)
      end, L).


-spec update() -> ok.
update() ->
    gen_server:cast(?MODULE, update).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    Timer = gen_timeout:new(
              #{timeout => {env, ?APP, conf_refresh_interval, 3600},
                unit => second}),
    Tab = ets:new(?TAB, [set,
                         public,
                         named_table,
                         {read_concurrency, true}]),
    State = #state{tab = Tab,
                   timer = Timer},
    update(State, force),
    {ok, State}.

%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(update, #state{timer = Timer} = State) ->
    update(State, soft),
    ?log(info, "Config updated"),
    Timer1 = gen_timeout:bump(
               gen_timeout:reset(Timer)),
    {noreply, State#state{timer = Timer1}}.

handle_info(timeout, #state{timer = Timer} =State) ->
    case gen_timeout:is_expired(Timer) of
        true ->
            update(State, soft),
            ?log(info, "Config updated"),
            Timer1 = gen_timeout:bump(
                       gen_timeout:reset(Timer)),
            {noreply, State#state{timer = Timer1}};
        false ->
            {noreply, State#state{timer = gen_timeout:reset(Timer)}}
    end.
terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

update(#state{tab = Tab}, force) ->
    update_ip(),
    update_key(Tab),
    update_config(Tab);
update(State, _) ->
    try update(State, force)
    catch ?WITH_STACKTRACE(Class, Reason, Stack)
            ?log(error, "Err updating proxy settings: ~s",
                 [lager:pr_stacktrace(Stack, {Class, Reason})]) %XXX lager-specific
    end.

update_key(Tab) ->
    Url = application:get_env(mtproto_proxy, proxy_secret_url, ?SECRET_URL),
    {ok, Body} = http_get(Url),
    true = ets:insert(Tab, {key, list_to_binary(Body)}).

update_config(Tab) ->
    Url = application:get_env(mtproto_proxy, proxy_config_url, ?CONFIG_URL),
    {ok, Body} = http_get(Url),
    Downstreams = parse_config(Body),
    update_downstreams(Downstreams, Tab),
    update_ids(Downstreams, Tab).

parse_config(Body) ->
    Lines = string:lexemes(Body, "\n"),
    ProxyLines = lists:filter(
                   fun("proxy_for " ++ _) -> true;
                      (_) -> false
                   end, Lines),
    [parse_downstream(Line) || Line <- ProxyLines].

parse_downstream(Line) ->
    ["proxy_for",
     DcId,
     IpPort] = string:lexemes(Line, " "),
    [Ip, PortWithTrailer] = string:split(IpPort, ":", trailing),
    Port = list_to_integer(string:trim(PortWithTrailer, trailing, ";")),
    {ok, IpAddr} = inet:parse_ipv4strict_address(Ip),
    {list_to_integer(DcId),
     IpAddr,
     Port}.

update_downstreams(Downstreams, Tab) ->
    ByDc = lists:foldl(
             fun({DcId, Ip, Port}, Acc) ->
                     Netlocs = maps:get(DcId, Acc, []),
                     Acc#{DcId => [{Ip, Port} | Netlocs]}
             end, #{}, Downstreams),
    [true = ets:insert(Tab, {?IPS_KEY(DcId), Netlocs})
     || {DcId, Netlocs} <- maps:to_list(ByDc)],
    lists:foreach(
      fun(DcId) ->
              case get_downstream_pool(DcId) of
                  not_found ->
                      {ok, _Pid} = mtp_dc_pool_sup:start_pool(DcId);
                  {ok, _} ->
                      ok
              end
      end,
      maps:keys(ByDc)).

update_ids(Downstreams, Tab) ->
    Ids = lists:usort([DcId || {DcId, _, _} <- Downstreams]),
    true = ets:insert(Tab, {?IDS_KEY, Ids}).

update_ip() ->
    case application:get_env(?APP, ip_lookup_services) of
        undefined -> false;
        {ok, URLs} ->
            update_ip(URLs)
    end.

update_ip([Url | Fallbacks]) ->
    try
        {ok, Body} = http_get(Url),
        IpStr= string:trim(Body),
        {ok, _} = inet:parse_ipv4strict_address(IpStr), %assert
        application:set_env(?APP, external_ip, IpStr)
    catch ?WITH_STACKTRACE(Class, Reason, Stack)
            ?log(error, "Failed to update IP with ~s service: ~s",
                 [Url, lager:pr_stacktrace(Stack, {Class, Reason})]), %XXX - lager-specific
            update_ip(Fallbacks)
    end;
update_ip([]) ->
    error(ip_lookup_failed).

-ifdef(OTP_VERSION).
%% XXX: ipfamily only works on OTP >= 20.3.4; see OTP 2dc08b47e6a5ea759781479593c55bb5776cd828
%% Enable it for OTP 21+ for simplicity
-define(OPTS, [{socket_opts, [{ipfamily, inet}]}]).
-else.
-define(OPTS, []).
-endif.

http_get(Url) ->
    {ok, Vsn} = application:get_key(mtproto_proxy, vsn),
    UserAgent = "MTProtoProxy/" ++ Vsn ++ " (+https://github.com/seriyps/mtproto_proxy)",
    Headers = [{"User-Agent", UserAgent}],
    {ok, {{_, 200, _}, _, Body}} =
        httpc:request(get, {Url, Headers}, [{timeout, 3000}], ?OPTS),
    {ok, Body}.

random_choice(L) ->
    Idx = rand:uniform(length(L)),
    lists:nth(Idx, L).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_test() ->
    Config = ("# force_probability 1 10
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.162.39:80;
proxy_for 2 149.154.162.33:80;"),
    Expect = [{1, {149, 154, 175, 50}, 8888},
              {-1, {149, 154, 175, 50}, 8888},
              {2, {149, 154, 162, 39}, 80},
              {2, {149, 154, 162, 33},80}],
    ?assertEqual(Expect, parse_config(Config)).

-endif.
