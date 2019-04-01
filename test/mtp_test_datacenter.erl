%% Fake telegram "datacenters"
%% Mock to emulate core.telegram.org and set of telegram
%% "middle-proxies" for each datacenter ID
-module(mtp_test_datacenter).

-export([start_dc/0,
         start_dc/3,
         stop_dc/1,
         start_config_server/5,
         stop_config_server/1]).
-export([middle_connections/1]).
-export([dc_list_to_config/1]).
-export([do/1]).

-include_lib("inets/include/httpd.hrl").

-define(SECRET_PATH, "/getProxySecret").
-define(CONFIG_PATH, "/getProxyConfig").

-type dc_conf() :: [{DcId :: integer(),
                     Ip :: inet:ip4_address(),
                     Port :: inet:port_number()}].

start_dc() ->
    Secret = crypto:strong_rand_bytes(128),
    DcConf = [{1, {127, 0, 0, 1}, 8888}],
    {ok, _Cfg} = start_dc(Secret, DcConf, #{}).

-spec start_dc(binary(), dc_conf(), #{}) -> {ok, #{}}.
start_dc(Secret, DcConf, Acc) ->
    Cfg = dc_list_to_config(DcConf),
    {ok, Acc1} = start_config_server({127, 0, 0, 1}, 0, Secret, Cfg, Acc),
    RpcHandler = maps:get(rpc_handler, Acc, mtp_test_echo_rpc),
    Ids =
        [begin
             Id = {?MODULE, DcId},
             {ok, _Pid} = mtp_test_middle_server:start(
                            Id, #{port => Port,
                                  ip => Ip,
                                  secret => Secret,
                                  rpc_handler => RpcHandler}),
             Id
         end || {DcId, Ip, Port} <- DcConf],
    {ok, Acc1#{srv_ids => Ids}}.

stop_dc(#{srv_ids := Ids} = Acc) ->
    {ok, Acc1} = stop_config_server(Acc),
    ok = lists:foreach(fun mtp_test_middle_server:stop/1, Ids),
    {ok, maps:without([srv_ids], Acc1)}.

middle_connections(#{srv_ids := Ids}) ->
    lists:flatten([ranch:procs(Id, connections)
                   || Id <- Ids]).

%%
%% Inets HTTPD to use as a mock for https://core.telegram.org
%%

%% Api
start_config_server(Ip, Port, Secret, DcConfig, Acc) ->
    application:load(mtproto_proxy),
    RootDir = code:lib_dir(mtproto_proxy, test),
    {ok, Pid} =
        inets:start(httpd,
                    [{port, Port},
                     {server_name, "mtp_config"},
                     {server_root, "/tmp"},
                     {document_root, RootDir},

                     {bind_address, Ip},
                     {modules, [?MODULE]},
                     {mtp_secret, Secret},
                     {mtp_dc_conf, DcConfig}]),
    %% Get listen port in case when Port is 0 (ephemeral)
    [{port, RealPort}] = httpd:info(Pid, [port]),
    Netloc = lists:flatten(io_lib:format("http://~s:~w", [inet:ntoa(Ip), RealPort])),
    Env = [{proxy_secret_url,
            Netloc ++ ?SECRET_PATH},
           {proxy_config_url,
            Netloc ++ ?CONFIG_PATH},
           {external_ip, "127.0.0.1"},
           {ip_lookup_services, undefined}],
    OldEnv =
        [begin
             %% OldV is undefined | {ok, V}
             OldV = application:get_env(mtproto_proxy, K),
             case V of
                 undefined -> application:unset_env(mtproto_proxy, K);
                 _ ->
                     application:set_env(mtproto_proxy, K, V)
             end,
             {K, OldV}
         end || {K, V} <- Env],
    {ok, Acc#{env => OldEnv,
              httpd_pid => Pid}}.

stop_config_server(#{env := Env, httpd_pid := Pid} = Acc) ->
    [case V of
         undefined ->
             application:unset_env(mtproto_proxy, K);
         {ok, Val} ->
             application:set_env(mtproto_proxy, K, Val)
     end || {K, V} <- Env],
    inets:stop(httpd, Pid),
    {ok, maps:without([env, httpd_pid], Acc)}.

dc_list_to_config(List) ->
    <<
      <<(list_to_binary(
           io_lib:format("proxy_for ~w ~s:~w;~n", [DcId, inet:ntoa(Ip), Port])
          ))/binary>>
      || {DcId, Ip, Port} <- List
      >>.

%% Inets callback
do(#mod{request_uri = ?CONFIG_PATH, config_db = Db}) ->
    [{_, DcConf}] = ets:lookup(Db, mtp_dc_conf),
    {break, [{response, {200, binary_to_list(DcConf)}}]};
do(#mod{request_uri = ?SECRET_PATH, config_db = Db}) ->
    [{_, Secret}] = ets:lookup(Db, mtp_secret),
    {break, [{response, {200, binary_to_list(Secret)}}]}.
