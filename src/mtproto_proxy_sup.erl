%%%-------------------------------------------------------------------
%% @doc mtproto_proxy top level supervisor.
%% @end
%% <pre>
%% In `both' (default) or `back' role:
%% dc_pool_sup (simple_one_for_one)
%%   dc_pool_1 [conn1, conn3, conn4, ..]
%%   dc_pool_-1 [conn2, ..]
%%   dc_pool_2 [conn5, conn7, ..]
%%   dc_pool_-2 [conn6, conn8, ..]
%%   ...
%% down_conn_sup (simple_one_for_one)
%%   conn1..connN
%%
%% In `front' role only session/policy children are started;
%% DC pools live on the remote back node.
%% </pre>
%%%-------------------------------------------------------------------

-module(mtproto_proxy_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
    SupFlags = #{strategy => one_for_all,       %TODO: maybe change strategy
                 intensity => 50,
                 period => 5},
    Role = application:get_env(mtproto_proxy, node_role, both),
    {ok, {SupFlags, children(Role)}}.

%%====================================================================
%% Internal functions
%%====================================================================

children(front) ->
    [#{id => mtp_session_storage,
       start => {mtp_session_storage, start_link, []}},
     #{id => mtp_policy_table,
       start => {mtp_policy_table, start_link, []}},
     #{id => mtp_policy_counter,
       start => {mtp_policy_counter, start_link, []}}];
children(back) ->
    [#{id => mtp_down_conn_sup,
       type => supervisor,
       start => {mtp_down_conn_sup, start_link, []}},
     #{id => mtp_dc_pool_sup,
       type => supervisor,
       start => {mtp_dc_pool_sup, start_link, []}},
     #{id => mtp_config,
       start => {mtp_config, start_link, []}}];
children(both) ->
    children(back) ++ children(front).
