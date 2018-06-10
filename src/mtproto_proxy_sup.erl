%%%-------------------------------------------------------------------
%% @doc mtproto_proxy top level supervisor.
%% @end
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

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    Childs = [#{id => mtp_config,
                start => {mtp_config, start_link, []}}
             ],
    {ok, {#{strategy => rest_for_one,
            intensity => 50,
            period => 5},
          Childs} }.

%%====================================================================
%% Internal functions
%%====================================================================
