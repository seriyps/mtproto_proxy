%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Supervisor for mtp_dc_pool processes
%%% @end
%%% Created : 14 Oct 2018 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_dc_pool_sup).

-behaviour(supervisor).

-export([start_link/0,
         start_pool/1]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec start_pool(mtp_config:dc_id()) -> {ok, pid()}.
start_pool(DcId) ->
    %% Or maybe it should read IPs from mtp_config by itself?
    supervisor:start_child(?SERVER, [DcId]).

init([]) ->

    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 50,
                 period => 5},

    AChild = #{id => mtp_dc_pool,
               start => {mtp_dc_pool, start_link, []},
               restart => permanent,
               shutdown => 10000,
               type => worker},

    {ok, {SupFlags, [AChild]}}.
