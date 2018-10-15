%%%-------------------------------------------------------------------
%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Supervisor for mtp_down_conn processes
%%% @end
%%% TODO: maybe have one supervisor per-DC
%%% Created : 14 Oct 2018 by Sergey <me@seriyps.ru>
%%%-------------------------------------------------------------------
-module(mtp_down_conn_sup).

-behaviour(supervisor).

-export([start_link/0,
         start_conn/2]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec start_conn(pid(), mtp_conf:dc_id()) -> {ok, pid()}.
start_conn(Pool, DcId) ->
    supervisor:start_child(?SERVER, [Pool, DcId]).

init([]) ->

    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 50,
                 period => 5},

    AChild = #{id => mtp_down_conn,
               start => {mtp_down_conn, start_link, []},
               restart => temporary,
               shutdown => 2000,
               type => worker},

    {ok, {SupFlags, [AChild]}}.
