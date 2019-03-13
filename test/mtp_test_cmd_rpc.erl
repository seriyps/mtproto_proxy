%% @doc Callback module for mtp_test_middle_server that supports some more tricky commands
-module(mtp_test_cmd_rpc).
-export([call/3,
         packet_to_term/1]).
-export([init/1,
         handle_rpc/2]).

call(M, F, Opts) ->
    true = erlang:function_exported(M, F, 3),
    term_to_packet({M, F, Opts}).

term_to_packet(Term) ->
    RespBin = term_to_binary(Term),
    RespSize = byte_size(RespBin),
    PadSize = case (RespSize rem 16) of
                  0 -> 0;
                  Rem -> 16 - Rem
              end,
    Pad = binary:copy(<<0>>, PadSize),
    <<RespSize:32/little-unsigned, RespBin/binary, Pad/binary>>.

packet_to_term(<<Size:32/little-unsigned, Term:Size/binary, _Pad/binary>>) ->
    binary_to_term(Term).

init(_) ->
    #{}.

handle_rpc({data, ConnId, Req}, St) ->
    {M, F, Opts} = packet_to_term(Req),
    case M:F(Opts, ConnId, St) of
        {reply, Resp, St1} ->
            {rpc, {proxy_ans, ConnId, term_to_packet(Resp)}, St1};
        {close, St1} ->
            {rpc, {close_ext, ConnId}, tombstone(ConnId, St1)};
        {return, What} ->
            What
    end;
handle_rpc({remote_closed, ConnId}, St) ->
    {noreply, tombstone(ConnId, St)}.

tombstone(ConnId, St) ->
    ({ok, tombstone} =/= maps:find(ConnId, St))
        orelse error({already_closed, ConnId}),
    St#{ConnId => tombstone}.
