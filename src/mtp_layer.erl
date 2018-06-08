%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Behaviour for MTProto layer codec
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_layer).

-export([new/2,
         try_decode_packet/2,
         encode_packet/2]).

-export([fold_packets/4]).
-export_type([codec/0,
              layer/0]).

-type state() :: any().
-type codec() :: mtb_aes_cbc
               | mtp_abridged
               | mtp_full
               | mtp_obfuscated
               | mtp_rpc
               | mtp_wrap.
-type layer() :: {codec(), state()} | ident.

-callback try_decode_packet(binary(), state()) ->
    {ok, binary(), state()}
        | {incomplete, state()}.

-callback encode_packet(binary(), state()) ->
    {binary(), state()}.

new(Mod, S) ->
    {Mod, S}.

encode_packet(Msg, ident) ->
    {Msg, ident};
encode_packet(Msg, {Mod, St}) ->
    {Enc, St1} = Mod:encode_packet(Msg, St),
    {Enc, {Mod, St1}}.

try_decode_packet(Msg, ident) ->
    {ok, Msg, ident};
try_decode_packet(Msg, {Mod, St}) ->
    case Mod:try_decode_packet(Msg, St) of
        {ok, Dec, St1} ->
            {ok, Dec, {Mod, St1}};
        {incomplete, St1} ->
            {incomplete, {Mod, St1}}
    end.

-spec fold_packets(fun( (binary(), FoldSt) -> FoldSt ),
                   FoldSt, binary(), layer()) ->
                          {ok, FoldSt, layer()}
                              when
      FoldSt :: any().
fold_packets(Fun, FoldSt, Data, ident) ->
    FoldSt1 = Fun(Data, FoldSt),
    {ok, FoldSt1, ident};
fold_packets(Fun, FoldSt, Data, Layer) ->
    case try_decode_packet(Data, Layer) of
        {ok, Decoded, L1} ->
            FoldSt1 = Fun(Decoded, FoldSt),
            fold_packets(Fun, FoldSt1, <<>>, L1);
        {incomplete, L1} ->
            {ok, FoldSt, L1}
    end.
