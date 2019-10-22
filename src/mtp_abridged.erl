%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto abridged packet format codec
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>

-module(mtp_abridged).
-behaviour(mtp_codec).

-export([new/0,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-dialyzer(no_improper_lists).

-record(st,
        {}).
-define(MAX_PACKET_SIZE, 1 * 1024 * 1024).      % 1mb
-define(APP, mtproto_proxy).

-opaque codec() :: #st{}.

new() ->
    #st{}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<Flag, Len:24/unsigned-little-integer, Rest/binary>>,
                      #st{} = St) when Flag == 127; Flag == 255 ->
    Len1 = Len * 4,
    try_decode_packet_len(Len1, Rest, St);
try_decode_packet(<<Len, Rest/binary>>,
                      #st{} = St) when Len >= 128 ->
    Len1 = (Len - 128) * 4,
    try_decode_packet_len(Len1, Rest, St);
try_decode_packet(<<Len, Rest/binary>>,
                      #st{} = St) when Len < 127 ->
    Len1 = Len * 4,
    try_decode_packet_len(Len1, Rest, St);
try_decode_packet(_, St) ->
    {incomplete, St}.

try_decode_packet_len(Len, LenStripped, St) ->
    (Len < ?MAX_PACKET_SIZE)
        orelse error({protocol_error, abridged_max_size, Len}),
    case LenStripped of
        <<Packet:Len/binary, Rest/binary>> ->
            {ok, Packet, Rest, St};
        _ ->
            {incomplete, St}
    end.

-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Data, St) ->
    Size = iolist_size(Data),
    Len = Size div 4,
    Packet =
        case Len < 127 of
            true ->
                [Len | Data];
            false ->
                [<<127, Len:24/unsigned-little-integer>> | Data]
        end,
    {Packet, St}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

decode_none_test() ->
    S = new(),
    ?assertEqual(
       {incomplete, S}, try_decode_packet(<<>>, S)).

-endif.
