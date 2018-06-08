%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto abridged packet format codec
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>

-module(mtp_abridged).
-behaviour(mtp_layer).

-export([new/0,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-record(st,
        {buffer = <<>> :: binary()}).
-define(MAX_PACKET_SIZE, 1 * 1024 * 1024).      % 1mb
-define(APP, mtproto_proxy).

-opaque codec() :: #st{}.

new() ->
    #st{}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<Flag, Len:24/unsigned-little-integer, Rest/binary>> = Data,
                      #st{buffer = <<>>} = St) when Flag == 127; Flag == 255 ->
    Len1 = Len * 4,
    (Len1 < ?MAX_PACKET_SIZE)
        orelse
        begin
            metric:count_inc([?APP, protocol_error, total], 1, #{labels => [abriged_max_size]}),
            error({packet_too_large, Len1})
        end,
    try_decode_packet_len(Len1, Rest, Data, St);
try_decode_packet(<<Len, Rest/binary>> = Data,
                      #st{buffer = <<>>} = St) when Len >= 128 ->
    Len1 = (Len - 128) * 4,
    try_decode_packet_len(Len1, Rest, Data, St);
try_decode_packet(<<Len, Rest/binary>> = Data,
                      #st{buffer = <<>>} = St) when Len < 127 ->
    Len1 = Len * 4,
    try_decode_packet_len(Len1, Rest, Data, St);
try_decode_packet(Bin, #st{buffer = Buf} = St) when byte_size(Buf) > 0 ->
    try_decode_packet(<<Buf/binary, Bin/binary>>, St#st{buffer = <<>>});
try_decode_packet(Bin, #st{buffer = <<>>} = St) ->
    {incomplete, St#st{buffer = Bin}}.

try_decode_packet_len(Len, LenStripped, Data, St) ->
    case LenStripped of
        <<Packet:Len/binary, Rest/binary>> ->
            {ok, Packet, St#st{buffer = Rest}};
        _ ->
            {incomplete, St#st{buffer = Data}}
    end.

-spec encode_packet(binary(), codec()) -> iodata().
encode_packet(Bin, St) ->
    Size = byte_size(Bin),
    Len = Size div 4,
    Packet =
        case Len < 127 of
            true ->
                [Len | Bin];
            false ->
                [<<127, Len:24/unsigned-little-integer>> | Bin]
        end,
    {Packet, St}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

decode_none_test() ->
    S = new(),
    ?assertEqual(
       {incomplete, S}, try_decode_packet(<<>>, S)).

-endif.
