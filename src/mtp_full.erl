%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto "full" packet format with padding
%%% ```
%%% <<MsgLen:32/integer, SeqNo:32/integer, Body:MsgLen/binary, CRC:32/integer>>
%%% ```
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_full).
-behaviour(mtp_codec).

-export([new/0, new/3,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-dialyzer(no_improper_lists).

-record(full_st,
        {enc_seq_no :: integer(),
         dec_seq_no :: integer(),
         check_crc = true :: boolean()}).

-define(MIN_MSG_LEN, 12).
-define(MAX_MSG_LEN,  16777216).                %2^24 - 16mb

-define(BLOCK_SIZE, 16).
-define(PAD, <<4:32/little>>).
-define(APP, mtproto_proxy).

-opaque codec() :: #full_st{}.


new() ->
    new(0, 0, true).

new(EncSeqNo, DecSeqNo, CheckCRC) ->
    #full_st{enc_seq_no = EncSeqNo,
             dec_seq_no = DecSeqNo,
             check_crc = CheckCRC}.

try_decode_packet(<<4:32/little, Tail/binary>>, S) ->
    %% Skip padding
    try_decode_packet(Tail, S);
try_decode_packet(<<Len:32/little, PktSeqNo:32/signed-little, Tail/binary>>,
                  #full_st{dec_seq_no = SeqNo, check_crc = CheckCRC} = S) ->
    ((Len rem byte_size(?PAD)) == 0)
        orelse error({wrong_alignement, Len}),
    ((?MIN_MSG_LEN =< Len) and (Len =< ?MAX_MSG_LEN))
        orelse error({wrong_msg_len, Len}),
    (SeqNo == PktSeqNo)
        orelse error({wrong_seq_no, SeqNo, PktSeqNo}),
    BodyLen = Len - 4 - 4 - 4,
    case Tail of
        <<Body:BodyLen/binary, CRC:32/little, Rest/binary>> ->
            case CheckCRC of
                true ->
                    PacketCrc = erlang:crc32([<<Len:32/little, PktSeqNo:32/little>> | Body]),
                    (CRC == PacketCrc)
                        orelse error({wrong_checksum, CRC, PacketCrc});
                false ->
                    ok
            end,
            %% TODO: predict padding size from padding_size(Len)
            {ok, Body, trim_padding(Rest), S#full_st{dec_seq_no = SeqNo + 1}};
        _ ->
            {incomplete, S}
    end;
try_decode_packet(_, S) ->
    {incomplete, S}.

trim_padding(<<4:32/little, Tail/binary>>) ->
    trim_padding(Tail);
trim_padding(Bin) -> Bin.


encode_packet(Bin, #full_st{enc_seq_no = SeqNo} = S) ->
    BodySize = iolist_size(Bin),
    ((BodySize rem byte_size(?PAD)) == 0)
        orelse error({wrong_alignment, BodySize}),
    Len = BodySize + 4 + 4 + 4,
    MsgNoChecksum =
        [<<Len:32/unsigned-little-integer,
           SeqNo:32/signed-little-integer>>
             | Bin],
    CheckSum = erlang:crc32(MsgNoChecksum),
    FullMsg = [MsgNoChecksum | <<CheckSum:32/unsigned-little-integer>>],
    Len = iolist_size(FullMsg),
    NPaddings = padding_size(Len) div byte_size(?PAD),
    Padding = lists:duplicate(NPaddings, ?PAD),
    {[FullMsg | Padding], S#full_st{enc_seq_no = SeqNo + 1}}.

padding_size(Len) ->
    %% XXX: is there a cleaner way?
    (?BLOCK_SIZE - (Len rem ?BLOCK_SIZE)) rem ?BLOCK_SIZE.


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encode_nopadding_test() ->
    S = new(),
    {Enc, _S1} = encode_packet(<<1, 1, 1, 1>>, S),
    ?assertEqual(
       <<16,0,0,0,
         0,0,0,0,
         1,1,1,1,
         22,39,175,160>>,
       iolist_to_binary(Enc)).

encode_padding_test() ->
    S = new(),
    {Enc, _S1} = encode_packet(<<1,1,1,1,1,1,1,1>>, S),
    ?assertEqual(
       <<20,0,0,0,0,0,0,0,                      %size, seq no
         1,1,1,1,1,1,1,1,                       %data
         246,196,46,149,                        %CRC
         4,0,0,0,4,0,0,0,4,0,0,0>>,             %padding
       iolist_to_binary(Enc)).

encode_padding_seq_test() ->
    S = new(),
    {Enc1, S1} = encode_packet(binary:copy(<<9>>, 8), S),
    ?assertEqual(
       <<20,0,0,0,
         0,0,0,0,
         9,9,9,9,9,9,9,9,
         229,35,162,164,
         4, 0,0,0,4,0,0,0,4,0,0,0>>,
       iolist_to_binary(Enc1)),
    {Enc2, _S2} = encode_packet(binary:copy(<<8>>, 8), S1),
    ?assertEqual(
       <<20,0,0,0,
         1,0,0,0,
         8,8,8,8,8,8,8,8,
         48,146,132,116,
         4,0,0,0,4,0,0,0,4,0,0,0>>,
       iolist_to_binary(Enc2)).

decode_none_test() ->
    S = new(),
    ?assertEqual(
       {incomplete, S}, try_decode_packet(<<>>, S)).

codec_test() ->
    %% Overhead is 12b per-packet
    S = new(),
    Packets = [
               binary:copy(<<0>>, 4),           %non-padded
               binary:copy(<<1>>, 8),           %padded
               binary:copy(<<2>>, 4),           %non-padded
               binary:copy(<<2>>, 100)          %padded
              ],
    lists:foldl(
      fun(B, S1) ->
              {Encoded, S2} = encode_packet(B, S1),
              BinEncoded = iolist_to_binary(Encoded),
              {ok, Decoded, <<>>, S3} = try_decode_packet(BinEncoded, S2),
              ?assertEqual(B, Decoded, {BinEncoded, S2, S3}),
              S3
      end, S, Packets).

codec_stream_test() ->
    S = new(),
    Packets = [
               binary:copy(<<0>>, 4),           %non-padded
               binary:copy(<<1>>, 8),           %padded
               binary:copy(<<2>>, 4),           %non-padded
               binary:copy(<<2>>, 100)          %padded
              ],
    {Encoded, SS} =
        lists:foldl(
          fun(B, {Enc1, S1}) ->
                  {Enc2, S2} = encode_packet(B, S1),
                  {[Enc1 | Enc2], S2}
          end, {[], S}, Packets),
    lists:foldl(
      fun(B, {Enc, S1}) ->
              {ok, Dec, Rest, S2} = try_decode_packet(Enc, S1),
              ?assertEqual(B, Dec),
              {Rest, S2}
      end, {iolist_to_binary(Encoded), SS}, Packets).

-endif.
