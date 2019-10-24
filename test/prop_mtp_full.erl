%% @doc property-based tests for mtp_full
-module(prop_mtp_full).
-include_lib("proper/include/proper.hrl").

-export([prop_codec/1, prop_stream/1]).


prop_codec(doc) ->
    "Tests that any 4-byte aligned binary can be encoded and decoded back".

prop_codec() ->
    ?FORALL({CheckCRC, Bin}, {proper_types:boolean(), mtp_prop_gen:packet_4b()},
            codec(Bin, CheckCRC)).

codec(Bin, CheckCRC) ->
    Codec = mtp_full:new(0, 0, CheckCRC),
    {Data, Codec1} = mtp_full:encode_packet(Bin, Codec),
    {ok, Decoded, <<>>, _} = mtp_full:try_decode_packet(iolist_to_binary(Data), Codec1),
    Decoded == Bin.


prop_stream(doc) ->
    "Tests that any number of packets can be encoded, concatenated and decoded".

prop_stream() ->
    ?FORALL(Stream, mtp_prop_gen:stream_4b(), stream_codec(Stream)).

stream_codec(Stream) ->
    Codec = mtp_full:new(),
    {BinStream, Codec1} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_full:encode_packet(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, Codec}, Stream),
    DecodedStream = decode_stream(BinStream, Codec1, []),
    Stream == DecodedStream.

decode_stream(BinStream, Codec, Acc) ->
    case mtp_full:try_decode_packet(BinStream, Codec) of
        {incomplete, _} ->
            lists:reverse(Acc);
        {ok, DecPacket, Tail, Codec1} ->
            decode_stream(Tail, Codec1, [DecPacket | Acc])
    end.
