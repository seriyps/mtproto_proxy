%% @doc Property-based tests for mtp_aes_cbc
-module(prop_mtp_aes_cbc).
-include_lib("proper/include/proper.hrl").

-export([prop_stream/1]).

prop_stream(doc) ->
    "Tests that any number of packets can be encoded, concatenated and decoded"
        " as a stream using the same key for encoding and decoding".

prop_stream() ->
    ?FORALL({Key, Iv, Stream}, arg_set(), stream_codec(Key, Iv, Stream)).


arg_set() ->
    proper_types:tuple(
      [mtp_prop_gen:key(),
       mtp_prop_gen:iv(),
       mtp_prop_gen:stream_16b()
      ]).

stream_codec(Key, Iv, Stream) ->
    Codec = mtp_aes_cbc:new(Key, Iv, Key, Iv, 16),
    {BinStream, Codec2} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_aes_cbc:encrypt(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, Codec}, Stream),
    {Decrypted, <<>>, _Codec3} = mtp_aes_cbc:decrypt(BinStream, Codec2),
    %% io:format("Dec: ~p~nOrig: ~p~nCodec: ~p~n", [Decrypted, Stream, _Codec3]),
    Decrypted == iolist_to_binary(Stream).
