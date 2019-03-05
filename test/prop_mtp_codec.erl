%% @doc Property-based tests for mtp_codec
-module(prop_mtp_codec).
-include_lib("proper/include/proper.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([prop_obfuscated_secure_stream/1,
         prop_obfuscated_secure_duplex/1,
         prop_obfuscated_secure_duplex_multi/1]).


prop_obfuscated_secure_stream(doc) ->
    "Tests that any number of packets can be encrypted and decrypted with codec that includes"
        " combination of mtp_obfuscated and mtp_secure".

prop_obfuscated_secure_stream() ->
    ?FORALL({Key, Iv, Stream}, stream_arg_set(), obfuscated_secure_stream(Key, Iv, Stream)).

stream_arg_set() ->
    proper_types:tuple(
      [mtp_prop_gen:key(),
       mtp_prop_gen:iv(),
       mtp_prop_gen:stream_4b()
      ]).

obfuscated_secure_stream(Key, Iv, Stream) ->
    Codec0 = mk_codec(Key, Iv, Key, Iv),
    {BinStream, Codec2} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_codec:encode_packet(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, Codec0}, Stream),
    {ok, RevStream, _Codec3} =
        mtp_codec:fold_packets(
          fun(Decoded, Acc, Codec3) ->
                  {[Decoded | Acc], Codec3}
          end, [], BinStream, Codec2),
    Stream == lists:reverse(RevStream).


prop_obfuscated_secure_duplex(doc) ->
    "Tests that any number of packets can be encrypted and decrypted in both directions using"
        " a pair of keys with codec that uses combination of mtp_obfuscated and mtp_secure".

prop_obfuscated_secure_duplex() ->
    ?FORALL({TxKey, TxIv, RxKey, RxIv, Stream}, duplex_arg_set(),
            obfuscated_secure_duplex(TxKey, TxIv, RxKey, RxIv, Stream)).

duplex_arg_set() ->
    {mtp_prop_gen:key(),
     mtp_prop_gen:iv(),
     mtp_prop_gen:key(),
     mtp_prop_gen:iv(),
     mtp_prop_gen:stream_4b()}.

obfuscated_secure_duplex(TxKey, TxIv, RxKey, RxIv, Stream) ->
    CliCodec0 = mk_codec(TxKey, TxIv, RxKey, RxIv),
    SrvCodec0 = mk_codec(RxKey, RxIv, TxKey, TxIv),
    {_, _, BackStream} = roundtrip(CliCodec0, SrvCodec0, Stream),
    Stream == BackStream.


prop_obfuscated_secure_duplex_multi(doc) ->
    "Tests that any number of packets can be encrypted and decrypted in both directions multiple"
        " times using a pair of keys with codec that uses combination of mtp_obfuscated and"
        " mtp_secure".

prop_obfuscated_secure_duplex_multi() ->
    ?FORALL({N, {TxKey, TxIv, RxKey, RxIv, Stream}}, {proper_types:range(1, 100), duplex_arg_set()},
            obfuscated_secure_duplex_multi(N, TxKey, TxIv, RxKey, RxIv, Stream)).

obfuscated_secure_duplex_multi(N, TxKey, TxIv, RxKey, RxIv, Stream0) ->
    CliCodec0 = mk_codec(TxKey, TxIv, RxKey, RxIv),
    SrvCodec0 = mk_codec(RxKey, RxIv, TxKey, TxIv),
    {_, _, Stream} =
        lists:foldl(
          fun(I, {CliCodec1, SrvCodec1, Stream1}) ->
                  {_, _, BackStream} = Res = roundtrip(CliCodec1, SrvCodec1, Stream1),
                  ?assertEqual(Stream0, BackStream, [{trip_i, I}]),
                  Res
          end, {CliCodec0, SrvCodec0, Stream0}, lists:seq(1, N)),
    Stream0 == Stream.


%% Helpers

roundtrip(CliCodec0, SrvCodec0, Stream) ->
    %% Client creates a stream of bytes
    {CliBinStream, CliCodec1} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_codec:encode_packet(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, CliCodec0}, Stream),
    %% Server decodes stream of bytes and immediately "sends" them back
    {ok, SrvBinStream, SrvCodec1} =
        mtp_codec:fold_packets(
          fun(Decoded, Acc, Codec1) ->
                  {Encoded, Codec2} = mtp_codec:encode_packet(Decoded, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Encoded))/binary>>, Codec2}
          end, <<>>, CliBinStream, SrvCodec0),
    %% Client "receives" and decodes what server sent
    {ok, RevCliDecodedStream, CliCodec2} =
        mtp_codec:fold_packets(
          fun(Decoded, Acc, Codec1) ->
                  {[Decoded | Acc], Codec1}
          end, [], SrvBinStream, CliCodec1),
    {CliCodec2, SrvCodec1, lists:reverse(RevCliDecodedStream)}.

mk_codec(EncKey, EncIv, DecKey, DecIv) ->
    Crypto = mtp_obfuscated:new(EncKey, EncIv, DecKey, DecIv),
    Packet = mtp_secure:new(),
    mtp_codec:new(mtp_obfuscated, Crypto,
                  mtp_secure, Packet).
