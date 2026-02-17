%% @doc property-based tests for mtp_fake_tls
-module(prop_mtp_fake_tls).
-include_lib("proper/include/proper.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([prop_codec_small/1, prop_codec_big/1, prop_stream/1, prop_variable_length_hello/1]).

prop_codec_small(doc) ->
    "Tests that any binary below 65535 bytes can be encoded and decoded back as single frame".

prop_codec_small() ->
    ?FORALL(Bin, mtp_prop_gen:binary(8, 16 * 1024), codec_small(Bin)).

codec_small(Bin) ->
    %% fake_tls can split big packets to multiple TLS frames of 2^14b
    Codec = mtp_fake_tls:new(),
    {Data, Codec1} = mtp_fake_tls:encode_packet(Bin, Codec),
    {ok, Decoded, <<>>, _} = mtp_fake_tls:try_decode_packet(iolist_to_binary(Data), Codec1),
    Decoded == Bin.


prop_codec_big(doc) ->
    "Tests that big binaries will be split to multiple chunks".

prop_codec_big() ->
    ?FORALL(Bin, mtp_prop_gen:binary(16 * 1024, 65535), codec_big(Bin)).

codec_big(Bin) ->
    Codec = mtp_fake_tls:new(),
    {Data, Codec1} = mtp_fake_tls:encode_packet(Bin, Codec),
    Chunks = decode_stream(iolist_to_binary(Data), Codec1, []),
    ?assert(length(Chunks) > 1),
    ?assertEqual(Bin, iolist_to_binary(Chunks)),
    true.
    

prop_stream(doc) ->
    "Tests that set of packets of size below 2^14b can be encoded and decoded back".

prop_stream() ->
    ?FORALL(Stream, proper_types:list(mtp_prop_gen:binary(8, 16000)),
           codec_stream(Stream)).

codec_stream(Stream) ->
    Codec = mtp_fake_tls:new(),
    {BinStream, Codec1} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_fake_tls:encode_packet(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, Codec}, Stream),
    DecodedStream = decode_stream(BinStream, Codec1, []),
    Stream == DecodedStream.

decode_stream(BinStream, Codec, Acc) ->
    case mtp_fake_tls:try_decode_packet(BinStream, Codec) of
        {incomplete, _} ->
            lists:reverse(Acc);
        {ok, DecPacket, Tail, Codec1} ->
            decode_stream(Tail, Codec1, [DecPacket | Acc])
    end.


prop_variable_length_hello(doc) ->
    "Tests that ClientHello with various packet lengths can be parsed correctly".

prop_variable_length_hello() ->
    ?FORALL({TlsPacketLen, Secret, Domain},
            {proper_types:integer(512, 4096),
             proper_types:binary(16),
             <<"example.com">>},
            variable_length_hello(TlsPacketLen, Secret, Domain)).

variable_length_hello(TlsPacketLen, Secret, Domain) ->
    Timestamp = erlang:system_time(second),
    SessionId = crypto:strong_rand_bytes(32),
    ClientHello = mtp_fake_tls:make_client_hello(Timestamp, SessionId, Secret, Domain, TlsPacketLen),
    %% Verify packet has correct length
    ?assertEqual(5 + TlsPacketLen, byte_size(ClientHello)),
    %% Verify handshake can be parsed
    {ok, _Response, Meta, _Codec} = mtp_fake_tls:from_client_hello(ClientHello, Secret),
    %% Verify metadata
    ?assertEqual(SessionId, maps:get(session_id, Meta)),
    ?assertEqual(Timestamp, maps:get(timestamp, Meta)),
    ?assertEqual(Domain, maps:get(sni_domain, Meta)),
    true.
