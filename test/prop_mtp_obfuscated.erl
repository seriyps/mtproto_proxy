%% @doc property-based tests for mtp_obfuscated
-module(prop_mtp_obfuscated).
-include_lib("proper/include/proper.hrl").

-export([prop_stream/1,
         prop_client_server_handshake/1,
         prop_client_server_stream/1]).

prop_stream(doc) ->
    "Tests that any number of packets can be encrypted with mtp_obfuscatedcoded,"
        " concatenated and decoded as a stream using the same key for encoding and decoding".

prop_stream() ->
    ?FORALL({Key, Iv, Stream}, stream_arg_set(), stream_codec(Key, Iv, Stream)).


stream_arg_set() ->
    proper_types:tuple(
      [mtp_prop_gen:key(),
       mtp_prop_gen:iv(),
       mtp_prop_gen:stream_4b()
      ]).

stream_codec(Key, Iv, Stream) ->
    Codec = mtp_obfuscated:new(Key, Iv, Key, Iv),
    {BinStream, Codec2} =
        lists:foldl(
          fun(Bin, {Acc, Codec1}) ->
                  {Data, Codec2} = mtp_obfuscated:encrypt(Bin, Codec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   Codec2}
          end, {<<>>, Codec}, Stream),
    {Decrypted, <<>>, _Codec3} = mtp_obfuscated:decrypt(BinStream, Codec2),
    %% io:format("Dec: ~p~nOrig: ~p~nCodec: ~p~n", [Decrypted, Stream, _Codec3]),
    Decrypted == iolist_to_binary(Stream).


prop_client_server_handshake(doc) ->
    "Tests that for any secret, protocol and dc_id, it's possible to perform handshake".

prop_client_server_handshake() ->
    ?FORALL({Secret, DcId, Protocol}, cs_hs_arg_set(),
            cs_hs_exchange(Secret, DcId, Protocol)).

cs_hs_arg_set() ->
    proper_types:tuple(
      [mtp_prop_gen:secret(),
       mtp_prop_gen:dc_id(),
       mtp_prop_gen:codec()]).

cs_hs_exchange(Secret, DcId, Protocol) ->
    %% io:format("Secret: ~p; DcId: ~p, Protocol: ~p~n",
    %%           [Secret, DcId, Protocol]),
    {Packet, _, _, _CliCodec} = mtp_obfuscated:client_create(Secret, Protocol, DcId),
    case mtp_obfuscated:from_header(Packet, Secret) of
        {ok, DcId, Protocol, _SrvCodec} ->
            true;
        _ ->
            false
    end.

prop_client_server_stream(doc) ->
    "Tests that for any secret, protocol and dc_id, it's possible to perform"
        " handshake/key exchange and then do bi-directional encode/decode stream of data".

prop_client_server_stream() ->
    ?FORALL({Secret, DcId, Protocol, Stream}, cs_stream_arg_set(),
            cs_stream_exchange(Secret, DcId, Protocol, Stream)).

cs_stream_arg_set() ->
    proper_types:tuple(
      [mtp_prop_gen:secret(),
       mtp_prop_gen:dc_id(),
       mtp_prop_gen:codec(),
       mtp_prop_gen:stream_4b()]).

cs_stream_exchange(Secret, DcId, Protocol, Stream) ->
    %% io:format("Secret: ~p; DcId: ~p, Protocol: ~p~n",
    %%           [Secret, DcId, Protocol]),
    {Header, _, _, CliCodec} = mtp_obfuscated:client_create(Secret, Protocol, DcId),
    {ok, DcId, Protocol, SrvCodec} = mtp_obfuscated:from_header(Header, Secret),

    %% Client to server
    {CliCodec1,
     SrvCodec1,
     Cli2SrvTransmitted} = transmit_stream(CliCodec, SrvCodec, Stream),
    {_CliCodec2,
     _SrvCodec2,
     Srv2CliTransmitted} = transmit_stream(SrvCodec1, CliCodec1, Stream),
    BinStream = iolist_to_binary(Stream),
    (Cli2SrvTransmitted == BinStream)
        andalso (Srv2CliTransmitted == BinStream).

transmit_stream(EncCodec, DecCodec, Stream) ->
    {EncStream, EncCodec3} =
        lists:foldl(
          fun(Packet, {Acc, CliCodec1}) ->
                  {Data, CliCodec2} = mtp_obfuscated:encrypt(Packet, CliCodec1),
                  {<<Acc/binary, (iolist_to_binary(Data))/binary>>,
                   CliCodec2}
          end, {<<>>, EncCodec}, Stream),
    {Decrypted, <<>>, DecCodec2} = mtp_obfuscated:decrypt(EncStream, DecCodec),
    {EncCodec3,
     DecCodec2,
     Decrypted}.
