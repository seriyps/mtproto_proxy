%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% This module provieds a comination of crypto and packet codecs.
%%% Crypto is always outer layer and packet is inner:
%%% ( --- packet --- )
%%%   (-- crypto --)
%%%      - tcp -
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_codec).

-export([new/4,
         decompose/1,
         try_decode_packet/2,
         encode_packet/2,
         fold_packets/4,
         is_empty/1]).
-export_type([codec/0]).

-type state() :: any().
-type crypto_codec() :: mtp_aes_cbc
                      | mtp_obfuscated
                      | mtp_noop_codec.
-type packet_codec() :: mtp_abridged
                      | mtp_full
                      | mtp_intermediate
                      | mtp_secure.

-record(codec,
        {crypto_mod :: crypto_codec(),
         crypto_state :: any(),
         crypto_buf = <<>> :: binary(),
         packet_mod :: packet_codec(),
         packet_state :: any(),
         packet_buf = <<>> :: binary()}).

-define(APP, mtproto_proxy).

-callback try_decode_packet(binary(), state()) ->
    {ok, Packet :: binary(), Tail :: binary(), state()}
        | {incomplete, state()}.

-callback encode_packet(iodata(), state()) ->
    {iodata(), state()}.

-opaque codec() :: #codec{}.


-spec new(crypto_codec(), state(), packet_codec(), state()) -> codec().
new(CryptoMod, CryptoState, PacketMod, PacketState) ->
    #codec{crypto_mod = CryptoMod,
           crypto_state = CryptoState,
           packet_mod = PacketMod,
           packet_state = PacketState}.

-spec decompose(codec()) -> {crypto_codec(), state(), packet_codec(), state()}.
decompose(#codec{crypto_mod = CryptoMod, crypto_state = CryptoState,
                 packet_mod = PacketMod, packet_state = PacketState}) ->
    {CryptoMod, CryptoState, PacketMod, PacketState}.


%% try_decode_packet(Inner) |> try_decode_packet(Outer)
-spec try_decode_packet(binary(), codec()) -> {ok, binary(), codec()} | {incomplete, codec()}.
try_decode_packet(Bin, S) ->
    decode_crypto(Bin, S).

decode_crypto(<<>>, #codec{crypto_state = CS, crypto_buf = <<>>} = S) ->
    %% There is smth in packet buffer
    decode_packet(<<>>, CS, <<>>, S);
decode_crypto(Bin, #codec{crypto_mod = CryptoMod,
                          crypto_state = CryptoSt,
                          crypto_buf = <<>>} = S) ->
    case CryptoMod:try_decode_packet(Bin, CryptoSt) of
        {incomplete, CryptoSt1} ->
            decode_packet(<<>>, CryptoSt1, <<>>, S);
        {ok, Dec1, Tail1, CryptoSt1} ->
            decode_packet(Dec1, CryptoSt1, Tail1, S)
    end;
decode_crypto(Bin, #codec{crypto_buf = Buf} = S) ->
    decode_crypto(<<Buf/binary, Bin/binary>>, S#codec{crypto_buf = <<>>}).


decode_packet(<<>>, CryptoSt, CryptoTail, #codec{packet_buf = <<>>} = S) ->
    %% Crypto produced nothing and there is nothing in packet buf
    {incomplete, S#codec{crypto_state = CryptoSt, crypto_buf = CryptoTail}};
decode_packet(Bin, CryptoSt, CryptoTail, #codec{packet_mod = PacketMod,
                                                packet_state = PacketSt,
                                                packet_buf = <<>>} = S) ->
    %% Crypto produced smth, and there is nothing in pkt buf
    case PacketMod:try_decode_packet(Bin, PacketSt) of
        {incomplete, PacketSt1} ->
            {incomplete, S#codec{crypto_state = CryptoSt,
                                 crypto_buf = CryptoTail,
                                 packet_state = PacketSt1,
                                 packet_buf = Bin
                                }};
        {ok, Dec2, Tail, PacketSt1} ->
            {ok, Dec2, S#codec{crypto_state = CryptoSt,
                               crypto_buf = CryptoTail,
                               packet_state = PacketSt1,
                               packet_buf = Tail}}
    end;
decode_packet(Bin, CSt, CTail, #codec{packet_buf = Buf} = S) ->
    decode_packet(<<Buf/binary, Bin/binary>>, CSt, CTail, S#codec{packet_buf = <<>>}).


%% encode_packet(Outer) |> encode_packet(Inner)
-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #codec{packet_mod = PacketMod,
                          packet_state = PacketSt,
                          crypto_mod = CryptoMod,
                          crypto_state = CryptoSt} = S) ->
    {Enc1, PacketSt1} = PacketMod:encode_packet(Bin, PacketSt),
    {Enc2, CryptoSt1} = CryptoMod:encode_packet(Enc1, CryptoSt),
    {Enc2, S#codec{crypto_state = CryptoSt1, packet_state = PacketSt1}}.


-spec fold_packets(fun( (binary(), FoldSt, codec()) -> FoldSt ),
                   FoldSt, binary(), codec()) ->
                          {ok, FoldSt, codec()}
                              when
      FoldSt :: any().
fold_packets(Fun, FoldSt, Data, Codec) ->
    case try_decode_packet(Data, Codec) of
        {ok, Decoded, Codec1} ->
            {FoldSt1, Codec2} = Fun(Decoded, FoldSt, Codec1),
            fold_packets(Fun, FoldSt1, <<>>, Codec2);
        {incomplete, Codec1} ->
            {ok, FoldSt, Codec1}
    end.

-spec is_empty(codec()) -> boolean().
is_empty(#codec{packet_buf = <<>>, crypto_buf = <<>>}) -> true;
is_empty(_) -> false.
