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

-export([new/4, new/7,
         info/2, replace/4, push_back/3, is_empty/1,
         try_decode_packet/2,
         encode_packet/2,
         fold_packets/4, fold_packets_if/4]).
-export_type([codec/0]).

-type state() :: any().
-type crypto_codec() :: mtp_aes_cbc
                      | mtp_obfuscated
                      | mtp_noop_codec.
-type packet_codec() :: mtp_abridged
                      | mtp_full
                      | mtp_intermediate
                      | mtp_secure
                      | mtp_noop_codec.
-type layer() :: tls | crypto | packet.

-define(MAX_BUFS_SIZE, 2 * 1024 * 1024).

-record(codec,
        {have_tls :: boolean(),
         tls_state :: mtp_fake_tls:codec() | undefined,
         tls_buf = <<>> :: binary(),
         crypto_mod :: crypto_codec(),
         crypto_state :: any(),
         crypto_buf = <<>> :: binary(),
         packet_mod :: packet_codec(),
         packet_state :: any(),
         packet_buf = <<>> :: binary(),
         limit = ?MAX_BUFS_SIZE :: pos_integer()}).

-define(APP, mtproto_proxy).


-callback try_decode_packet(binary(), state()) ->
    {ok, Packet :: binary(), Tail :: binary(), state()}
        | {incomplete, state()}.

-callback encode_packet(iodata(), state()) ->
    {iodata(), state()}.

-opaque codec() :: #codec{}.

new(CryptoMod, CryptoState, PacketMod, PacketState) ->
    new(CryptoMod, CryptoState, PacketMod, PacketState, false, undefined, ?MAX_BUFS_SIZE).

-spec new(crypto_codec(), state(), packet_codec(), state(), boolean(), any(), pos_integer()) -> codec().
new(CryptoMod, CryptoState, PacketMod, PacketState, UseTls, TlsState, Limit) ->
    #codec{have_tls = UseTls,
           tls_state = TlsState,
           crypto_mod = CryptoMod,
           crypto_state = CryptoState,
           packet_mod = PacketMod,
           packet_state = PacketState,
           limit = Limit}.

-spec replace(layer(), module() | boolean(), any(), codec()) -> codec().
replace(tls, HaveTls, St, #codec{tls_buf = <<>>} = Codec) ->
    Codec#codec{have_tls = HaveTls, tls_state = St};
replace(crypto, Mod, St, #codec{crypto_buf = <<>>} = Codec) ->
    Codec#codec{crypto_mod = Mod, crypto_state = St};
replace(packet, Mod, St, #codec{packet_buf = <<>>} = Codec) ->
    Codec#codec{packet_mod = Mod, packet_state = St}.


-spec info(layer(), codec()) -> {module() | boolean(), state()}.
info(tls, #codec{have_tls = HaveTls, tls_state = TlsState}) ->
    {HaveTls, TlsState};
info(crypto, #codec{crypto_mod = CryptoMod, crypto_state = CryptoState}) ->
    {CryptoMod, CryptoState};
info(packet, #codec{packet_mod = PacketMod, packet_state = PacketState}) ->
    {PacketMod, PacketState}.


%% @doc Push already produced data back to one of codec's input buffers
-spec push_back(layer() | first, binary(), codec()) -> codec().
push_back(tls, Data, #codec{tls_buf = Buf} = Codec) ->
    assert_overflow(Codec#codec{tls_buf = <<Data/binary, Buf/binary>>});
push_back(crypto, Data, #codec{crypto_buf = Buf} = Codec) ->
    assert_overflow(Codec#codec{crypto_buf = <<Data/binary, Buf/binary>>});
push_back(packet, Data, #codec{packet_buf = Buf} = Codec) ->
    assert_overflow(Codec#codec{packet_buf = <<Data/binary, Buf/binary>>});
push_back(first, Data, #codec{have_tls = HaveTls} = Codec) ->
    Destination =
        case HaveTls of
            true -> tls;
            false -> crypto
        end,
    push_back(Destination, Data, Codec).



-spec try_decode_packet(binary(), codec()) -> {ok, binary(), codec()} | {incomplete, codec()}.
try_decode_packet(Bin, S) ->
    decode_tls(Bin, S).

decode_tls(Bin, #codec{have_tls = false} = S) ->
    decode_crypto(Bin, S);
decode_tls(<<>>, #codec{tls_buf = <<>>} = S) ->
    decode_crypto(<<>>, S);
decode_tls(Bin, #codec{tls_state = TlsSt, tls_buf = <<>>} = S) ->
    {DecIolist, Tail, TlsSt1} = mtp_fake_tls:decode_all(Bin, TlsSt),
    decode_crypto(iolist_to_binary(DecIolist), assert_overflow(S#codec{tls_state = TlsSt1, tls_buf = Tail}));
decode_tls(Bin, #codec{tls_buf = Buf} = S) ->
    decode_tls(<<Buf/binary, Bin/binary>>, S#codec{tls_buf = <<>>}).


decode_crypto(<<>>, #codec{crypto_state = CS, crypto_buf = <<>>} = S) ->
    %% There might be smth in packet buffer
    decode_packet(<<>>, CS, <<>>, S);
decode_crypto(Bin, #codec{crypto_mod = CryptoMod,
                          crypto_state = CryptoSt,
                          crypto_buf = <<>>} = S) ->
    case CryptoMod:try_decode_packet(Bin, CryptoSt) of
        {incomplete, CryptoSt1} ->
            decode_packet(<<>>, CryptoSt1, Bin, S);
        {ok, Dec1, Tail1, CryptoSt1} ->
            decode_packet(Dec1, CryptoSt1, Tail1, S)
    end;
decode_crypto(Bin, #codec{crypto_buf = Buf} = S) ->
    decode_crypto(<<Buf/binary, Bin/binary>>, S#codec{crypto_buf = <<>>}).


decode_packet(<<>>, CryptoSt, CryptoTail, #codec{packet_buf = <<>>} = S) ->
    %% Crypto produced nothing and there is nothing in packet buf
    {incomplete, assert_overflow(S#codec{crypto_state = CryptoSt, crypto_buf = CryptoTail})};
decode_packet(Bin, CryptoSt, CryptoTail, #codec{packet_mod = PacketMod,
                                                packet_state = PacketSt,
                                                packet_buf = <<>>} = S) ->
    %% Crypto produced smth, and there is nothing in pkt buf
    case PacketMod:try_decode_packet(Bin, PacketSt) of
        {incomplete, PacketSt1} ->
            {incomplete, assert_overflow(
                           S#codec{crypto_state = CryptoSt,
                                   crypto_buf = CryptoTail,
                                   packet_state = PacketSt1,
                                   packet_buf = Bin
                                  })};
        {ok, Dec2, Tail, PacketSt1} ->
            {ok, Dec2, assert_overflow(
                         S#codec{crypto_state = CryptoSt,
                                 crypto_buf = CryptoTail,
                                 packet_state = PacketSt1,
                                 packet_buf = Tail})}
    end;
decode_packet(Bin, CSt, CTail, #codec{packet_buf = Buf} = S) ->
    decode_packet(<<Buf/binary, Bin/binary>>, CSt, CTail, S#codec{packet_buf = <<>>}).


%% encode_packet(Outer) |> encode_packet(Inner)
-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #codec{have_tls = HaveTls,
                          tls_state = TlsSt,
                          packet_mod = PacketMod,
                          packet_state = PacketSt,
                          crypto_mod = CryptoMod,
                          crypto_state = CryptoSt} = S) ->
    {Enc1, PacketSt1} = PacketMod:encode_packet(Bin, PacketSt),
    {Enc2, CryptoSt1} = CryptoMod:encode_packet(Enc1, CryptoSt),
    case HaveTls of
        false ->
            {Enc2, S#codec{crypto_state = CryptoSt1, packet_state = PacketSt1}};
        true ->
            {Enc3, TlsSt1} = mtp_fake_tls:encode_packet(Enc2, TlsSt),
            {Enc3, S#codec{crypto_state = CryptoSt1, packet_state = PacketSt1, tls_state = TlsSt1}}
    end.


-spec fold_packets(fun( (binary(), FoldSt, codec()) -> {FoldSt, codec()} ),
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

-spec fold_packets_if(fun( (binary(), FoldSt, codec()) -> {next | stop, FoldSt, codec()} ),
                   FoldSt, binary(), codec()) ->
                          {ok, FoldSt, codec()}
                              when
      FoldSt :: any().
fold_packets_if(Fun, FoldSt0, Data, Codec0) ->
    case try_decode_packet(Data, Codec0) of
        {ok, Decoded, Codec1} ->
            case Fun(Decoded, FoldSt0, Codec1) of
                {next, FoldSt1, Codec2} ->
                    fold_packets(Fun, FoldSt1, <<>>, Codec2);
                {stop, FoldSt1, Codec2} ->
                    {ok, FoldSt1, Codec2}
            end;
        {incomplete, Codec1} ->
            {ok, FoldSt0, Codec1}
    end.

-spec is_empty(codec()) -> boolean().
is_empty(#codec{packet_buf = <<>>, crypto_buf = <<>>, tls_buf = <<>>}) -> true;
is_empty(_) -> false.

assert_overflow(#codec{packet_buf = PB, crypto_buf = CB, tls_buf = TB, limit = Limit} = Codec) ->
    Size = byte_size(PB) + byte_size(CB) + byte_size(TB),
    case Size > Limit of
        true ->
            error({protocol_error, max_buffers_size, Size});
        false ->
            Codec
    end.
