%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2019, Sergey
%%% @doc
%%% Decoding benchmarks for codecs
%%% @end
%%% Created :  7 Sep 2019 by Sergey <me@seriyps.ru>

-module(bench_codec_decode).

-export([fake_tls/1, bench_fake_tls/2,
         intermediate/1, bench_intermediate/2,
         secure/1, bench_secure/2,
         full/1, bench_full/2,
         full_nocheck/1, bench_full_nocheck/2,
         aes_cbc/1, bench_aes_cbc/2,
         obfuscated/1, bench_obfuscated/2,
         fold_dd_codec/1, bench_fold_dd_codec/2,
         fold_tls_codec/1, bench_fold_tls_codec/2,
         fold_backend_codec/1, bench_fold_backend_codec/2]).


%% @doc bench mtp_fake_tls decoding
fake_tls(init) ->
    mtp_fake_tls:new();
fake_tls({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_fake_tls, Codec).

bench_fake_tls(Stream, Codec) ->
    mtp_fake_tls:decode_all(Stream, Codec).


%% @doc bench mtp_intermediate decoding
intermediate(init) ->
    mtp_intermediate:new();
intermediate({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_intermediate, Codec).

bench_intermediate(Stream, Codec) ->
    decode_all_intermediate(Stream, Codec).

decode_all_intermediate(Stream0, Codec0) ->
    case mtp_intermediate:try_decode_packet(Stream0, Codec0) of
        {ok, Pkt, Stream1, Codec1} ->
            [Pkt | decode_all_intermediate(Stream1, Codec1)];
        {incomplete, _} ->
            []
    end.


%% @doc bench mtp_secure decoding
secure(init) ->
    mtp_secure:new();
secure({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_secure, Codec).

bench_secure(Stream, Codec) ->
    decode_all_secure(Stream, Codec).

decode_all_secure(Stream0, Codec0) ->
    case mtp_secure:try_decode_packet(Stream0, Codec0) of
        {ok, Pkt, Stream1, Codec1} ->
            [Pkt | decode_all_secure(Stream1, Codec1)];
        {incomplete, _} ->
            []
    end.


%% @doc bench mtp_full decoding
full(init) ->
    mtp_full:new();
full({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_full, Codec).

bench_full(Stream, Codec) ->
    decode_all_full(Stream, Codec).

decode_all_full(Stream0, Codec0) ->
    case mtp_full:try_decode_packet(Stream0, Codec0) of
        {ok, Pkt, Stream1, Codec1} ->
            [Pkt | decode_all_full(Stream1, Codec1)];
        {incomplete, _} ->
            []
    end.


%% @doc bench mtp_full with disabled CRC32 verification check
full_nocheck(init) ->
    mtp_full:new(0, 0, false);
full_nocheck({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_full, Codec).

bench_full_nocheck(Stream, Codec) ->
    decode_all_full(Stream, Codec).


%% @doc bench aes_cbc decryption
aes_cbc(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    BlockSize = 16,
    mtp_aes_cbc:new(Key, IV, Key, IV, BlockSize);
aes_cbc({input, Codec}) ->
    Packets = mk_front_packets(),
    {Stream, _} = mtp_aes_cbc:encrypt(Packets, Codec),
    Stream.

bench_aes_cbc(Stream, Codec) ->
    {Dec, <<>>, _} = mtp_aes_cbc:decrypt(Stream, Codec),
    Dec.


%% @doc decrypt mtp_obfuscated
obfuscated(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    mtp_obfuscated:new(Key, IV, Key, IV);
obfuscated({input, Codec}) ->
    Packets = mk_front_packets(),
    {Stream, _} = mtp_obfuscated:encrypt(Packets, Codec),
    Stream.

bench_obfuscated(Stream, Codec) ->
    {Dec, <<>>, _} = mtp_obfuscated:decrypt(Stream, Codec),
    Dec.

%% @doc "codec" that is used for "dd" secrets
fold_dd_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    CryptoSt = mtp_obfuscated:new(Key, IV, Key, IV),
    PacketSt = mtp_secure:new(),
    mtp_codec:new(mtp_obfuscated, CryptoSt,
                  mtp_secure, PacketSt);
fold_dd_codec({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_codec, Codec).

bench_fold_dd_codec(Stream, Codec) ->
    codec_fold(Stream, Codec).


%% @doc "codec" that is used for "fake-tls" connections
fold_tls_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    CryptoSt = mtp_obfuscated:new(Key, IV, Key, IV),
    PacketSt = mtp_secure:new(),
    TlsSt = mtp_fake_tls:new(),
    mtp_codec:new(mtp_obfuscated, CryptoSt,
                  mtp_secure, PacketSt,
                  true, TlsSt,
                  10 * 1024 * 1024);
fold_tls_codec({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_codec, Codec).

bench_fold_tls_codec(Stream, Codec) ->
    codec_fold(Stream, Codec).


%% @doc codec that is used for connections to telegram datacenter
fold_backend_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    BlockSize = 16,
    CryptoSt = mtp_aes_cbc:new(Key, IV, Key, IV, BlockSize),
    PacketSt = mtp_full:new(),
    mtp_codec:new(mtp_aes_cbc, CryptoSt,
                  mtp_full, PacketSt);
fold_backend_codec({input, Codec}) ->
    Packets = mk_front_packets(),
    encode_all(Packets, mtp_codec, Codec).

bench_fold_backend_codec(Stream, Codec) ->
    codec_fold(Stream, Codec).


%%
%% Helpers

mk_front_packets() ->
    %% Histogram from live server shows that majority of Telegram protocol packets from client to
    %% proxy are between 128 to 512 bytes.
    %% Network (tcp) data chunk size depends on sock buffewr, but is usually between 128b to 2kb.
    Packet = binary:copy(<<0>>, 256),
    lists:duplicate(8, Packet).

encode_all(Pkts, Codec, St0) ->
    {Stream, _} =
        lists:foldl(
          fun(Pkt, {Acc, St}) ->
                  {Enc, St1} = Codec:encode_packet(Pkt, St),
                  {<<Acc/binary, (iolist_to_binary(Enc))/binary>>, St1}
          end, {<<>>, St0}, Pkts),
    Stream.

codec_fold(Stream, Codec) ->
    mtp_codec:fold_packets(
      fun(Pkt, Acc, Codec1) ->
              {[Pkt | Acc], Codec1}
      end, [], Stream, Codec).
