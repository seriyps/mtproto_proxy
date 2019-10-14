%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2019, Sergey
%%% @doc
%%% Encoding benchmark for codecs
%%% @end
%%% Created : 15 Sep 2019 by Sergey <me@seriyps.ru>

-module(bench_codec_encode).

-export([fake_tls/1, bench_fake_tls/2,
         intermediate/1, bench_intermediate/2,
         secure/1, bench_secure/2,
         full/1, bench_full/2,
         aes_cbc/1, bench_aes_cbc/2,
         obfuscated/1, bench_obfuscated/2,
         dd_codec/1, bench_dd_codec/2,
         fake_tls_codec/1, bench_fake_tls_codec/2,
         backend_codec/1, bench_backend_codec/2
        ]).


fake_tls({input, _}) ->
    mk_back_packets().

bench_fake_tls(Packets, _) ->
    Codec0 = mtp_fake_tls:new(),
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_fake_tls:encode_packet(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


intermediate({input, _}) ->
    mk_back_packets().

bench_intermediate(Packets, _) ->
    Codec0 = mtp_intermediate:new(),
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_intermediate:encode_packet(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


secure({input, _}) ->
    mk_back_packets().

bench_secure(Packets, _) ->
    Codec0 = mtp_secure:new(),
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_secure:encode_packet(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


full({input, _}) ->
    mk_back_packets().

bench_full(Packets, _) ->
    Codec0 = mtp_full:new(),
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_full:encode_packet(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


aes_cbc(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    BlockSize = 16,
    mtp_aes_cbc:new(Key, IV, Key, IV, BlockSize);
aes_cbc({input, _}) ->
    mk_back_packets().

bench_aes_cbc(Packets, Codec0) ->
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_aes_cbc:encrypt(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


obfuscated(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    mtp_obfuscated:new(Key, IV, Key, IV);
obfuscated({input, _}) ->
    mk_back_packets().

bench_obfuscated(Packets, Codec0) ->
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_obfuscated:encrypt(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).


dd_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    CryptoSt = mtp_obfuscated:new(Key, IV, Key, IV),
    PacketSt = mtp_secure:new(),
    mtp_codec:new(mtp_obfuscated, CryptoSt,
                  mtp_secure, PacketSt);
dd_codec({input, _}) ->
    mk_back_packets().

bench_dd_codec(Packets, Codec) ->
    codec_encode(Packets, Codec).


fake_tls_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    CryptoSt = mtp_obfuscated:new(Key, IV, Key, IV),
    PacketSt = mtp_secure:new(),
    TlsSt = mtp_fake_tls:new(),
    mtp_codec:new(mtp_obfuscated, CryptoSt,
                  mtp_secure, PacketSt,
                  true, TlsSt,
                  10 * 1024 * 1024);
fake_tls_codec({input, _}) ->
    mk_back_packets().

bench_fake_tls_codec(Packets, Codec) ->
    codec_encode(Packets, Codec).


backend_codec(init) ->
    Key = binary:copy(<<0>>, 32),
    IV = binary:copy(<<1>>, 16),
    BlockSize = 16,
    CryptoSt = mtp_aes_cbc:new(Key, IV, Key, IV, BlockSize),
    PacketSt = mtp_full:new(),
    mtp_codec:new(mtp_aes_cbc, CryptoSt,
                  mtp_full, PacketSt);
backend_codec({input, _}) ->
    mk_back_packets().

bench_backend_codec(Packets, Codec) ->
    codec_encode(Packets, Codec).


%%
%% Helpers

mk_back_packets() ->
    %% Histogram from live server shows that majority of Telegram protocol packets from server to
    %% proxy are between 32b to 2kb.
    %% Network (tcp) data chunk size depends on sock buffewr, but is usually distributed
    %% evenly in logarithmic scale: 32b - 128b - 512b - 2kb - 8kb - 33kb
    %% Majority is from 128b to 512b
    Packet = binary:copy(<<0>>, 512),
    lists:duplicate(4, Packet).

codec_encode(Packets, Codec0) ->
    lists:foldl(
      fun(Pkt, Codec1) ->
              {_Enc, Codec2} = mtp_codec:encode_packet(Pkt, Codec1),
              Codec2
      end, Codec0, Packets).
