%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% https://github.com/telegramdesktop/tdesktop/commit/69b6b487382c12efc43d52f472cab5954ab850e2
%%% It's not real TLS, but it looks like TLS1.3 from outside
%%% @end
%%% Created : 24 Jul 2019 by sergey <me@seriyps.ru>

-module(mtp_fake_tls).

-behaviour(mtp_codec).

-export([format_secret_base64/2,
         format_secret_hex/2]).
-export([from_client_hello/2,
         new/0,
         try_decode_packet/2,
         decode_all/2,
         encode_packet/2]).
-ifdef(TEST).
-export([make_client_hello/2,
         make_client_hello/4,
         parse_server_hello/1]).
-endif.

-export_type([codec/0, meta/0]).

-include_lib("hut/include/hut.hrl").

-dialyzer(no_improper_lists).

-record(st, {}).

-record(client_hello,
        {pseudorandom :: binary(),
         session_id :: binary(),
         cipher_suites :: list(),
         compression_methods :: list(),
         extensions :: [{non_neg_integer(), any()}]
        }).

-define(u16, 16/unsigned-big).
-define(u24, 24/unsigned-big).

-define(MAX_IN_PACKET_SIZE, 65535).      % sizeof(uint16) - 1
-define(MAX_OUT_PACKET_SIZE, 16384).     % 2^14 https://tools.ietf.org/html/rfc8446#section-5.1

-define(TLS_10_VERSION, 3, 1).
-define(TLS_12_VERSION, 3, 3).
-define(TLS_13_VERSION, 3, 4).
-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_CIPHERSUITE, 192, 47).
-define(TLS_CHANGE_CIPHER, ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).

-define(EXT_KEY_SHARE, 51).

-define(EXT_SUPPORTED_VERSIONS, 43).

-define(APP, mtproto_proxy).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  sni_domain => binary()}.


%% @doc format TLS secret
format_secret_hex(Secret, Domain) when byte_size(Secret) == 16 ->
    mtp_handler:hex(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_hex(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_hex(mtp_handler:unhex(HexSecret), Domain).

-spec format_secret_base64(binary(), binary()) -> binary().
format_secret_base64(Secret, Domain) when byte_size(Secret) == 16 ->
    base64url(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_base64(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_base64(mtp_handler:unhex(HexSecret), Domain).

base64url(Bin) ->
    %% see https://hex.pm/packages/base64url
    << << (urlencode_digit(D)) >> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

%% Parse fake-TLS "ClientHello" packet and generate "ServerHello + ChangeCipher + ApplicationData"
-spec from_client_hello(binary(), binary()) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    #client_hello{pseudorandom = ClientDigest,
                  session_id = SessionId,
                  extensions = Extensions} = CliHlo = parse_client_hello(Data),
    ?log(debug, "TLS ClientHello=~p", [CliHlo]),
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),
    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),
    Response0 = [_, CC, DD] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData)],
    SrvHelloDigest = crypto:hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD],
    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp},
    Meta = case lists:keyfind(?EXT_SNI, 1, Extensions) of
               {_, [{?EXT_SNI_HOST_NAME, Domain}]} ->
                       Meta0#{sni_domain => Domain};
               _ ->
                   Meta0
           end,
    {ok, Response, Meta, new()}.


parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, 512:?u16, %Frame
                     ?TLS_TAG_CLI_HELLO, 508:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                     %% _/binary>>
                  ) ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = parse_extensions(Extensions)
      }.

parse_suites(Bin) ->
    [Suite || <<Suite:?u16>> <= Bin].

parse_compression(Bin) ->
    [Bin].                                      %TODO: just binary_to_list(Bin)

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value}
     || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key}
     || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(_Type, Data) ->
    Data.


make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    crypto:hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares =
                lists:dropwhile(
                  fun({Group, Key}) ->
                          not (
                            byte_size(Key) < 128
                            andalso
                            lists:member(       % https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4
                              Group, [% secp256r1
                                      16#0017,
                                      % secp384r1
                                      16#0018,
                                      % secp521r1
                                      16#0019,
                                      % x25519
                                      16#001D,
                                      % x448
                                      16#001E,
                                      % ffdhe2048
                                      16#0100,
                                      % ffdhe3072
                                      16#0101,
                                      % ffdhe4096
                                      16#0102,
                                      % ffdhe6144
                                      16#0103,
                                      % ffdhe8192
                                      16#0104])
                           )
                  end, KeyShares),
            case SupportedKeyShares of
                [] ->
                    error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] ->
                    {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ ->
            error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}) ->
    %% https://tools.ietf.org/html/rfc8446#section-4.1.3
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    Extensions =
        [<<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
         KeyShareEntity,
         <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>],
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize,
                 SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,                              % Compression method
                 (iolist_size(Extensions)):?u16>>
                   | Extensions],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

-ifdef(TEST).
%% Generate Fake-TLS "ClientHello". Used for tests only.
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32,
                                                                byte_size(Secret) == 16 ->
    %% Wireshark capture from Telegram Desktop
    CipherSuites =
        mtp_handler:unhex(<<"eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a">>),
    CSLen = byte_size(CipherSuites),

    SNI = make_sni([SniDomain]),
    %% Wireshark capture from Telegram Desktop
    KeyShare =
        mtp_handler:unhex(
          <<"0033002b00295a5a000100001d0020a4146c3e8573565bb5f5c877a88a98dcbbd46a9b3ca1ab3df7217cc33b4b6d2c">>),
    SupportedVersions =
        mtp_handler:unhex(<<"002b000b0a1a1a0304030303020301">>),
    ExtLen = 401,                               % From wireshark
    RealExtensions = <<KeyShare/binary, SupportedVersions/binary, SNI/binary>>,
    Extensions = add_padding_ext(RealExtensions, ExtLen),
    (ExtLen == byte_size(Extensions)) orelse error({bad_ext_len, byte_size(Extensions)}),

    SessIdLen = byte_size(SessionId),
    Pack = fun(FakeRandom) ->
                   <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, 512:?u16,
                     ?TLS_TAG_CLI_HELLO, 508:?u24, ?TLS_12_VERSION,
                     FakeRandom:?DIGEST_LEN/binary,
                     SessIdLen, SessionId:SessIdLen/binary,
                     CSLen:?u16, CipherSuites:CSLen/binary,
                     1, 0,                                        %Compression methods
                     ExtLen:?u16, Extensions:ExtLen/binary>>
           end,
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = crypto:hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

add_padding_ext(RealExtensions, ExtLen) ->
    RealExtLen = byte_size(RealExtensions),
    PadSize = ExtLen - RealExtLen - 4,
    PaddingExt = <<21:?u16,                          %EXT_PADDING
                   PadSize:?u16,
                   (binary:copy(<<0>>, PadSize))/binary>>,
    <<RealExtensions/binary, PaddingExt/binary>>.

%% Parses "ServerHello" (the one produced by from_client_hello/2). Used for tests only.
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < (512 + 5) ->
    incomplete.

-endif.

%% Data stream codec

-spec new() -> codec().
new() ->
    #st{}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    %% "Change cipher" are ignored
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->  % 5 is ?TLS_12_DATA + Size:16 size
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

%% @doc decodes as much TLS packets as possible to single binary
-spec decode_all(binary(), codec()) -> {Decoded :: binary(), Tail :: binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.


-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    {encode_as_frames(Bin), St}.

encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    as_tls_data_frame(Bin);
encode_as_frames(<<Chunk:?MAX_OUT_PACKET_SIZE/binary, Tail/binary>>) ->
    [as_tls_data_frame(Chunk) | encode_as_frames(Tail)].

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].
