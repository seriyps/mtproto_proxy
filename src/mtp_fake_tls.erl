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
         derive_sni_secret/3,
         parse_sni/1,
         tls_decode_error_alert/0,
         new/0,
         try_decode_packet/2,
         decode_all/2,
         encode_packet/2]).
-export([make_client_hello/2,
         make_client_hello/4,
         parse_server_hello/1]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

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
-define(TLS_REC_ALERT, 21).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).

-define(TLS_ALERT_FATAL, 2).
-define(TLS_ALERT_DECODE_ERROR, 50).

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
                  client_digest := binary(),
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
    ?LOG_DEBUG("TLS ClientHello=~p", [CliHlo]),
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
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD],
    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest},
    Meta = case lists:keyfind(?EXT_SNI, 1, Extensions) of
               {_, [{?EXT_SNI_HOST_NAME, Domain}]} ->
                       Meta0#{sni_domain => Domain};
               _ ->
                   Meta0
           end,
    {ok, Response, Meta, new()}.

%% Extract the SNI domain from a raw ClientHello binary without validating the secret.
%% Used for domain fronting: call this when from_client_hello/2 raises tls_invalid_digest,
%% to determine where to forward the connection.
%%
%% Returns {ok, Domain :: binary()} or {error, no_sni | bad_hello}.
-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} ->
                {ok, Domain};
            _ ->
                {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} ->
            {error, bad_hello}
    end.

%% TLS fatal decode_error alert (RFC 8446 §6).
%% Sent to clients whose ClientHello is structurally invalid or lacks an SNI,
%% making the proxy behave like a real TLS server rather than silently dropping.
-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

%% Derive a per-SNI 16-byte secret from the base secret, SNI domain and a salt.
%% Derivation: SHA256(salt || hex32(base_secret) || sni_domain)[0:16]
%%
%% The salt is the sole true secret — keep it private and back it up alongside
%% the base secret. The base_secret is included in the message for instance-specific
%% binding (defense-in-depth if the salt ever leaks).
%%
%% Using hex32(base_secret) rather than raw bytes makes the derivation reproducible
%% with a single SHA-256 call in any language without binary manipulation:
%%   sha256(salt + secret_hex + sni)[0:16]
-spec derive_sni_secret(BaseSecret :: binary(), SniDomain :: binary(), Salt :: binary())
        -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.


parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16, %Frame
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                     %% _/binary>>
                  ) when TlsFrameLen >= 512, HelloLen >= 508 ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = parse_extensions(Extensions)
      };
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

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
    hmac(sha256, Secret, Msg).

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

%% Generate Fake-TLS "ClientHello".
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32,
                                                                byte_size(Secret) == 16 ->
    %% Modern ClientHello following tdesktop b72deb1 + tdlib d0de8a7.
    %% Variable length (no fixed padding); proxy only validates the HMAC in Random.
    GREASE = <<16#ea, 16#ea>>,

    %% Cipher suites: GREASE + 15 standard suites (TLS_RSA_WITH_3DES removed)
    CipherSuites =
        <<GREASE/binary,
          16#13, 16#01,   % TLS_AES_128_GCM_SHA256
          16#13, 16#02,   % TLS_AES_256_GCM_SHA384
          16#13, 16#03,   % TLS_CHACHA20_POLY1305_SHA256
          16#c0, 16#2b,   % ECDHE_ECDSA_AES128_GCM_SHA256
          16#c0, 16#2f,   % ECDHE_RSA_AES128_GCM_SHA256
          16#c0, 16#2c,   % ECDHE_ECDSA_AES256_GCM_SHA384
          16#c0, 16#30,   % ECDHE_RSA_AES256_GCM_SHA384
          16#cc, 16#a9,   % ECDHE_ECDSA_CHACHA20_POLY1305
          16#cc, 16#a8,   % ECDHE_RSA_CHACHA20_POLY1305
          16#c0, 16#13,   % ECDHE_RSA_AES128_CBC_SHA
          16#c0, 16#14,   % ECDHE_RSA_AES256_CBC_SHA
          16#00, 16#9c,   % RSA_AES128_GCM_SHA256
          16#00, 16#9d,   % RSA_AES256_GCM_SHA384
          16#00, 16#2f,   % RSA_AES128_CBC_SHA
          16#00, 16#35>>, % RSA_AES256_CBC_SHA

    SNI = make_sni([SniDomain]),

    SigAlgos =
        <<16#00, 16#0d,   % signature_algorithms
          16#00, 16#20,   % ext length 32 (2 list-len + 30 entries)
          16#00, 16#1e,   % sig-algo list length 30 (15 algos × 2)
          16#04, 16#03,   % ecdsa_secp256r1_sha256
          16#05, 16#03,   % ecdsa_secp384r1_sha384
          16#06, 16#03,   % ecdsa_secp521r1_sha512
          16#02, 16#03,   % ecdsa_sha1
          16#08, 16#04,   % rsa_pss_rsae_sha256
          16#08, 16#05,   % rsa_pss_rsae_sha384
          16#08, 16#06,   % rsa_pss_rsae_sha512
          16#04, 16#01,   % rsa_pkcs1_sha256
          16#05, 16#01,   % rsa_pkcs1_sha384
          16#06, 16#01,   % rsa_pkcs1_sha512
          16#02, 16#01,   % rsa_pkcs1_sha1
          16#04, 16#02,
          16#03, 16#02,
          16#02, 16#02,
          16#03, 16#01>>,

    %% supported_groups: added X25519MLKEM768 (0x11ec), per tdesktop b72deb1
    SupportedGroups =
        <<16#00, 16#0a,   % supported_groups
          16#00, 16#0c,   % ext length 12 (2 list-len + 10 entries)
          16#00, 16#0a,   % named-group list length 10 (5 groups × 2)
          GREASE/binary,  % GREASE named group
          16#11, 16#ec,   % X25519MLKEM768 (new)
          16#00, 16#1d,   % x25519
          16#00, 16#17,   % secp256r1
          16#00, 16#18>>, % secp384r1

    SupportedVersions =
        <<16#00, 16#2b,   % supported_versions
          16#00, 16#07,   % ext length 7 (1 list-len + 6 bytes)
          16#06,          % version list length 6 (3 versions × 2)
          GREASE/binary,  % GREASE version
          16#03, 16#04,   % TLS 1.3
          16#03, 16#03>>, % TLS 1.2 (TG does not offer TLS 1.1 / TLS 1.0)

    %% key_share: GREASE + X25519MLKEM768 (1184+32 bytes) + standalone X25519 (32 bytes)
    %% The proxy and server-side make_key_share/1 will pick the standalone X25519 entry.
    %% ML-KEM-768 public key: 1184 random bytes (proxy does not validate key material)
    MlKem768Key = crypto:strong_rand_bytes(1184),
    KSKey1 = crypto:strong_rand_bytes(32),  % X25519 component of the hybrid entry
    KSKey2 = crypto:strong_rand_bytes(32),  % standalone X25519 key (picked by proxy)
    KeyShareEntries =
        <<GREASE/binary, 16#00, 16#01, 16#00,      % GREASE: group + key_len=1 + 0x00
          16#11, 16#ec, 16#04, 16#c0,               % X25519MLKEM768: group + key_len=1216
          MlKem768Key/binary,                        % ML-KEM-768 public key (1184 bytes)
          KSKey1/binary,                             % X25519 component (32 bytes)
          16#00, 16#1d, 16#00, 16#20,               % x25519: group + key_len=32
          KSKey2/binary>>,                           % standalone X25519 public key
    KSListLen = byte_size(KeyShareEntries),          % 5 + 1220 + 36 = 1261
    KeyShare =
        <<16#00, 16#33,        % key_share
          (KSListLen + 2):?u16, % ext length = list-len field (2) + entries
          KSListLen:?u16,
          KeyShareEntries/binary>>,

    %% Encrypted Client Hello outer (0xfe0d), per tdlib d0de8a7
    %% (previously 0xfe02; the \x00\x20 + 32-byte field was also extended from 20 to 32 bytes)
    EchRand1   = crypto:strong_rand_bytes(1),
    EchRand32  = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(176),       % fixed choice from {144,176,208,240}
    EchContent =
        <<16#00, 16#00, 16#01, 16#00, 16#01,          % fixed ECH outer header
          EchRand1/binary,                             % 1 random byte
          16#00, 16#20,
          EchRand32/binary,                            % 32 random bytes
          (byte_size(EchPayload)):?u16,
          EchPayload/binary>>,
    ECH =
        <<16#fe, 16#0d,                               % ech_outer_extensions (0xfe0d)
          (byte_size(EchContent)):?u16,
          EchContent/binary>>,

    Extensions =
        [<<GREASE/binary, 0:16>>,                     % leading GREASE extension (empty)
         <<16#00, 16#17, 0:16>>,                      % extended_master_secret (empty)
         ECH,                                         % encrypted_client_hello (0xfe0d) — position 3 like TG
         <<16#00, 16#23, 0:16>>,                      % session_ticket (empty)
         <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>, % ec_point_formats: uncompressed
         <<16#44, 16#cd, 16#00, 16#05,                % application_layer_protocol_settings
           16#00, 16#03, 16#02, $h, $2>>,             %   (type updated 0x4469→0x44cd in b72deb1)
         KeyShare,                                    % key_share (0x0033)
         <<16#00, 16#12, 0:16>>,                      % signed_certificate_timestamp (empty)
         SupportedGroups,                             % supported_groups (0x000a)
         <<16#00, 16#1b, 16#00, 16#03,                % compress_certificate
           16#02, 16#00, 16#02>>,                     %   algorithms_len(1)=2, brotli(2)
         <<16#ff, 16#01, 16#00, 16#01, 16#00>>,       % renegotiation_info (empty)
         SigAlgos,                                    % signature_algorithms (0x000d)
         <<16#00, 16#05, 16#00, 16#05,                % status_request (OCSP)
           16#01, 0:32>>,                              %   type=ocsp(1) + empty responder list(2) + empty exts(2)
         <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>, % psk_key_exchange_modes: psk_dhe_ke
         <<16#00, 16#10, 16#00, 16#0e,                % application_layer_protocol_negotiation
           16#00, 16#0c,                               %   protocol list length 12
           16#02, $h, $2,                              %   "h2"
           16#08, $h, $t, $t, $p, $/, $1, $., $1>>,  %   "http/1.1"
         SNI,                                         % server_name (0x0000) — near end like TG
         SupportedVersions,                           % supported_versions (0x002b)
         <<GREASE/binary, 16#00, 16#01, 16#00>>],     % trailing GREASE extension

    ExtBin = iolist_to_binary(Extensions),
    CSLen = byte_size(CipherSuites),
    SessIdLen = byte_size(SessionId),  % always 32
    ExtLen = byte_size(ExtBin),
    %% HelloBodyLen: TLS version(2) + Random(32) + SessIdLen(1) + SessId + CSLen(2) + CS
    %%             + CompMethodsLen(1) + CompMethod(1) + ExtLen(2) + Extensions
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,  % +4 for handshake type(1) + handshake length(3)
    Pack = fun(FakeRandom) ->
                   <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
                     FakeRandom:?DIGEST_LEN/binary,
                     SessIdLen, SessionId/binary,
                     CSLen:?u16, CipherSuites/binary,
                     1, 0,               % 1 compression method: null(0)
                     ExtLen:?u16, ExtBin/binary>>
           end,
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% Parses "ServerHello" (the one produced by from_client_hello/2).
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    %% TLS handshake record: could be proxy ServerHello still arriving in fragments,
    %% or domain forwarding. Wait until all 3 records are fully received.
    case tls_records_complete(B, 3) of
        true  -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) ->
    %% Received a TLS alert: proxy rejected the ClientHello
    {error, tls_alert};
parse_server_hello(_) ->
    %% Unknown content — not an MTProto proxy ServerHello
    {error, not_proxy_response}.

%% Returns true when the binary contains at least N complete TLS records.
-spec tls_records_complete(binary(), non_neg_integer()) -> boolean().
tls_records_complete(_B, 0) ->
    true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) ->
    false.

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

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) ->
    crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) ->
    crypto:hmac(Algo, Key, Str).
-endif.
