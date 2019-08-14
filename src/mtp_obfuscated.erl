%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto proxy encryption and packet layer; "obfuscated2" protocol lib
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>

-module(mtp_obfuscated).
-behaviour(mtp_codec).
-export([from_header/2,
         new/4,
         encrypt/2,
         decrypt/2,
         try_decode_packet/2,
         encode_packet/2
        ]).
-export([bin_rev/1]).
-ifdef(TEST).
-export([client_create/3,
         client_create/4]).
-endif.

-export_type([codec/0]).

-record(st,
        {encrypt :: any(),                      % aes state
         decrypt :: any()                       % aes state
        }).

-define(APP, mtproto_proxy).

-define(KEY_LEN, 32).
-define(IV_LEN, 16).

-opaque codec() :: #st{}.

-ifdef(TEST).
client_create(Secret, Protocol, DcId) ->
    client_create(crypto:strong_rand_bytes(58),
                  Secret, Protocol, DcId).

-spec client_create(binary(), binary(), mtp_codec:packet_codec(), integer()) ->
                           {Packet,
                            {EncKey, EncIv},
                            {DecKey, DecIv},
                            CliCodec} when
      Packet :: binary(),
      EncKey :: binary(),
      EncIv :: binary(),
      DecKey :: binary(),
      DecIv :: binary(),
      CliCodec :: codec().
client_create(Seed, HexSecret, Protocol, DcId) when byte_size(HexSecret) == 32 ->
    client_create(Seed, mtp_handler:unhex(HexSecret), Protocol, DcId);
client_create(Seed, Secret, Protocol, DcId) when byte_size(Seed) == 58,
                                          byte_size(Secret) == 16,
                                          DcId > -10,
                                          DcId < 10,
                                          is_atom(Protocol) ->
    <<L:56/binary, R:2/binary>> = Seed,
    ProtocolBin = encode_protocol(Protocol),
    DcIdBin = encode_dc_id(DcId),
    Raw = <<L:56/binary, ProtocolBin:4/binary, DcIdBin:2/binary, R:2/binary>>,

    %% init_up_encrypt/2
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Raw,
    <<DecKeySeed:?KEY_LEN/binary, DecIv:?IV_LEN/binary>> = bin_rev(ToRev),
    DecKey = crypto:hash('sha256', <<DecKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    %% init_up_decrypt/2
    <<_:8/binary, EncKeySeed:?KEY_LEN/binary, EncIv:?IV_LEN/binary, _/binary>> = Raw,
    EncKey = crypto:hash('sha256', <<EncKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    Codec = new(EncKey, EncIv, DecKey, DecIv),
    {<<_:56/binary, Encrypted:8/binary>>, Codec1} = encrypt(Raw, Codec),
    <<RawL:56/binary, _:8/binary>> = Raw,
    Packet = <<RawL:56/binary, Encrypted:8/binary>>,
    {Packet,
     {EncKey, EncIv},
     {DecKey, DecIv},
     Codec1}.


%% 4byte
encode_protocol(mtp_abridged) ->
    <<16#ef, 16#ef, 16#ef, 16#ef>>;
encode_protocol(mtp_intermediate) ->
    <<16#ee, 16#ee, 16#ee, 16#ee>>;
encode_protocol(mtp_secure) ->
    <<16#dd, 16#dd, 16#dd, 16#dd>>.

%% 4byte
encode_dc_id(DcId) ->
    <<DcId:16/signed-little-integer>>.
-endif.

%% @doc creates new obfuscated stream (MTProto proxy format)
-spec from_header(binary(), binary()) -> {ok, integer(), mtp_codec:packet_codec(), codec()}
                                             | {error, unknown_protocol}.
from_header(Header, Secret) when byte_size(Header) == 64  ->
    %% 1) Encryption key
    %%     [--- _: 8b ----|---------- b: 48b -------------|-- _: 8b --] = header: 64b
    %% b_r: 48b = reverse([---------- b ------------------])
    %%                    [-- key_seed: 32b --|- iv: 16b -] = b_r
    %% key: 32b = sha256( [-- key_seed: 32b --|-- secret: 32b --] )
    %% iv: 16b = iv
    %%
    %% 2) Decryption key
    %%      [--- _: 8b ---|-- key_seed: 32b --|- iv: 16b -|-- _: 8b --] = header
    %% key: 32b = sha256( [-- key_seed: 32b --|-- secret: 32b --] )
    %% ib: 16b = ib
    %%
    %% 3) Protocol and datacenter
    %% decrypted_header: 64b = decrypt(header)
    %%      [-------------- _a: 56b ----|-------- b: 6b ---------|- _: 2b -] = decrypted_header
    %%                                  [- proto: 4b -|- dc: 2b -]
    {EncKey, EncIV} = init_up_encrypt(Header, Secret),
    {DecKey, DecIV} = init_up_decrypt(Header, Secret),
    St = new(EncKey, EncIV, DecKey, DecIV),
    {<<_:56/binary, Bin1:6/binary, _:2/binary>>, <<>>, St1} = decrypt(Header, St),
    case get_protocol(Bin1) of
        {error, unknown_protocol} = Err ->
            Err;
        Protocol ->
            DcId = get_dc(Bin1),
            {ok, DcId, Protocol, St1}
    end.

init_up_encrypt(Bin, Secret) ->
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary>> = Rev,
    %% <<_:32/binary, RevIV:16/binary, _/binary>> = Bin,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

init_up_decrypt(Bin, Secret) ->
    <<_:8/binary, KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary, _/binary>> = Bin,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

get_protocol(<<16#ef, 16#ef, 16#ef, 16#ef, _:2/binary>>) ->
    mtp_abridged;
get_protocol(<<16#ee, 16#ee, 16#ee, 16#ee, _:2/binary>>) ->
    mtp_intermediate;
get_protocol(<<16#dd, 16#dd, 16#dd, 16#dd, _:2/binary>>) ->
    mtp_secure;
get_protocol(_) ->
    {error, unknown_protocol}.

get_dc(<<_:4/binary, DcId:16/signed-little-integer>>) ->
    DcId.


new(EncKey, EncIV, DecKey, DecIV) ->
    #st{decrypt = crypto:stream_init('aes_ctr', DecKey, DecIV),
        encrypt = crypto:stream_init('aes_ctr', EncKey, EncIV)}.

-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto:stream_encrypt(Enc, Data),
    {Encrypted, St#st{encrypt = Enc1}}.

-spec decrypt(iodata(), codec()) -> {binary(), binary(), codec()}.
decrypt(Encrypted, #st{decrypt = Dec} = St) ->
    {Dec1, Data} = crypto:stream_encrypt(Dec, Encrypted),
    {Data, <<>>, St#st{decrypt = Dec1}}.

-spec try_decode_packet(iodata(), codec()) -> {ok, Decoded :: binary(), Tail :: binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(Encrypted, St) ->
    {Decrypted, Tail, St1} = decrypt(Encrypted, St),
    {ok, Decrypted, Tail, St1}.

-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, S) ->
    encrypt(Msg, S).


%% Helpers
bin_rev(Bin) ->
    %% binary:encode_unsigned(binary:decode_unsigned(Bin, little)).
    list_to_binary(lists:reverse(binary_to_list(Bin))).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

client_server_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, _CliCodec} = client_create(Secret, Protocol, DcId),
    Srv = from_header(Packet, Secret),
    ?assertMatch({ok, DcId, Protocol, _}, Srv).

-endif.
