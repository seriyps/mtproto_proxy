%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto proxy encryption and packet layer; "obfuscated2" protocol lib
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>

-module(mtp_obfuscated).
-behaviour(mtp_layer).
-export([create/0,
         create/1,
         from_header/2,
         new/4,
         encrypt/2,
         decrypt/2,
         try_decode_packet/2,
         encode_packet/2
        ]).
-export([bin_rev/1]).

-export_type([codec/0]).

-record(st,
        {encrypt :: any(),                      % aes state
         decrypt :: any()                       % aes state
        }).

-define(APP, mtproto_proxy).

-opaque codec() :: #st{}.

%% @doc Creates new obfuscated stream (usual format)
-spec create() -> {ok, Header :: binary(), codec()}.
create() ->
    create(crypto:strong_rand_bytes(60)).

-spec create(binary()) -> {ok, Header :: binary(), codec()}.
create(<<Left:56/binary, Right:4/binary>>) ->
    DownHeader = <<Left/binary,
                   16#ef, 16#ef, 16#ef, 16#ef,
                   Right/binary>>,
    new2(DownHeader).

new2(<<Left:56/binary, _/binary>> = DownHeader) ->
    {EncKey, EncIV} = init_down_encrypt(DownHeader),
    {DecKey, DecIV} = init_down_decrypt(DownHeader),
    St = new(EncKey, EncIV, DecKey, DecIV),
    {<<_:56/binary, Rep:8/binary, _/binary>>, St1} = encrypt(DownHeader, St),
    {ok,
     <<Left/binary, Rep/binary>>,
     St1}.

init_down_decrypt(<<_:8/binary, ToRev:48/binary, _/binary>>) ->
    Reversed = bin_rev(ToRev),
    <<KeyRev:32/binary, RevIV:16/binary>> = Reversed,
    {KeyRev, RevIV}.

init_down_encrypt(<<_:8/binary, Key:32/binary, IV:16/binary, _/binary>>) ->
    {Key, IV}.


%% @doc creates new obfuscated stream (MTProto proxy format)
-spec from_header(binary(), binary()) -> {ok, inet:ip4_address(), codec()}.
from_header(Header, Secret) when byte_size(Header) == 64  ->
    {EncKey, EncIV} = init_up_encrypt(Header, Secret),
    {DecKey, DecIV} = init_up_decrypt(Header, Secret),
    St = new(EncKey, EncIV, DecKey, DecIV),
    {<<_:56/binary, Bin1:8/binary, _/binary>>, St1} = decrypt(Header, St),
    <<HeaderPart:56/binary, _/binary>> = Header,
    NewHeader = <<HeaderPart/binary, Bin1/binary>>,
    case NewHeader of
        <<_:56/binary, 16#ef, 16#ef, 16#ef, 16#ef, _/binary>> ->
            DcId = get_dc(NewHeader),
            {ok, DcId, St1};
        <<_:56/binary, 16#ee, 16#ee, 16#ee, 16#ee, _/binary>> ->
            metric:count_inc([?APP, protocol_error, total], 1, #{labels => [intermediate]}),
            {error, {protocol_not_supported, intermediate}};
        _ ->
            metric:count_inc([?APP, protocol_error, total], 1, #{labels => [unknown]}),
            {error, unknown_protocol}
    end.

init_up_encrypt(Bin, Secret) ->
    <<_:8/binary, ToRev:48/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeyRev:32/binary, RevIV:16/binary, _/binary>> = Rev,
    %% <<_:32/binary, RevIV:16/binary, _/binary>> = Bin,
    KeyRevHash = crypto:hash('sha256', <<KeyRev/binary, Secret/binary>>),
    {KeyRevHash, RevIV}.

init_up_decrypt(Bin, Secret) ->
    <<_:8/binary, Key:32/binary, IV:16/binary, _/binary>> = Bin,
    KeyHash = crypto:hash('sha256', <<Key/binary, Secret/binary>>),
    {KeyHash, IV}.

get_dc(<<_:60/binary, DcId:16/signed-little-integer, _/binary>>) ->
    DcId.


new(EncKey, EncIV, DecKey, DecIV) ->
    #st{decrypt = crypto:stream_init('aes_ctr', DecKey, DecIV),
        encrypt = crypto:stream_init('aes_ctr', EncKey, EncIV)}.

-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto:stream_encrypt(Enc, Data),
    {Encrypted, St#st{encrypt = Enc1}}.

-spec decrypt(iodata(), codec()) -> {binary(), codec()}.
decrypt(Encrypted, #st{decrypt = Dec} = St) ->
    {Dec1, Data} = crypto:stream_encrypt(Dec, Encrypted),
    {Data, St#st{decrypt = Dec1}}.

%% To comply with mtp_layer interface
-spec try_decode_packet(iodata(), codec()) -> {ok, Decoded :: binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(Encrypted, St) ->
    {Decrypted, St1} = decrypt(Encrypted, St),
    {ok, Decrypted, St1}.

-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, S) ->
    encrypt(Msg, S).


%% Helpers
bin_rev(Bin) ->
    %% binary:encode_unsigned(binary:decode_unsigned(Bin, little)).
    list_to_binary(lists:reverse(binary_to_list(Bin))).
