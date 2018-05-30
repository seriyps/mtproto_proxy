%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto proxy encryption and packet layer; "obfuscated2" protocol lib
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>

-module(mtp_obfuscated).
-export([new/0,
         new/1,
         from_header/2,
         encrypt/2,
         decrypt/2]).

-export_type([codec/0]).

-record(st,
        {encrypt :: any(),                      % aes state
         decrypt :: any()                       % aes state
        }).

-define(ENDPOINTS, {
          {149, 154, 175, 50},
          {149, 154, 167, 51},
          {149, 154, 175, 100},
          {149, 154, 167, 91},
          {149, 154, 171, 5}
         }).
-define(APP, mtproto_proxy).
%% -define(DBG(Fmt, Args), io:format(user, Fmt, Args)).
-define(DBG(_F, _A), ok).

-opaque codec() :: #st{}.

%% @doc Creates new obfuscated stream (usual format)
-spec new() -> {ok, Header :: binary(), codec()}.
new() ->
    new(crypto:strong_rand_bytes(60)).

-spec new(binary()) -> {ok, Header :: binary(), codec()}.
new(<<Left:56/binary, Right:4/binary>>) ->
    DownHeader = <<Left/binary,
                   16#ef, 16#ef, 16#ef, 16#ef,
                   Right/binary>>,
    new2(DownHeader).

new2(<<Left:56/binary, _/binary>> = DownHeader) ->
    Encrypt = init_down_encrypt(DownHeader),
    Decrypt = init_down_decrypt(DownHeader),
    St = #st{decrypt = Decrypt,
             encrypt = Encrypt},
    {<<_:56/binary, Rep:8/binary, _/binary>>, St1} = encrypt(DownHeader, St),
    {ok,
     <<Left/binary, Rep/binary>>,
     St1}.

init_down_decrypt(<<_:8/binary, ToRev:48/binary, _/binary>>) ->
    Reversed = bin_rev(ToRev),
    <<KeyRev:32/binary, RevIV:16/binary>> = Reversed,
    ?DBG("down-DEC Key: ~w;~nIV: ~w~n", [KeyRev, RevIV]),
    crypto:stream_init('aes_ctr', KeyRev, RevIV).

init_down_encrypt(<<_:8/binary, Key:32/binary, IV:16/binary, _/binary>>) ->
    ?DBG("down-ENC Key: ~w;~nIV: ~w~n", [Key, IV]),
    crypto:stream_init('aes_ctr', Key, IV).


%% @doc creates new obfuscated stream (MTProto proxy format)
-spec from_header(binary(), binary()) -> {ok, inet:ip4_address(), codec()}.
from_header(Header, Secret) when byte_size(Header) == 64  ->
    Encrypt = init_up_encrypt(Header, Secret),
    Decrypt = init_up_decrypt(Header, Secret),
    {Decrypt1, <<_:56/binary, Bin1:8/binary, _/binary>>} = crypto:stream_encrypt(Decrypt, Header),
    <<HeaderPart:56/binary, _/binary>> = Header,
    NewHeader = <<HeaderPart/binary, Bin1/binary>>,
    case NewHeader of
        <<_:56/binary, 16#ef, 16#ef, 16#ef, 16#ef, _/binary>> ->
            Endpoint = get_endpoint(NewHeader),
            {ok, Endpoint, #st{decrypt = Decrypt1,
                               encrypt = Encrypt}};
        <<_:56/binary, 16#ee, 16#ee, 16#ee, 16#ee, _/binary>> ->
            {error, {protocol_not_supported, intermediate}};
        _ ->
            {error, unknown_protocol}
    end.

init_up_encrypt(Bin, Secret) ->
    <<_:8/binary, ToRev:48/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeyRev:32/binary, RevIV:16/binary, _/binary>> = Rev,
    %% <<_:32/binary, RevIV:16/binary, _/binary>> = Bin,
    KeyRevHash = crypto:hash('sha256', <<KeyRev/binary, Secret/binary>>),
    ?DBG("up-ENC Key: ~p;~nIV: ~p~n", [KeyRevHash, RevIV]),
    crypto:stream_init('aes_ctr', KeyRevHash, RevIV).

init_up_decrypt(Bin, Secret) ->
    <<_:8/binary, Key:32/binary, _/binary>> = Bin,
    <<_:40/binary, IV:16/binary, _/binary>> = Bin,
    KeyHash = crypto:hash('sha256', <<Key/binary, Secret/binary>>),
    ?DBG("up-DEC Key: ~p;~nIV: ~p~n", [KeyHash, IV]),
    crypto:stream_init('aes_ctr', KeyHash, IV).

get_endpoint(<<_:60/binary, DcId:16/signed-little-integer, _/binary>>) ->
    element(abs(DcId), ?ENDPOINTS).

encrypt(Data, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto:stream_encrypt(Enc, Data),
    ?DBG("encrypt: IN:~p~nOUT:~p~n", [Data, Encrypted]),
    {Encrypted, St#st{encrypt = Enc1}}.

decrypt(Encrypted, #st{decrypt = Dec} = St) ->
    {Dec1, Data} = crypto:stream_encrypt(Dec, Encrypted),
    ?DBG("decrypt: IN:~p~nOUT:~p~n", [Encrypted, Data]),
    {Data, St#st{decrypt = Dec1}}.


%% Helpers
bin_rev(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).
