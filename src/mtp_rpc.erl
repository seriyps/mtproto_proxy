%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto RPC codec
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_rpc).

-export([decode_packet/1,
         decode_nonce/1,
         decode_handshake/1,
         encode_nonce/1,
         encode_handshake/1,
         encode_packet/2]).
%% For tests
-export([srv_decode_packet/1,
         srv_encode_packet/1]).
%% Helpers
-export([inet_pton/1,
         encode_ip_port/2]).
-export_type([codec/0]).

-dialyzer(no_improper_lists).

-record(rpc_st,
        {client_addr :: binary(),
         proxy_addr :: binary(),
         proxy_tag :: binary(),
         conn_id :: integer()}).

-define(APP, mtproto_proxy).
-define(RPC_PROXY_REQ, 238,241,206,54).         %0x36cef1ee
-define(RPC_PROXY_ANS, 13,218,3,68).            %0x4403da0d
-define(RPC_CLOSE_CONN, 93,66,207,31).          %0x1fcf425d
-define(RPC_CLOSE_EXT, 162,52,182,94).          %0x5eb634a2
-define(RPC_SIMPLE_ACK, 155,64,172,59).         %0x3bac409b
-define(TL_PROXY_TAG, 174,38,30,219).

-define(RPC_NONCE, 170,135,203,122).
-define(RPC_HANDSHAKE, 245,238,130,118).
-define(RPC_FLAGS, 0, 0, 0, 0).


-define(FLAG_NOT_ENCRYPTED , 16#2).
-define(FLAG_HAS_AD_TAG    , 16#8).
-define(FLAG_MAGIC         , 16#1000).
-define(FLAG_EXTMODE2      , 16#20000).
-define(FLAG_PAD           , 16#8000000).       %TODO: use it
-define(FLAG_INTERMEDIATE  , 16#20000000).
-define(FLAG_ABRIDGED      , 16#40000000).
-define(FLAG_QUICKACK      , 16#80000000).


-opaque codec() :: #rpc_st{}.
-type conn_id() :: integer().
-type packet() :: {proxy_ans, conn_id(), binary()}
                | {close_ext, conn_id()}
                | {simple_ack, conn_id(), binary()}.

decode_nonce(<<?RPC_NONCE,
               KeySelector:4/binary,
               Schema:32/little,
               CryptoTs:32/little,
               CliNonce:16/binary>>) ->
    {nonce, KeySelector, Schema, CryptoTs, CliNonce}.

decode_handshake(<<?RPC_HANDSHAKE,
                       ?RPC_FLAGS,
                       SenderPID:12/binary,
                       PeerPID:12/binary>>) ->
    {handshake, SenderPID, PeerPID}.

encode_nonce({nonce, KeySelector, Schema, CryptoTs, SrvNonce}) ->
    <<?RPC_NONCE,
      KeySelector:4/binary,
      Schema:32/little,
      CryptoTs:32/little,
      SrvNonce:16/binary>>.

encode_handshake({handshake, SenderPID, PeerPID}) ->
    <<?RPC_HANDSHAKE,
      0, 0, 0, 0,                    %Some flags
      SenderPID:12/binary,
      PeerPID:12/binary>>.

%% It expects that packet segmentation was done on previous layer
%% See mtproto/mtproto-proxy.c:process_client_packet
-spec decode_packet(binary()) -> packet() | error.
decode_packet(<<?RPC_PROXY_ANS, _AnsFlags:4/binary, ConnId:64/signed-little, Data/binary>>) ->
    %% mtproto/mtproto-proxy.c:client_send_message
    {proxy_ans, ConnId, Data};
decode_packet(<<?RPC_CLOSE_EXT, ConnId:64/signed-little>>) ->
    {close_ext, ConnId};
decode_packet(<<?RPC_SIMPLE_ACK, ConnId:64/signed-little, Confirm:4/binary>>) ->
    %% mtproto/mtproto-proxy.c:push_rpc_confirmation
    {simple_ack, ConnId, Confirm}.


encode_packet({data, Msg}, {{ConnId, ClientAddr, ProxyTag}, ProxyAddr}) ->
    %% See mtproto/mtproto-proxy.c:forward_mtproto_packet
    ((iolist_size(Msg) rem 4) == 0)
        orelse error({not_aligned, Msg}),
    Flags1 = (?FLAG_HAS_AD_TAG
                  bor ?FLAG_MAGIC
                  bor ?FLAG_EXTMODE2
                  bor ?FLAG_ABRIDGED),
    %% if (auth_key_id) ...
    Flags = case Msg of
                %% XXX: what if Msg is iolist?
                <<0, 0, 0, 0, 0, 0, 0, 0, _/binary>> ->
                    Flags1 bor ?FLAG_NOT_ENCRYPTED;
                _ ->
                    Flags1
             end,
    [<<?RPC_PROXY_REQ,                          %RPC_PROXY_REQ
       Flags:32/little,                           %int: Flags
       ConnId:64/little-signed>>,                 %long long:
     ClientAddr, ProxyAddr,
     <<24:32/little,                            %int: ExtraSize
       ?TL_PROXY_TAG,                           %int: ProxyTag
       (byte_size(ProxyTag)),                   %tls_string_len()
       ProxyTag/binary,                         %tls_string_data()
       0, 0, 0                                  %tls_pad()
     >>
         | Msg
    ];
encode_packet(remote_closed, ConnId) ->
    <<?RPC_CLOSE_CONN, ConnId:64/little-signed>>.

%%
%% Middle-proxy side encoding and decodong (FOR TESTS ONLY!)
%%

%% opposite of encode_packet
srv_decode_packet(<<?RPC_PROXY_REQ, _Flags:32/little, ConnId:64/little-signed,
                    _ClientAddrBin:20/binary, _ProxyAddrBin:20/binary,
                    24:32/little, ?TL_PROXY_TAG, 16, _ProxyTag:16/binary, 0, 0, 0,
                    Data/binary>>) ->
    {data, ConnId, Data};
srv_decode_packet(<<?RPC_CLOSE_CONN, ConId:64/little-signed>>) ->
    {remote_closed, ConId}.

%% Opposite of decode_packet
srv_encode_packet({proxy_ans, ConnId, Data}) ->
    <<?RPC_PROXY_ANS,
      0, 0, 0, 0,                               %some flags
      ConnId:64/signed-little,
      Data/binary>>;
srv_encode_packet({close_ext, ConnId}) ->
    <<?RPC_CLOSE_EXT, ConnId:64/little-signed>>.

%% IP and port as 10 + 2 + 4 + 4 = 20b
-spec encode_ip_port(inet:ip_address(), inet:port_number()) -> iodata().
encode_ip_port(IPv4, Port) when tuple_size(IPv4) == 4 ->
    IpBin = inet_pton(IPv4),
    [lists:duplicate(10, <<0>>)
     | <<255,255,
         IpBin/binary,
         Port:32/little>>];
encode_ip_port(IPv6, Port) when tuple_size(IPv6) == 8 ->
    IpBin = inet_pton(IPv6),
    [IpBin, <<Port:32/little>>].

inet_pton({X1, X2, X3, X4}) ->
    <<X1, X2, X3, X4>>;
inet_pton(IPv6) when tuple_size(IPv6) == 8 ->
    << <<I:16/big-integer>> || I <- tuple_to_list(IPv6)>>.
    
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

tst_new() ->
    {{1, encode_ip_port({109, 238, 131, 159}, 1128),
      <<220,190,143,20,147,250,76,217,171,48,8,145,192,181,179,38>>},
     encode_ip_port({80, 211, 29, 34}, 53634)}.

decode_none_test() ->
    ?assertError(function_clause, decode_packet(<<>>)).

encode_test() ->
    S = tst_new(),
    Samples =
        [{<<0,0,0,0,0,0,0,0,0,0,0,0,61,2,24,91,20,0,0,0,120,151,70,96,153,197,142,238,245,139,85,208,160,241,68,89,106,7,118,167>>,
          <<238,241,206,54,10,16,2,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255,255,109,238,131,159,104,4,0,0,0,0,0,0,0,0,0,0,0,0,255,255,80,211,29,34,130,209,0,0,24,0,0,0,174,38,30,219,16,220,190,143,20,147,250,76,217,171,48,8,145,192,181,179,38,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,61,2,24,91,20,0,0,0,120,151,70,96,153,197,142,238,245,139,85,208,160,241,68,89,106,7,118,167>>},
         {<<14,146,6,159,99,150,29,221,115,87,68,198,122,39,38,249,153,87,37,105,4,111,147,70,54,179,134,12,90,4,223,155,206,220,167,201,203,176,123,181,103,176,49,216,163,106,54,148,133,51,206,212,81,90,47,26,3,161,149,251,182,90,190,51,213,7,107,176,112,220,25,144,183,249,149,182,172,194,218,146,161,191,247,4,250,123,230,251,41,181,139,177,55,171,253,198,153,183,61,53,119,115,46,174,172,245,90,166,215,99,181,58,236,129,103,80,218,244,81,45,142,128,177,146,26,131,184,155,22,217,218,187,209,155,156,64,219,235,175,40,249,235,77,82,212,73,11,133,52,4,222,157,67,176,251,46,254,241,15,192,215,192,186,82,233,68,147,234,88,250,96,14,172,179,7,159,28,11,237,48,44,33,137,185,166,166,173,103,136,174,31,35,77,151,76,55,176,211,230,176,118,144,139,77,0,213,68,179,73,58,58,80,238,120,197,67,241,210,210,156,72,105,60,125,239,98,7,19,234,249,222,194,166,37,46,100,1,65,225,224,244,57,147,119,49,20,1,160,4,51,247,161,142,11,131,11,27,166,159,110,145,78,55,205,126,246,126,68,44,114,91,191,213,241,242,9,33,16,30,228>>,
          <<238,241,206,54,8,16,2,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255,255,109,238,131,159,104,4,0,0,0,0,0,0,0,0,0,0,0,0,255,255,80,211,29,34,130,209,0,0,24,0,0,0,174,38,30,219,16,220,190,143,20,147,250,76,217,171,48,8,145,192,181,179,38,0,0,0,14,146,6,159,99,150,29,221,115,87,68,198,122,39,38,249,153,87,37,105,4,111,147,70,54,179,134,12,90,4,223,155,206,220,167,201,203,176,123,181,103,176,49,216,163,106,54,148,133,51,206,212,81,90,47,26,3,161,149,251,182,90,190,51,213,7,107,176,112,220,25,144,183,249,149,182,172,194,218,146,161,191,247,4,250,123,230,251,41,181,139,177,55,171,253,198,153,183,61,53,119,115,46,174,172,245,90,166,215,99,181,58,236,129,103,80,218,244,81,45,142,128,177,146,26,131,184,155,22,217,218,187,209,155,156,64,219,235,175,40,249,235,77,82,212,73,11,133,52,4,222,157,67,176,251,46,254,241,15,192,215,192,186,82,233,68,147,234,88,250,96,14,172,179,7,159,28,11,237,48,44,33,137,185,166,166,173,103,136,174,31,35,77,151,76,55,176,211,230,176,118,144,139,77,0,213,68,179,73,58,58,80,238,120,197,67,241,210,210,156,72,105,60,125,239,98,7,19,234,249,222,194,166,37,46,100,1,65,225,224,244,57,147,119,49,20,1,160,4,51,247,161,142,11,131,11,27,166,159,110,145,78,55,205,126,246,126,68,44,114,91,191,213,241,242,9,33,16,30,228>>}],
    lists:foreach(
      fun({In, Out}) ->
              Enc = encode_packet({data, In}, S),
              ?assertEqual(Out, iolist_to_binary(Enc))
      end, Samples).

decode_test() ->
    Samples =
        [{<<13,218,3,68,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,52,62,238,60,2,24,91,64,0,0,0,99,36,22,5,153,197,142,238,245,139,85,208,160,241,68,89,106,7,118,167,146,202,163,241,63,158,32,27,246,203,226,70,177,46,106,225,8,34,202,206,241,19,38,121,245,0,0,0,21,196,181,28,1,0,0,0,33,107,232,108,2,43,180,195>>,
          <<0,0,0,0,0,0,0,0,1,52,62,238,60,2,24,91,64,0,0,0,99,36,22,5,153,197,142,238,245,139,85,208,160,241,68,89,106,7,118,167,146,202,163,241,63,158,32,27,246,203,226,70,177,46,106,225,8,34,202,206,241,19,38,121,245,0,0,0,21,196,181,28,1,0,0,0,33,107,232,108,2,43,180,195>>},
         {<<13,218,3,68,0,0,0,0,2,0,0,0,0,0,0,0,14,146,6,159,99,150,29,221,85,233,237,52,236,18,11,0,174,214,89,213,69,89,250,18,116,192,128,240,217,221,210,144,123,9,182,152,60,206,88,187,101,178,53,107,44,98,190,195,149,114,0,19,90,218,101,133,183,249,183,170,90,21,86,24,42,81,224,152,13,58,90,84,41,158,177,99,57,83,123,99,138,127,29,238,162,49,71,65,165,168,218,220,245,202,24,135,152,1,28,38,85,197,8,232,201,163,65,118,202,89,204,67,48,21,51,106,188,7,167,61,185,82,39,210,164,21,97,99,63,167,2,143,69,126,214,75,95,142,69,68,243,49,11,121,28,177,159,0,154,134,206,34>>,
          <<14,146,6,159,99,150,29,221,85,233,237,52,236,18,11,0,174,214,89,213,69,89,250,18,116,192,128,240,217,221,210,144,123,9,182,152,60,206,88,187,101,178,53,107,44,98,190,195,149,114,0,19,90,218,101,133,183,249,183,170,90,21,86,24,42,81,224,152,13,58,90,84,41,158,177,99,57,83,123,99,138,127,29,238,162,49,71,65,165,168,218,220,245,202,24,135,152,1,28,38,85,197,8,232,201,163,65,118,202,89,204,67,48,21,51,106,188,7,167,61,185,82,39,210,164,21,97,99,63,167,2,143,69,126,214,75,95,142,69,68,243,49,11,121,28,177,159,0,154,134,206,34>>}],
    lists:foreach(
      fun({In, Out}) ->
              {proxy_ans, _ConnId, Packet} = decode_packet(In),
              ?assertEqual(Out, iolist_to_binary(Packet))
      end, Samples).

%% decode_close_test() ->
%%     S = tst_new(),
%%     In = <<>>,
%%     ?assertError(rpc_close, try_decode_packet(In, S)).

-endif.
