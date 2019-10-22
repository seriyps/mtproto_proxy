%% @doc Simple mtproto proxy client
-module(mtp_test_client).

-export([connect/5,
         connect/6,
         send/2,
         recv_packet/2,
         recv_all/2,
         close/1,
         ping_session/6]).

-export([unencrypted_cli_packet/1,
         unencrypted_cli_packet/3,
         parse_unencrypted_srv_packet/1]).
-export([req_pq/0,
         res_pq_matches/2,
         ping/0,
         pong_matches/2]).

-export_type([client/0]).

-record(client,
        {sock,
         codec}).

-opaque client() :: #client{}.
-type tcp_error() :: inet:posix() | closed.  % | timeout.

connect(Host, Port, Secret, DcId, Protocol) ->
    Seed = crypto:strong_rand_bytes(58),
    connect(Host, Port, Seed, Secret, DcId, Protocol).

-spec connect(inet:socket_address() | inet:hostname(),
              inet:port_number(),
              binary(), binary(), integer(),
              mtp_codec:packet_codec() | {mtp_fake_tls, binary()}) -> client().
connect(Host, Port, Seed, Secret, DcId, Protocol0) ->
    Opts = [{packet, raw},
            {mode, binary},
            {active, false},
            {buffer, 1024},
            {send_timeout, 5000}],
    {ok, Sock} = gen_tcp:connect(Host, Port, Opts, 1000),
    {Protocol, TlsEnabled, TlsSt} =
        case Protocol0 of
            {mtp_fake_tls, Domain} ->
                ClientHello = mtp_fake_tls:make_client_hello(Secret, Domain),
                ok = gen_tcp:send(Sock, ClientHello),
                %% Let's hope whole server hello will arrive in a single chunk
                {ok, ServerHello} = gen_tcp:recv(Sock, 0, 5000),
                %% TODO: if Tail is not empty, use codec:push_back(first, ..)
                {_HS, _CC, _D, <<>>} = mtp_fake_tls:parse_server_hello(ServerHello),
                {mtp_secure, true, mtp_fake_tls:new()};
            _ -> {Protocol0, false, undefined}
        end,
    {Header0, _, _, CryptoLayer} = mtp_obfuscated:client_create(Seed, Secret, Protocol, DcId),
    NoopSt = mtp_noop_codec:new(),
    %% First, create codec with just TLS (which might be noop as well) to encode "obfuscated" header
    Codec0 = mtp_codec:new(mtp_noop_codec, NoopSt,
                           mtp_noop_codec, NoopSt,
                           TlsEnabled, TlsSt,
                           25 * 1024 * 1024),
    {Header, Codec1} = mtp_codec:encode_packet(Header0, Codec0),
    ok = gen_tcp:send(Sock, Header),
    PacketLayer = Protocol:new(),
    Codec2 = mtp_codec:replace(crypto, mtp_obfuscated, CryptoLayer, Codec1),
    Codec3 = mtp_codec:replace(packet, Protocol, PacketLayer, Codec2),
    #client{sock = Sock,
            codec = Codec3}.

send(Data, #client{sock = Sock, codec = Codec} = Client) ->
    {Enc, Codec1} = mtp_codec:encode_packet(Data, Codec),
    ok = gen_tcp:send(Sock, Enc),
    Client#client{codec = Codec1}.

-spec recv_packet(client(), timeout()) -> {ok, iodata(), client()} | {error, tcp_error() | timeout}.
recv_packet(#client{codec = Codec} = Client, Timeout) ->
    case mtp_codec:try_decode_packet(<<>>, Codec) of
        {ok, Data, Codec1} ->
            %% We already had some data in codec's buffers
            {ok, Data, Client#client{codec = Codec1}};
        {incomplete, Codec1} ->
            recv_packet_inner(Client#client{codec = Codec1}, Timeout)
    end.

recv_packet_inner(#client{sock = Sock, codec = Codec0} = Client, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Stream} ->
            %% io:format("~p: ~p~n", [byte_size(Stream), Stream]),
            case mtp_codec:try_decode_packet(Stream, Codec0) of
                {ok, Data, Codec} ->
                    {ok, Data, Client#client{codec = Codec}};
                {incomplete, Codec} ->
                    %% recurse
                    recv_packet_inner(Client#client{codec = Codec}, Timeout)
            end;
        Err ->
            Err
    end.

-spec recv_all(client(), timeout()) -> {ok, [iodata()], client()} | {error, tcp_error()}.
recv_all(#client{sock = Sock, codec = Codec0} = Client, Timeout) ->
    case tcp_recv_all(Sock, Timeout) of
        {ok, Stream} ->
            %% io:format("~p: ~p~n", [byte_size(Stream), Stream]),
            {ok, Packets, Codec} =
                mtp_codec:fold_packets(
                  fun(Packet, Acc, Codec) ->
                          {[Packet | Acc], Codec}
                  end,
                  [], Stream, Codec0),
            {ok, lists:reverse(Packets),
             Client#client{codec = Codec}};
        {error, timeout} ->
            {ok, [], Client};
        Err ->
            Err
    end.

tcp_recv_all(Sock, Timeout) ->
    %% io:format("Sock: ~p; Timeout: ~p~n~n~n", [Sock, Timeout]),
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Stream} ->
            tcp_recv_all_inner(Sock, Stream);
        Err ->
            Err
    end.

tcp_recv_all_inner(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 0) of
        {ok, Stream} ->
            tcp_recv_all_inner(Sock, <<Acc/binary, Stream/binary>>);
        {error, timeout} ->
            {ok, Acc};
        Other ->
            Other
    end.

close(#client{sock = Sock}) ->
    ok = gen_tcp:close(Sock).


ping_session(Host, Port, Secret, DcId, Protocol, Timeout) ->
    Cli0 = connect(Host, Port, Secret, DcId, Protocol),
    ReqPQ = req_pq(),
    Cli1 = send(unencrypted_cli_packet(ReqPQ), Cli0),
    {ok, Packet, Cli2} = recv_packet(Cli1, Timeout),
    ok = close(Cli2),
    {_MsgId, response, ResPQ} = parse_unencrypted_srv_packet(Packet),
    {res_pq_matches(ReqPQ, ResPQ),
     ReqPQ, ResPQ}.

%%
%% Messages
%%

%% @doc encodes payload as unencrypted client message
%% https://core.telegram.org/mtproto/description#unencrypted-message
unencrypted_cli_packet(Payload) ->
    Now = erlang:system_time(microsecond),
    %% Is 128 enough?
    PadSize = rand:uniform(128 div 4) * 4,              % should be alined to 4b
    Padding = crypto:strong_rand_bytes(PadSize),
    unencrypted_cli_packet(Payload, Now, Padding).

unencrypted_cli_packet(Payload, Now, Pad) ->
    %% Client message identifiers are divisible by 4.
    Micro = 1000000,
    NowSec = Now div Micro,
    MicroFraction = Now rem Micro,
    MicroDiv4 = MicroFraction - (MicroFraction rem 4),
    %% MsgId = NowSec * (2 bsl 31) + MicroDiv4,
    [<<0:64,
       MicroDiv4:32/unsigned-little,
       NowSec:32/unsigned-little,
       (byte_size(Payload) + byte_size(Pad)):32/unsigned-little>>,
     Payload | Pad].


%% @doc extracts payload from unencrypted server message
parse_unencrypted_srv_packet(<<0:64, MsgId:64/unsigned-little,
                               Size:32/unsigned-little,
                               Payload:Size/binary>>) ->
    %% Server message identifiers modulo 4 yield 1 if the message is a response to a
    %% client message, and 3 otherwise.
    Kind =
        case MsgId rem 4 of
            1 -> response;
            3 -> event
        end,
    {MsgId, Kind, Payload}.



%% https://core.telegram.org/mtproto/serialize#base-types
-define(int, 32/signed-little).
-define(long, 64/signed-little).

-define(REQ_PQ, 16#60469778:?int).
-define(RES_PQ, 16#05162463:?int).

%% @doc creates req_pq packet
req_pq() ->
    %% req_pq#60469778 nonce:int128 = ResPQ;
    Nonce = <<(crypto:strong_rand_bytes(12)):12/binary,
              (erlang:unique_integer()):32/little>>,
    <<?REQ_PQ, Nonce:16/binary>>.


%% @doc returns `true' if ResPQ nonce matches the nonce for ReqPQ
%% @param ReqPQ: req_pq packet generated by req_pq/0
%% @param ResPQ: resPQ packet received from server
res_pq_matches(<<?REQ_PQ, Nonce:16/binary>>, <<?RES_PQ, Nonce:16/binary, _/binary>>) ->
    %% resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes \
    %%     server_public_key_fingerprints:Vector<long> = ResPQ;
    true;
res_pq_matches(_, _) ->
    false.


-define(PING, 16#7abe77ec:?int).
-define(PONG, 16#347773c5:?int).
%% @doc constructs 'ping' message
ping() ->
    %% ping#7abe77ec ping_id:long = Pong;
    PingId = erlang:unique_integer(),
    <<?PING, PingId:?long>>.

pong_matches(<<?PING, PingId:?long>>, <<?PONG, _MsgId1:?long, PingId:?long>>) ->
    %% pong#347773c5 msg_id:long ping_id:long = Pong;
    true;
pong_matches(_, _) ->
    false.
