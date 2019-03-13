%% @doc Simple mtproto proxy client
-module(mtp_test_client).

-export([connect/5,
         send/2,
         recv_packet/2,
         recv_all/2,
         close/1]).
-export_type([client/0]).

-record(client,
        {sock,
         codec}).

-opaque client() :: #client{}.
-type tcp_error() :: inet:posix() | closed.  % | timeout.

connect(Host, Port, Secret, DcId, Protocol) ->
    Opts = [{packet, raw},
            {mode, binary},
            {active, false},
            {buffer, 1024},
            {send_timeout, 5000}],
    {ok, Sock} = gen_tcp:connect(Host, Port, Opts, 1000),
    {Header, _, _, CryptoLayer} = mtp_obfuscated:client_create(Secret, Protocol, DcId),
    ok = gen_tcp:send(Sock, Header),
    PacketLayer = Protocol:new(),
    Codec = mtp_codec:new(mtp_obfuscated, CryptoLayer,
                          Protocol, PacketLayer),
    #client{sock = Sock,
            codec = Codec}.

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
