%% @doc MTProto proxy ping tool.
%% This tool is for manual testing and debugging of MTProto proxies.
%% It is not required for proxy server to work. It is here just for your convenience.
%%
%% Build:   ./rebar3 escriptize
%% Result:  ./_build/default/bin/mtp_ping
%%
%% Usage:   mtp_ping [OPTIONS] <proxy-url>
-module(mtp_ping).

-export([main/1]).

-define(DEFAULT_DC_IDS, [-5, -4, -3, -2, -1, 1, 2, 3, 4, 5]).
-define(DEFAULT_TIMEOUT, 5000).
-define(DEFAULT_REPEAT, 1).

-record(client, {sock, codec}).

%%%-------------------------------------------------------------------
%%% Entry point
%%%-------------------------------------------------------------------

main(Args) ->
    case parse_args(Args) of
        {ok, Url, Opts} ->
            case parse_url(Url) of
                {ok, Proxy} ->
                    _ = application:ensure_all_started(crypto),
                    run(Proxy, Opts);
                {error, Reason} ->
                    die("Invalid URL: ~s~n", [Reason])
            end;
        help ->
            usage(), halt(0);
        {error, Msg} ->
            die("~s~n", [Msg])
    end.

die(Fmt, Args) ->
    io:format(standard_error, "Error: " ++ Fmt ++ "~n", Args),
    usage(),
    halt(1).

usage() ->
    io:format(
      "Usage: mtp_ping [OPTIONS] <proxy-url>~n"
      "~n"
      "Proxy URL formats (tg://proxy or https://t.me/proxy):~n"
      "  Normal:           ...&secret=<32 hex chars>~n"
      "  Secure (dd):      ...&secret=dd<32 hex chars>~n"
      "  Fake-TLS hex:     ...&secret=ee<32 hex chars><domain hex>~n"
      "  Fake-TLS base64:  ...&secret=<base64 starting with '7'>~n"
      "~n"
      "Options:~n"
      "  --dc ID,...      DC IDs to test, comma-separated~n"
      "                   (default: -5,-4,-3,-2,-1,1,2,3,4,5)~n"
      "                   Current valid DCs: https://core.telegram.org/getProxyConfig~n"
      "  --proto P,...    Protocols: normal, secure, fake-tls~n"
      "                   (default: protocol from URL)~n"
      "  --timeout MS     Per-attempt network timeout ms (default: 5000)~n"
      "  --repeat N       Repeat each ping N times, report average (default: 1)~n"
      "  --verbose / -v   Show error stacktraces~n"
      "  --help           Show this help~n"
    ).

%%%-------------------------------------------------------------------
%%% Run
%%%-------------------------------------------------------------------

run(#{host := Host, port := Port, secret := Secret,
      proto_type := ProtoType, domain := Domain}, Opts) ->
    Timeout  = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    Repeat   = maps:get(repeat,  Opts, ?DEFAULT_REPEAT),
    DcIds    = maps:get(dc_ids,  Opts, ?DEFAULT_DC_IDS),
    Verbose  = maps:get(verbose, Opts, false),
    UserProtos = maps:get(protocols, Opts, undefined),
    Protocols = resolve_protocols(UserProtos, ProtoType, Domain),

    io:format("Proxy   : ~s:~w~n", [Host, Port]),
    io:format("Secret  : ~s~n", [bin_to_hex(Secret)]),
    case Domain of
        undefined -> ok;
        D -> io:format("Domain  : ~s~n", [D])
    end,
    RepeatStr = case Repeat of
                    1 -> "";
                    N -> io_lib:format(", showing avg over ~w repeats", [N])
                end,
    io:format("Testing : ~w protocol(s) x ~w DC(s), timeout=~wms~s~n~n",
              [length(Protocols), length(DcIds), Timeout, RepeatStr]),

    Results =
        lists:append(
          [lists:map(
             fun(DcId) ->
                     ping_and_print(Host, Port, Secret, Proto, DcId, Timeout, Repeat, Verbose)
             end, DcIds)
           || Proto <- Protocols]),

    io:format("~n"),
    print_summary(Results).

%% Determine the list of protocols to exercise.
resolve_protocols(undefined, ProtoType, Domain) ->
    [proto_type_to_codec(ProtoType, Domain)];
resolve_protocols(Names, _ProtoType, Domain) ->
    [user_name_to_codec(N, Domain) || N <- Names].

proto_type_to_codec(normal,   _D) -> mtp_intermediate;
proto_type_to_codec(secure,   _D) -> mtp_secure;
proto_type_to_codec(fake_tls,  D) -> {mtp_fake_tls, coerce_domain(D)}.

user_name_to_codec(normal,   _D) -> mtp_intermediate;
user_name_to_codec(secure,   _D) -> mtp_secure;
user_name_to_codec(fake_tls,  D) -> {mtp_fake_tls, coerce_domain(D)}.

coerce_domain(undefined) -> <<"example.com">>;
coerce_domain(D)         -> D.

%%%-------------------------------------------------------------------
%%% Per-ping output
%%%-------------------------------------------------------------------

ping_and_print(Host, Port, Secret, Proto, DcId, Timeout, Repeat, Verbose) ->
    ProtoName = proto_name(Proto),
    DcStr = dc_str(DcId),
    io:format("  ~-9s  DC ~s  :  ", [ProtoName, DcStr]),
    Runs = [do_ping(Host, Port, Secret, Proto, DcId, Timeout)
            || _ <- lists:seq(1, Repeat)],
    OkRuns = [R || R <- Runs, is_map(R)],
    case OkRuns of
        [] ->
            LastErr = lists:last(Runs),
            io:format("ERROR ~s~n", [error_str(LastErr, Verbose)]),
            #{proto => ProtoName, dc => DcId, error => LastErr};
        _ ->
            Tcp   = avg([maps:get(tcp,  R) || R <- OkRuns]),
            Hs    = avg([maps:get(hs,   R) || R <- OkRuns]),
            Ping  = avg([maps:get(ping, R) || R <- OkRuns]),
            Total = Tcp + Hs + Ping,
            io:format("tcp=~wms  handshake=~wms  ping=~wms  [total=~wms]  OK~n",
                      [Tcp, Hs, Ping, Total]),
            #{proto => ProtoName, dc => DcId,
              tcp => Tcp, hs => Hs, ping => Ping, total => Total}
    end.

%%%-------------------------------------------------------------------
%%% Ping: connect → handshake → req_pq/res_pq round-trip
%%%-------------------------------------------------------------------

do_ping(Host, Port, Secret, Protocol, DcId, Timeout) ->
    T0 = ts(),
    case gen_tcp:connect(to_host(Host), Port,
                         [{packet, raw}, {mode, binary}, {active, false},
                          {send_timeout, Timeout}],
                         Timeout) of
        {ok, Sock} ->
            T1 = ts(),
            try
                Cli0 = client_connect(Sock, Secret, DcId, Protocol, Timeout),
                T2 = ts(),
                ReqPQ = req_pq(),
                Cli1 = client_send(wrap_unencrypted(ReqPQ), Cli0),
                case client_recv(Cli1, Timeout) of
                    {ok, Packet, Cli2} ->
                        client_close(Cli2),
                        T3 = ts(),
                        case parse_unencrypted_srv(Packet) of
                            {_MsgId, response, ResPQ} ->
                                res_pq_matches(ReqPQ, ResPQ) orelse
                                    error(res_pq_nonce_mismatch),
                                #{tcp  => ms(T1 - T0),
                                  hs   => ms(T2 - T1),
                                  ping => ms(T3 - T2)};
                            Other ->
                                client_close(Cli2),
                                error({unexpected_response, Other})
                        end;
                    {error, closed} -> error(connection_closed_after_req_pq);
                    {error, Reason} -> error({recv_failed, Reason})
                end
            catch
                _T:R:Stack ->
                    gen_tcp:close(Sock),
                    {error, handshake, R, Stack}
            end;
        {error, Reason} ->
            {error, connect, Reason}
    end.

to_host(Host) -> binary_to_list(Host).

%%%-------------------------------------------------------------------
%%% Client connection (mirrors mtpc_client from mtp_checker)
%%%-------------------------------------------------------------------

client_connect(Sock, Secret, DcId, {mtp_fake_tls, Domain}, Timeout) ->
    CH = mtp_fake_tls:make_client_hello(Secret, Domain),
    ok = gen_tcp:send(Sock, CH),
    Tail = recv_server_hello(Sock, Timeout, <<>>),
    client_connect_obfuscated(Sock, Secret, DcId, mtp_secure,
                              true, mtp_fake_tls:new(), Tail, Timeout);
client_connect(Sock, Secret, DcId, Protocol, Timeout) ->
    client_connect_obfuscated(Sock, Secret, DcId, Protocol,
                              false, undefined, <<>>, Timeout).

client_connect_obfuscated(Sock, Secret, DcId, Protocol,
                          TlsEnabled, TlsSt, Tail, _Timeout) ->
    Seed = crypto:strong_rand_bytes(58),
    {Header0, _, _, CryptoLayer} = mtp_obfuscated:client_create(Seed, Secret, Protocol, DcId),
    NoopSt = mtp_noop_codec:new(),
    Codec00 = mtp_codec:new(mtp_noop_codec, NoopSt,
                            mtp_noop_codec, NoopSt,
                            TlsEnabled, TlsSt,
                            25 * 1024 * 1024),
    Codec0  = mtp_codec:push_back(first, Tail, Codec00),
    {Header, Codec1} = mtp_codec:encode_packet(Header0, Codec0),
    ok = gen_tcp:send(Sock, Header),
    PacketLayer = Protocol:new(),
    Codec2 = mtp_codec:replace(crypto, mtp_obfuscated, CryptoLayer, Codec1),
    Codec3 = mtp_codec:replace(packet, Protocol, PacketLayer, Codec2),
    #client{sock = Sock, codec = Codec3}.

recv_server_hello(Sock, Timeout, Acc) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Part} ->
            Data = <<Acc/binary, Part/binary>>,
            case mtp_fake_tls:parse_server_hello(Data) of
                {_HS, _CC, _D, Tail}         -> Tail;
                incomplete                    -> recv_server_hello(Sock, Timeout, Data);
                {error, tls_domain_forwarding} -> error(tls_domain_forwarding);
                {error, tls_alert}            -> error(tls_alert);
                {error, not_proxy_response}   -> error(not_proxy_response)
            end;
        {error, closed} -> error(connection_closed_during_tls_handshake);
        {error, Reason} -> error({tls_handshake_recv_failed, Reason})
    end.

client_send(Data, #client{sock = Sock, codec = Codec} = C) ->
    {Enc, Codec1} = mtp_codec:encode_packet(Data, Codec),
    ok = gen_tcp:send(Sock, Enc),
    C#client{codec = Codec1}.

client_recv(#client{codec = Codec} = C, Timeout) ->
    case mtp_codec:try_decode_packet(<<>>, Codec) of
        {ok, Data, Codec1} ->
            {ok, Data, C#client{codec = Codec1}};
        {incomplete, Codec1} ->
            client_recv_inner(C#client{codec = Codec1}, Timeout)
    end.

client_recv_inner(#client{sock = Sock, codec = Codec0} = C, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Stream} ->
            case mtp_codec:try_decode_packet(Stream, Codec0) of
                {ok, Data, Codec} ->
                    {ok, Data, C#client{codec = Codec}};
                {incomplete, Codec} ->
                    client_recv_inner(C#client{codec = Codec}, Timeout)
            end;
        Err -> Err
    end.

client_close(#client{sock = Sock}) -> gen_tcp:close(Sock).

%%%-------------------------------------------------------------------
%%% MTProto unencrypted message framing (pre-auth handshake)
%%%-------------------------------------------------------------------

%% Wrap payload as an unencrypted MTProto client message.
wrap_unencrypted(Payload) ->
    Now = erlang:system_time(microsecond),
    PadSize = rand:uniform(128 div 4) * 4,
    Padding = crypto:strong_rand_bytes(PadSize),
    Micro = 1000000,
    NowSec = Now div Micro,
    MF = Now rem Micro,
    MF4 = MF - (MF rem 4),
    [<<0:64,
       MF4:32/unsigned-little,
       NowSec:32/unsigned-little,
       (byte_size(Payload) + byte_size(Padding)):32/unsigned-little>>,
     Payload, Padding].

parse_unencrypted_srv(<<0:64, MsgId:64/unsigned-little,
                         Size:32/unsigned-little,
                         Payload:Size/binary, _/binary>>) ->
    Kind = case MsgId rem 4 of 1 -> response; 3 -> event end,
    {MsgId, Kind, Payload}.

-define(REQ_PQ_CID, 16#60469778).
-define(RES_PQ_CID, 16#05162463).

req_pq() ->
    Nonce = <<(crypto:strong_rand_bytes(12)):12/binary,
              (erlang:unique_integer()):32/little>>,
    <<(?REQ_PQ_CID):32/signed-little, Nonce:16/binary>>.

res_pq_matches(<<(?REQ_PQ_CID):32/signed-little, Nonce:16/binary>>,
               <<(?RES_PQ_CID):32/signed-little, Nonce:16/binary, _/binary>>) -> true;
res_pq_matches(_, _) -> false.

%%%-------------------------------------------------------------------
%%% Summary table
%%%-------------------------------------------------------------------

print_summary(Results) ->
    %% Unique protocols and DC IDs in order of first appearance.
    Protos = unique_ordered([maps:get(proto, R) || R <- Results]),
    DcIds  = unique_ordered([maps:get(dc,    R) || R <- Results]),

    %% --- Part 1: one-line protocol status ---
    io:format("=== Summary ===~n~nProtocols:~n"),
    lists:foreach(
      fun(Proto) ->
              Rs  = [R || R <- Results, maps:get(proto, R) =:= Proto],
              OkN = length([R || R <- Rs, not maps:is_key(error, R)]),
              Tot = length(Rs),
              case OkN > 0 of
                  true ->
                      io:format("  ~-9s  OK       (~w/~w DCs)~n", [Proto, OkN, Tot]);
                  false ->
                      Reasons = lists:usort([error_str(maps:get(error, R), false) || R <- Rs]),
                      io:format("  ~-9s  DISABLED (~w/~w DCs)  ~s~n",
                                [Proto, OkN, Tot, lists:join("; ", Reasons)])
              end
      end, Protos),

    %% --- Part 2: per-DC averages across all working protocols ---
    OkProtos  = [P || P <- Protos,
                      lists:any(fun(R) -> maps:get(proto, R) =:= P
                                          andalso not maps:is_key(error, R)
                                end, Results)],
    OkResults = [R || R <- Results, not maps:is_key(error, R)],
    case OkResults of
        [] -> ok;
        _  ->
            io:format("~nAvg timings per DC (across ~w working protocol(s)):~n",
                      [length(OkProtos)]),
            io:format("~-4s  ~-8s  ~-13s  ~-9s  ~-9s~n",
                      ["DC", "TCP(ms)", "Handshake(ms)", "Ping(ms)", "Total(ms)"]),
            io:format("~s~n", [lists:duplicate(50, $-)]),
            lists:foreach(
              fun(DcId) ->
                      DcOk = [R || R <- OkResults, maps:get(dc, R) =:= DcId],
                      case DcOk of
                          [] -> ok;
                          _  ->
                              io:format("~-4s  ~-8w  ~-13w  ~-9w  ~-9w~n",
                                        [dc_str(DcId),
                                         avg([maps:get(tcp,   R) || R <- DcOk]),
                                         avg([maps:get(hs,    R) || R <- DcOk]),
                                         avg([maps:get(ping,  R) || R <- DcOk]),
                                         avg([maps:get(total, R) || R <- DcOk])])
                      end
              end, DcIds)
    end.

unique_ordered(List) ->
    lists:foldr(fun(X, Acc) ->
                        case lists:member(X, Acc) of true -> Acc; false -> [X | Acc] end
                end, [], List).

%%%-------------------------------------------------------------------
%%% URL parsing
%%%-------------------------------------------------------------------

parse_url(Url) ->
    try
        UriMap = case uri_string:parse(Url) of
                     {error, Reason, _} ->
                         throw({error, io_lib:format("malformed URL: ~p", [Reason])});
                     M -> M
                 end,
        validate_uri(UriMap),
        Query  = maps:get(query, UriMap, ""),
        Params = case uri_string:dissect_query(Query) of
                     {error, Reason2, _} ->
                         throw({error, io_lib:format("malformed query string: ~p", [Reason2])});
                     P -> P
                 end,
        Host      = require_param(Params, "server"),
        Port      = list_to_integer(require_param(Params, "port")),
        SecretStr = require_param(Params, "secret"),
        {ProtoType, Secret16, Domain} = decode_secret(SecretStr),
        {ok, #{host       => list_to_binary(Host),
               port       => Port,
               secret     => Secret16,
               proto_type => ProtoType,
               domain     => Domain}}
    catch
        throw:{error, Msg} -> {error, Msg};
        _:Err -> {error, io_lib:format("parse error: ~p", [Err])}
    end.

validate_uri(#{scheme := "tg",    host := "proxy"})                  -> ok;
validate_uri(#{scheme := "https", host := "t.me", path := "/proxy"}) -> ok;
validate_uri(#{scheme := S} = M) ->
    throw({error, io_lib:format("unsupported URL: ~s://~s~s",
                                [S, maps:get(host, M, ""), maps:get(path, M, "")])});
validate_uri(_) ->
    throw({error, "invalid URL"}).

require_param(Params, Key) ->
    case proplists:get_value(Key, Params) of
        undefined -> throw({error, "missing URL parameter: " ++ Key});
        Val -> Val
    end.

%%--------------------------------------------------------------------
%% Secret decoding
%%
%% The `secret` query parameter can be in several formats:
%%   32 hex chars            → normal (mtp_intermediate), 16-byte secret
%%   "dd" + 32 hex chars     → secure (mtp_secure),       16-byte secret
%%   "ee" + 32 hex + hex dom → fake-tls,                  16-byte secret + domain
%%   base64 starting with "7"→ fake-tls (ee-prefix packed as base64),
%%                             decoded: <<0xEE, secret:16, domain/binary>>
%%--------------------------------------------------------------------
decode_secret(S) ->
    Lc = string:to_lower(S),
    case Lc of
        [$7 | _] -> decode_b64_secret(S);
        _        -> decode_hex_secret(Lc)
    end.

decode_hex_secret(Hex) ->
    case length(Hex) of
        32 ->
            {normal, hex_to_bin(Hex), undefined};
        34 ->
            "dd" ++ Rest = Hex,
            {secure, hex_to_bin(Rest), undefined};
        N when N > 34 ->
            "ee" ++ Rest = Hex,
            SecHex = lists:sublist(Rest, 32),
            DomHex = lists:nthtail(32, Rest),
            Domain = hex_to_bin(DomHex),
            {fake_tls, hex_to_bin(SecHex), nonempty_domain(Domain)};
        _ ->
            throw({error, io_lib:format("invalid secret length ~w", [length(Hex)])})
    end.

decode_b64_secret(S) ->
    %% Normalise URL-safe base64 (-/_) to standard (+//) and add padding.
    Std = lists:map(fun($-) -> $+; ($_) -> $/; (C) -> C end, S),
    Pad = Std ++ lists:duplicate((4 - (length(Std) rem 4)) rem 4, $=),
    try base64:decode(Pad) of
        <<16#ee, Secret:16/binary, DomainBin/binary>> ->
            {fake_tls, Secret, nonempty_domain(DomainBin)};
        Other ->
            throw({error, io_lib:format("unexpected base64 secret value: ~p", [Other])})
    catch
        _:_ -> throw({error, "invalid base64 secret"})
    end.

nonempty_domain(<<>>) -> undefined;
nonempty_domain(D)    -> D.

%%%-------------------------------------------------------------------
%%% CLI argument parsing
%%%-------------------------------------------------------------------

parse_args(["--help" | _])                 -> help;
parse_args(Args)                           -> parse_args(Args, #{}, undefined).

parse_args([], _, undefined)               -> {error, "URL is required"};
parse_args([], Opts, Url)                  -> {ok, Url, Opts};
parse_args(["--dc", Val | Rest], Opts, Url) ->
    Ids = [list_to_integer(string:strip(S)) || S <- string:tokens(Val, ",")],
    parse_args(Rest, Opts#{dc_ids => Ids}, Url);
parse_args(["--proto", Val | Rest], Opts, Url) ->
    Protos = [parse_proto_name(string:strip(S)) || S <- string:tokens(Val, ",")],
    parse_args(Rest, Opts#{protocols => Protos}, Url);
parse_args(["--timeout", Val | Rest], Opts, Url) ->
    parse_args(Rest, Opts#{timeout => list_to_integer(Val)}, Url);
parse_args(["--verbose" | Rest], Opts, Url) ->
    parse_args(Rest, Opts#{verbose => true}, Url);
parse_args(["-v" | Rest], Opts, Url) ->
    parse_args(Rest, Opts#{verbose => true}, Url);
parse_args(["--repeat", Val | Rest], Opts, Url) ->
    parse_args(Rest, Opts#{repeat => list_to_integer(Val)}, Url);
parse_args([[$- | _] = Unknown | _], _, _) ->
    {error, "unknown option: " ++ Unknown};
parse_args([Url], Opts, undefined) ->
    parse_args([], Opts, Url);
parse_args([Extra | _], _, _) ->
    {error, "unexpected argument: " ++ Extra}.

parse_proto_name("normal")   -> normal;
parse_proto_name("secure")   -> secure;
parse_proto_name("fake-tls") -> fake_tls;
parse_proto_name(Other) ->
    throw({error, "unknown protocol '" ++ Other ++ "' (use normal, secure, fake-tls)"}).

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

ts() -> erlang:monotonic_time().
ms(Diff) -> erlang:convert_time_unit(Diff, native, millisecond).
avg(L)   -> lists:sum(L) div length(L).

dc_str(N) when N > 0 -> "+" ++ integer_to_list(N);
dc_str(N)            -> integer_to_list(N).

proto_name(mtp_intermediate)      -> "normal";
proto_name(mtp_secure)            -> "secure";
proto_name({mtp_fake_tls, _})     -> "fake-tls".

error_str({error, connect,   Reason}, _Verbose) ->
    io_lib:format("connect failed: ~p", [Reason]);
error_str({error, handshake, tls_domain_forwarding}, _Verbose) ->
    "ClientHello rejected: proxy forwarded to SNI host (domain-fronting response)";
error_str({error, handshake, tls_domain_forwarding, _Stack}, _Verbose) ->
    "ClientHello rejected: proxy forwarded to SNI host (domain-fronting response)";
error_str({error, handshake, tls_alert}, _Verbose) ->
    "ClientHello rejected: proxy sent TLS alert (unsupported format or wrong secret)";
error_str({error, handshake, tls_alert, _Stack}, _Verbose) ->
    "ClientHello rejected: proxy sent TLS alert (unsupported format or wrong secret)";
error_str({error, handshake, not_proxy_response}, _Verbose) ->
    "ClientHello rejected: unexpected non-TLS response from server";
error_str({error, handshake, not_proxy_response, _Stack}, _Verbose) ->
    "ClientHello rejected: unexpected non-TLS response from server";
error_str({error, handshake, Reason}, _Verbose) ->
    io_lib:format("handshake failed: ~p", [Reason]);
error_str({error, handshake, Reason, Stack}, true) ->
    io_lib:format("handshake failed: ~p~n    ~p", [Reason, Stack]);
error_str({error, handshake, Reason, _Stack}, false) ->
    io_lib:format("handshake failed: ~p", [Reason]).

hex_to_bin(Hex) ->
    list_to_binary(
      [list_to_integer([A, B], 16)
       || <<A, B>> <= list_to_binary(string:to_lower(Hex))]).

bin_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).
