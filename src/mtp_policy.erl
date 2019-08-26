%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2019, Sergey
%%% @doc
%%% Evaluator for "policy" config
%%% @end
%%% Created : 20 Aug 2019 by Sergey <me@seriyps.ru>

-module(mtp_policy).
-export([check/4]).
-export([dec/4]).
-export([convert/2]).

-export_type([rule/0,
              key/0,
              db_val/0]).

-record(vars,
        {listener :: atom(),
         client_ip :: inet:ip_address(),
         ip_family :: inet | inet6,
         tls_domain :: undefined | binary()}).

-type key() ::
        port_name |
        tls_domain |
        client_ipv4 |
        client_ipv6 |
        {client_ipv4_subnet, 1..32} |
        {client_ipv6_subnet, 8..128}.

-type rule() ::
        {max_connections, [key()], pos_integer()} |
        {in_table, key(), mtp_policy_table:sub_tab()} |
        {not_in_table, key(), mtp_policy_table:sub_tab()}.

-type db_val() :: binary() | integer() | atom().

-include_lib("hut/include/hut.hrl").

-spec check([rule()], any(), inet:ip_address(), binary() | undefined) -> [rule()].
check(Rules, ListenerName, ClientIp, TlsDomain) ->
    Vars = vars(ListenerName, ClientIp,TlsDomain),
    lists:dropwhile(
      fun(Rule) ->
              try check(Rule, Vars)
              catch throw:not_applicable ->
                      true
              end
      end, Rules).

dec(Rules, ListenerName, ClientIp,TlsDomain) ->
    Vars = vars(ListenerName, ClientIp,TlsDomain),
    lists:foreach(
      fun({max_connections, Keys, _Max}) ->
              try
                  Key = [val(K, Vars) || K <- Keys],
                  mtp_policy_counter:decrement(Key)
              catch throw:not_applicable ->
                      ok
              end;
         (_) ->
              ok
      end, Rules).

vars(ListenerName, ClientIp, TlsDomain) ->
    IpFamily = case tuple_size(ClientIp) of
                   4 -> inet;
                   8 -> inet6
               end,
    #vars{listener = ListenerName,
          client_ip = ClientIp,
          ip_family = IpFamily,
          tls_domain = TlsDomain}.

check({max_connections, Keys, Max}, Vars) ->
    Key = [val(K, Vars) || K <- Keys],
    case mtp_policy_counter:increment(Key) of
        N when N > Max ->
            mtp_policy_counter:decrement(Key),
            false;
        _ ->
            true
    end;
check({in_table, Key, Tab}, Vars) ->
    Val = val(Key, Vars),
    mtp_policy_table:exists(Tab, Val);
check({not_in_table, Key, Tab}, Vars) ->
    Val = val(Key, Vars),
    not mtp_policy_table:exists(Tab, Val).


val(port_name = T, #vars{listener = Listener}) ->
    convert(T, Listener);
val(tls_domain = T, #vars{tls_domain = Domain}) when is_binary(Domain) ->
    convert(T, Domain);
val(client_ipv4 = T, #vars{ip_family = inet, client_ip = Ip}) ->
    convert(T, Ip);
val(client_ipv6 = T, #vars{ip_family = inet6, client_ip = Ip}) ->
    convert(T, Ip);
val({client_ipv4_subnet, Mask} = T, #vars{ip_family = inet, client_ip = Ip}) when Mask > 0,
                                                                                  Mask =< 32 ->
    convert(T, Ip);
val({client_ipv6_subnet, Mask} = T, #vars{ip_family = inet6, client_ip = Ip}) when Mask > 8,
                                                                                   Mask =< 128 ->
    convert(T, Ip);
val(Policy, Vars) when is_atom(Policy);
                       is_tuple(Policy) ->
    ?log(debug, "Policy ~p not applicable ~p", [Policy, Vars]),
    throw(not_applicable).


-spec convert(key(), any()) -> db_val().
convert(port_name, PortName) ->
    PortName;
convert(tls_domain, Domain) when is_binary(Domain) ->
    string:casefold(Domain);
convert(tls_domain, DomainStr) when is_list(DomainStr) ->
    convert(tls_domain, list_to_binary(DomainStr));
convert(client_ipv4, Ip0) ->
    Ip = parse_ip(v4, Ip0),
    <<I:32/unsigned-little>> = mtp_rpc:inet_pton(Ip),
    I;
convert(client_ipv6, Ip0) ->
    Ip = parse_ip(v6, Ip0),
    <<I:128/unsigned-little>> = mtp_rpc:inet_pton(Ip),
    I;
convert({client_ipv4_subnet, Mask}, Ip0) ->
    Ip = parse_ip(v4, Ip0),
    <<I:Mask/unsigned-little, _/bits>> = mtp_rpc:inet_pton(Ip),
    I;
convert({client_ipv6_subnet, Mask}, Ip0) ->
    Ip = parse_ip(v6, Ip0),
    <<I:Mask/unsigned-little, _/bits>> = mtp_rpc:inet_pton(Ip),
    I.

parse_ip(v4, Tup) when is_tuple(Tup),
                       tuple_size(Tup) == 4 ->
    Tup;
parse_ip(v6, Tup) when is_tuple(Tup),
                       tuple_size(Tup) == 8 ->
    Tup;
parse_ip(v4, Str) when is_list(Str) ->
    {ok, Ip} = inet:parse_ipv4_address(Str),
    Ip;
parse_ip(v6, Str) when is_list(Str) ->
    {ok, Ip} = inet:parse_ipv6_address(Str),
    Ip.

