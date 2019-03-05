%% @doc property-based tests for mtp_rpc
-module(prop_mtp_rpc).
-include_lib("proper/include/proper.hrl").

-export([prop_nonce/1,
         prop_handshake/1,
         prop_s2c_packet/1,
         prop_c2s_packet/1]).


prop_nonce(doc) ->
    "Tests encode/decode of 'nonce' RPC packet".

prop_nonce() ->
    ?FORALL(Packet, nonce_gen(), nonce(Packet)).

nonce_gen() ->
    {nonce,
     proper_types:binary(4),
     1,
     proper_types:pos_integer(),
     proper_types:binary(16)}.

nonce(Packet) ->
    Bin = mtp_rpc:encode_nonce(Packet),
    Packet == mtp_rpc:decode_nonce(Bin).


prop_handshake(doc) ->
    "Tests encode/decode of 'handshake' RPC packet".

prop_handshake() ->
    ?FORALL(Packet, handshake_gen(), handshake(Packet)).

handshake_gen() ->
    {handshake,
     proper_types:binary(12),
     proper_types:binary(12)}.

handshake(Packet) ->
    Bin = mtp_rpc:encode_handshake(Packet),
    Packet == mtp_rpc:decode_handshake(Bin).


prop_s2c_packet(doc) ->
    "Tests encode/decode of 'proxy_ans'/'close_ext' RPC packets".

prop_s2c_packet() ->
    ?FORALL(Packet, s2c_packet_gen(), s2c_packet(Packet)).

s2c_packet_gen() ->
    proper_types:oneof(
      [
       {proxy_ans,
        proper_types:integer(),
        proper_types:binary()},
       {close_ext,
        proper_types:integer()}
      ]).

s2c_packet(Packet) ->
    Bin = mtp_rpc:srv_encode_packet(Packet),
    Packet == mtp_rpc:decode_packet(Bin).


prop_c2s_packet(doc) ->
    "Tests encode/decode of 'data'/'remote_closed' RPC packets".

prop_c2s_packet() ->
    ?FORALL(Packet, c2s_packet_gen(), c2s_packet(Packet)).

c2s_packet_gen() ->
    proper_types:oneof(
      [
       {{data,
         mtp_prop_gen:packet_4b()               %Data
        },
        {{proper_types:integer(),               %ConnId
          proper_types:binary(20),              %ClientAddr
          proper_types:binary(16)               %ProxyTag
         },
         proper_types:binary(20)                %ProxyAddr
        }},
       {remote_closed,
        proper_types:integer()}
      ]).

c2s_packet({{data, Data} = Packet, {{ConnId, _, _}, _} = Static}) ->
    Bin = mtp_rpc:encode_packet(Packet, Static),
    {data, ConnId, Data} == mtp_rpc:srv_decode_packet(iolist_to_binary(Bin));
c2s_packet({remote_closed, ConnId} = Packet) ->
    Bin = mtp_rpc:encode_packet(remote_closed, ConnId),
    Packet == mtp_rpc:srv_decode_packet(iolist_to_binary(Bin)).
