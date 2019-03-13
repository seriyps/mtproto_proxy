%% @doc Common data generators for property-based tests

-module(mtp_prop_gen).
-include_lib("proper/include/proper.hrl").

-export([stream_4b/0,
         packet_4b/0,
         stream_16b/0,
         packet_16b/0,
         key/0,
         iv/0,
         secret/0,
         dc_id/0,
         codec/0
        ]).


%% 4-byte aligned packet: `binary()`
packet_4b() ->
    ?LET(IoList, proper_types:non_empty(proper_types:list(proper_types:binary(4))),
         iolist_to_binary(IoList)).

%% List of 4-byte aligned packets: `[binary()]`
stream_4b() ->
    proper_types:list(packet_4b()).

%% 16-byte aligned packet: `binary()`
packet_16b() ->
    ?LET(IoList, proper_types:non_empty(proper_types:list(proper_types:binary(16))),
         iolist_to_binary(IoList)).

%% List of 16-byte aligned packets: `[binary()]`
stream_16b() ->
    proper_types:list(packet_16b()).

%% 32-byte encryption key: `binary()`
key() ->
    proper_types:binary(32).

%% 16-byte encryption initialization vector: `binary()`
iv() ->
    proper_types:binary(16).

%% 16-byte secret: `binary()`
secret() ->
    proper_types:binary(16).

%% Datacenter ID: `[-9..9]`
dc_id() ->
    proper_types:integer(-9, 9).

codec() ->
    Protocols = [mtp_abridged, mtp_intermediate, mtp_secure],
    proper_types:oneof(Protocols).
