%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto intermediate protocol with random padding ("secure")
%%% @end
%%% Created : 29 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_secure).

-behaviour(mtp_layer).

-export([new/0,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-opaque codec() :: mtp_intermediate:codec().

new() ->
    mtp_intermediate:new(#{padding => true}).

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(Data, St) ->
    mtp_intermediate:try_decode_packet(Data, St).

-spec encode_packet(iodata(), codec()) -> iodata().
encode_packet(Data, St) ->
    mtp_intermediate:encode_packet(Data, St).
