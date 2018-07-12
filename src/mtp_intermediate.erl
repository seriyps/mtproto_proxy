%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto intermediate protocol
%%% @end
%%% Created : 18 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_intermediate).

-behaviour(mtp_layer).

-export([new/0,
         new/1,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-record(int_st,
        {padding = false :: boolean(),
         buffer = <<>> :: binary()}).
-define(MAX_PACKET_SIZE, 1 * 1024 * 1024).      % 1mb
-define(APP, mtproto_proxy).
-define(MAX_SIZE, 16#80000000).

-opaque codec() :: #int_st{}.

new() ->
    new(#{}).

new(Opts) ->
    #int_st{padding = maps:get(padding, Opts, false)}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<Len:32/unsigned-little, _/binary>> = Data,
                      #int_st{buffer = <<>>} = St)  ->
    Len1 = case Len < ?MAX_SIZE of
               true -> Len;
               false -> Len - ?MAX_SIZE
           end,
    (Len1 < ?MAX_PACKET_SIZE)
        orelse
        begin
            metric:count_inc([?APP, protocol_error, total], 1, #{labels => [intermediate_max_size]}),
            error({packet_too_large, Len1})
        end,
    try_decode_packet_len(Len1, Data, St);
try_decode_packet(Bin, #int_st{buffer = Buf} = St) when byte_size(Buf) > 0 ->
    try_decode_packet(<<Buf/binary, Bin/binary>>, St#int_st{buffer = <<>>});
try_decode_packet(Bin, #int_st{buffer = <<>>} = St) ->
    {incomplete, St#int_st{buffer = Bin}}.

try_decode_packet_len(Len, Data, #int_st{padding = Pad} = St) ->
    Padding = case Pad of
                  true -> Len rem 4;
                  false -> 0
              end,
    NopadLen = Len - Padding,
    case Data of
        <<_:4/binary, Packet:NopadLen/binary, _Padding:Padding/binary, Rest/binary>> ->
            {ok, Packet, St#int_st{buffer = Rest}};
        _ ->
            {incomplete, St#int_st{buffer = Data}}
    end.

-spec encode_packet(iodata(), codec()) -> iodata().
encode_packet(Data, #int_st{padding = Pad} = St) ->
    Size = iolist_size(Data),
    Packet = case Pad of
                 false -> [<<Size:32/little>> | Data];
                 true ->
                     PadSize = rand:uniform(4) - 1,
                     Padding = crypto:strong_rand_bytes(PadSize), % 0 is ok
                     [<<(Size + PadSize):32/little>>, Data | Padding]
             end,
    {Packet, St}.
