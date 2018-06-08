%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Abstraction that allows to wrap one mtp_layer into another mtp_layer
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_wrap).
-behaviour(mtp_layer).

-export([new/2,
         try_decode_packet/2,
         encode_packet/2]).
-export_type([codec/0]).

-record(wrap_st,
        {outer :: mtp_layer:layer(),
         inner :: mtp_layer:layer()}).

-define(APP, mtproto_proxy).

-opaque codec() :: #wrap_st{}.

new(Outer, Inner) ->
    #wrap_st{outer = Outer,
             inner = Inner}.

%% try_decode_packet(Inner) |> try_decode_packet(Outer)
try_decode_packet(Bin, #wrap_st{outer = Outer,
                                inner = Inner} = S) ->
    {Dec1, Inner1} =
        case mtp_layer:try_decode_packet(Bin, Inner) of
            {incomplete, Inner1_} ->
                %% We have to check if something is left in inner's buffers
                {<<>>, Inner1_};
            {ok, Dec1_, Inner1_} ->
                {Dec1_, Inner1_}
        end,
    case mtp_layer:try_decode_packet(Dec1, Outer) of
        {incomplete, Outer1} ->
            {incomplete, S#wrap_st{inner = Inner1,
                                   outer = Outer1}};
        {ok, Dec2, Outer1} ->
            {ok, Dec2, S#wrap_st{inner = Inner1,
                                 outer = Outer1}}
    end.

%% encode_packet(Outer) |> encode_packet(Inner)
encode_packet(Bin, #wrap_st{outer = Outer,
                            inner = Inner} = S) ->
    {Enc1, Outer1} = mtp_layer:encode_packet(Bin, Outer),
    {Enc2, Inner1} = mtp_layer:encode_packet(Enc1, Inner),
    {Enc2, S#wrap_st{outer = Outer1, inner = Inner1}}.
