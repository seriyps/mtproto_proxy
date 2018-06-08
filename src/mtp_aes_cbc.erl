%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% Block CBC AES codec with buffered decoding
%%% @end
%%% Created :  6 Jun 2018 by Sergey <me@seriyps.ru>

-module(mtp_aes_cbc).
-behaviour(mtp_layer).

-export([new/5,
         encrypt/2,
         decrypt/2,
         try_decode_packet/2,
         encode_packet/2
        ]).

-export_type([codec/0]).

-record(baes_st,
        {decode_buf :: binary(),
         block_size :: pos_integer(),
         encrypt :: any(),                      % aes state
         decrypt :: any()                       % aes state
        }).

-opaque codec() :: #baes_st{}.



new(EncKey, EncIv, DecKey, DecIv, BlockSize) ->
    #baes_st{
       decode_buf = <<>>,
       block_size = BlockSize,
       encrypt = {EncKey, EncIv},
       decrypt = {DecKey, DecIv}
      }.

-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #baes_st{block_size = BSize,
                       encrypt = {EncKey, EncIv}} = S) ->
    ((iolist_size(Data) rem BSize) == 0)
        orelse error({data_not_aligned, BSize, byte_size(Data)}),
    Encrypted = crypto:block_encrypt(aes_cbc, EncKey, EncIv, Data),
    {Encrypted, S#baes_st{encrypt = {EncKey, crypto:next_iv(aes_cbc, Encrypted)}}}.


-spec decrypt(binary(), codec()) -> {binary(), codec()}.
decrypt(Data, #baes_st{block_size = BSize,
                       decode_buf = <<>>} = S) ->
    Size = byte_size(Data),
    Div = Size div BSize,
    Rem = Size rem BSize,
    case {Div, Rem} of
        {0, _} ->
            %% Not enough bytes
            {<<>>, S#baes_st{decode_buf = Data}};
        {_, 0} ->
            %% Aligned
            do_decrypt(Data, S);
        {_, Tail} ->
            %% N blocks + reminder
            Head = Size - Tail,
            <<ToDecode:Head/binary, Reminder/binary>> = Data,
            do_decrypt(ToDecode, S#baes_st{decode_buf = Reminder})
    end;
decrypt(Data, #baes_st{decode_buf = Buf} = S) ->
    decrypt(<<Buf/binary, Data/binary>>, S#baes_st{decode_buf = <<>>}).

do_decrypt(Data, #baes_st{decrypt = {DecKey, DecIv}} = S) ->
    Decrypted = crypto:block_decrypt(aes_cbc, DecKey, DecIv, Data),
    NewDecIv = crypto:next_iv(aes_cbc, Data),
    {Decrypted, S#baes_st{decrypt = {DecKey, NewDecIv}}}.

%% To comply mtp_layer interface
try_decode_packet(Bin, S) ->
    case decrypt(Bin, S) of
        {<<>>, S1} ->
            {incomplete, S1};
        {Dec, S1} ->
            {ok, Dec, S1}
    end.

encode_packet(Bin, S) ->
    encrypt(Bin, S).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

decode_none_test() ->
    DecKey = <<21,211,191,127,143,222,184,152,232,213,25,173,243,163,243,224,133,131,199,13,206,156,146,141,67,172,85,114,190,203,176,215>>,
    DecIV = <<9,156,175,247,37,161,219,155,52,115,93,76,122,195,158,194>>,
    S = new(DecKey, DecIV, DecKey, DecIV, 16),
    ?assertEqual(
       {incomplete, S}, try_decode_packet(<<>>, S)).

decrypt_test() ->
    DecKey = <<21,211,191,127,143,222,184,152,232,213,25,173,243,163,243,224,133,131,199,13,206,156,146,141,67,172,85,114,190,203,176,215>>,
    DecIV = <<9,156,175,247,37,161,219,155,52,115,93,76,122,195,158,194>>,
    S = new(DecKey, DecIV, DecKey, DecIV, 16),
    Samples =
        [{<<36,170,147,95,53,27,44,255,252,105,70,8,90,40,77,226>>,
          <<44,0,0,0,255,255,255,255,245,238,130,118,0,0,0,0>>},
         {<<137,187,80,238,110,142,52,130,119,140,210,138,13,72,169,144,63,167,172,19,161,13,231,169,237,34,203,240,8,135,67,29>>,
          <<134,153,66,10,95,9,134,49,221,133,21,91,73,80,73,80,80,82,80,68,84,73,77,69,133,250,76,84,4,0,0,0>>}
        ],
    lists:foldl(
      fun({In, Out}, S1) ->
              {Dec, S2} = decrypt(In, S1),
              ?assertEqual(Out, Dec),
              S2
      end, S, Samples).

encrypt_test() ->
    EncKey = <<89,84,72,247,172,56,204,11,10,242,143,240,111,53,33,162,221,141,148,243,100,21,167,160,132,99,61,189,128,73,138,89>>,
    EncIV = <<248,195,42,53,235,104,78,225,84,171,182,125,18,192,251,77>>,
    S = new(EncKey, EncIV, EncKey, EncIV, 16),
    Samples =
        [{<<44,0,0,0,255,255,255,255,245,238,130,118,0,0,0,0,73,80,73,80,80,82,80,68,84,73,77,69,73,80,73,80,80,82,80,68,84,73,77,69,2,118,29,129,4,0,0,0>>,
          <<161,206,198,191,175,240,48,162,245,192,234,210,104,195,161,214,55,147,145,157,174,33,243,198,84,188,29,201,116,128,185,149,73,241,149,122,244,193,59,112,153,188,141,134,90,24,75,216>>},
         {<<136,0,0,0,0,0,0,0,238,241,206,54,8,16,2,64,195,43,106,127,211,218,156,102,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,24,0,0,0,174,38,30,219,16,220,190,143,20,147,250,76,217,171,48,8,145,192,181,179,38,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,56,220,23,91,20,0,0,0,120,151,70,96,26,49,96,74,221,243,104,13,173,13,132,192,238,22,97,126,247,233,151,22,4,0,0,0,4,0,0,0>>,
          <<92,173,139,247,1,147,48,108,162,98,125,215,170,185,87,131,65,26,90,205,43,54,115,216,90,101,3,188,151,165,126,144,104,247,57,65,32,107,245,154,77,194,161,157,63,232,169,68,113,64,96,197,10,209,66,117,251,15,10,141,248,122,40,242,195,38,196,237,68,132,189,49,102,53,31,139,56,64,213,107,79,105,210,182,157,73,203,105,165,134,163,116,49,94,143,171,88,132,84,123,196,38,35,53,220,182,232,199,92,29,182,129,239,116,252,31,72,29,120,203,57,49,46,129,142,94,204,121,21,113,211,10,193,126,180,227,139,40,85,223,134,124,152,81>>}],
    lists:foldl(
      fun({In, Out}, S1) ->
              {Enc, S2} = encrypt(In, S1),
              ?assertEqual(Out, Enc),
              S2
      end, S, Samples).

-endif.
