-module(tktor_authdata_source_claim).
-behaviour(tktor_authdata_source).

%% Behaviour

-export([get_authdata/2]).

%% API types

-type opts() :: token_keeper_claim_utils:decode_opts().
-export_type([opts/0]).

%% Internal types

-type decoded_authdata() :: tktor_authdata:prototype().

%% Behaviour functions

-spec get_authdata(tktor_token:verified_token(), opts()) -> decoded_authdata() | undefined.
get_authdata(#{payload := TokenPayload}, Opts) ->
    case token_keeper_claim_utils:decode_authdata(TokenPayload, Opts) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed attempt to decode authdata from claims: ~p", [Reason]),
            undefined
    end.
