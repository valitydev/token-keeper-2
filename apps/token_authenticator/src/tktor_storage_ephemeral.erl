-module(tktor_storage_ephemeral).

%%

-behaviour(tktor_storage).
-export([get_authdata/2]).

%%

-type opts() :: #{
    authdata_sources := [tktor_authdata_source:authdata_source()]
}.

-export_type([opts/0]).

%% tktor_storage behaviour

-spec get_authdata(tktor_token:verified_token(), opts()) -> {ok, tktor_authdata:prototype()} | {error, Reason :: _}.
get_authdata(VerifiedToken, Opts) ->
    AuthDataSources = get_auth_data_sources(Opts),
    case get_authdata_from_sources(AuthDataSources, VerifiedToken) of
        #{} = AuthData ->
            {ok, AuthData};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

%% Internal functions

get_auth_data_sources(Authority) ->
    case maps:get(authdata_sources, Authority, undefined) of
        Sources when is_list(Sources) ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authdata_from_sources([], _VerifiedToken) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], VerifiedToken) ->
    case tktor_authdata_source:get_authdata(SourceOpts, VerifiedToken) of
        undefined ->
            get_authdata_from_sources(Rest, VerifiedToken);
        AuthData ->
            AuthData
    end.
