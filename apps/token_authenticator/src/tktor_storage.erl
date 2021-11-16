-module(tktor_storage).

-export([get_authdata/2]).

-type opts() :: {ephemeral, tktor_storage_ephemeral:opts()}.

-export_type([opts/0]).

%%

-type storage_opts() :: tktor_storage_ephemeral:opts().
-type verified_token() :: tktor_token:verified_token().

-callback get_authdata(verified_token(), storage_opts()) ->
    {ok, tktor_authdata:prototype()} | {error, Reason :: term()}.

-spec get_authdata(verified_token(), opts()) -> {ok, tktor_authdata:prototype()} | {error, Reason :: term()}.
get_authdata(VerifiedToken, {ephemeral, Opts}) ->
    tktor_storage_ephemeral:get_authdata(VerifiedToken, Opts).
