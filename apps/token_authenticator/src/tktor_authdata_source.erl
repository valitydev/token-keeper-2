-module(tktor_authdata_source).

%% Behaviour

-callback get_authdata(tktor_token:verified_token(), opts()) -> sourced_authdata() | undefined.

%% API functions

-export([get_authdata/2]).

%% API Types

-type authdata_source() :: claim_source() | extractor_source().
-type sourced_authdata() :: tktor_authdata:prototype().

-type opts() ::
    tktor_authdata_source_context_extractor:opts()
    | tktor_authdata_source_claim:opts().

-export_type([authdata_source/0]).
-export_type([sourced_authdata/0]).

%% Internal types

-type claim_source() :: {claim, tktor_authdata_source_claim:opts()}.
-type extractor_source() :: {extract_context, tktor_authdata_source_context_extractor:opts()}.

%% API functions

-spec get_authdata(authdata_source(), tktor_token:verified_token()) -> sourced_authdata() | undefined.
get_authdata(AuthDataSource, TokenPayload) ->
    {Source, Opts} = get_source_opts(AuthDataSource),
    Hander = get_source_handler(Source),
    Hander:get_authdata(TokenPayload, Opts).

%%

get_source_opts({_Source, _Opts} = StorageOpts) ->
    StorageOpts;
get_source_opts(Source) when is_atom(Source) ->
    {Source, #{}}.

get_source_handler(claim) ->
    tktor_authdata_source_claim;
get_source_handler(extract_context) ->
    tktor_authdata_source_context_extractor.
