-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token:token_data(), opts()) -> sourced_authdata() | undefined.

%% API functions

-export([get_authdata/2]).

%% API Types

-type authdata_source() :: legacy_claim_source() | extractor_source().
-type sourced_authdata() :: tk_authdata:prototype().

-type opts() ::
    tk_authdata_source_context_extractor:opts()
    | tk_authdata_source_legacy_claim:opts().

-export_type([authdata_source/0]).
-export_type([sourced_authdata/0]).

%% Internal types

-type legacy_claim_source() :: {legacy_claim, tk_authdata_source_legacy_claim:opts()}.
-type extractor_source() :: {extract_context, tk_authdata_source_context_extractor:opts()}.

%% API functions

-spec get_authdata(tk_token:token_data(), authdata_source()) -> sourced_authdata() | undefined.
get_authdata(TokenPayload, {legacy_claim, Opts}) ->
    tk_authdata_source_legacy_claim:get_authdata(TokenPayload, Opts);
get_authdata(TokenPayload, {extract_context, Opts}) ->
    tk_authdata_source_context_extractor:get_authdata(TokenPayload, Opts).

%% Internal functions
