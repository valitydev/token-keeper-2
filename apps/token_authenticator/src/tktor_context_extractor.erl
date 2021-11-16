-module(tktor_context_extractor).

%% Behaviour

-callback extract_context(tktor_token:verified_token(), opts()) -> extracted_context() | undefined.

%% API functions

-export([extract_context/2]).

%% API Types

-type method_opts() :: {method(), opts()}.
-type methods() :: [method_opts()].
-type method() :: detect_token | api_key_token | user_session_token | invoice_template_access_token.

-type opts() ::
    tktor_context_extractor_detect_token:opts()
    | tktor_context_extractor_phony_api_key:opts()
    | tktor_context_extractor_user_session_token:opts()
    | tktor_context_extractor_invoice_tpl_token:opts().

-type extracted_context() :: {context_fragment(), tktor_authdata:metadata() | undefined}.
-type context_fragment() :: bouncer_context_helpers:context_fragment().

-export_type([methods/0]).
-export_type([method/0]).
-export_type([opts/0]).
-export_type([extracted_context/0]).
-export_type([context_fragment/0]).

%% API functions

-spec extract_context(method_opts(), tktor_token:verified_token()) -> extracted_context() | undefined.
extract_context({Method, Opts}, TokenPayload) ->
    Hander = get_extractor_handler(Method),
    Hander:extract_context(TokenPayload, Opts).

%%

get_extractor_handler(detect_token) ->
    tktor_context_extractor_detect_token;
get_extractor_handler(phony_api_key) ->
    tktor_context_extractor_phony_api_key;
get_extractor_handler(user_session_token) ->
    tktor_context_extractor_user_session_token;
get_extractor_handler(invoice_template_access_token) ->
    tktor_context_extractor_invoice_tpl_token.
