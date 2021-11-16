-module(tktor_token).

%%

-export([child_spec/1]).
-export([init/1]).

%%

-callback load_keyset(keyset()) -> ok.
-callback verify(token_string(), source_context()) -> {ok, verified_token()} | {error, Reason :: term()}.

-export([verify/2]).

%% API Types

-type token_opts() :: #{authority_id() => token_handler_opts()}.

-type token_string() :: binary().
-type verified_token() :: #{
    id := binary(),
    expiration := expiration(),
    authority := token_authenticator:authority_id(),
    payload := payload(),
    source_context := source_context()
}.
-type payload() :: map().
-type expiration() :: unlimited | non_neg_integer().
-type source_context() :: #{
    request_origin => binary()
}.

-type type() :: jwt.

-export_type([token_string/0]).
-export_type([verified_token/0]).
-export_type([payload/0]).
-export_type([expiration/0]).
-export_type([source_context/0]).
-export_type([type/0]).

%% Internal types

-type authority_id() :: token_authenticator:authority_id().
-type token_handler_opts() :: {jwt, tktor_token_jwt:keyset()}.
-type keyset() :: tktor_token_jwt:keyset().

%% Supervisor functions

-spec child_spec(token_opts()) -> supervisor:child_spec() | no_return().
child_spec(TokenOpts) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, TokenOpts]},
        type => supervisor
    }.

-spec init(token_opts()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(TokenOpts) ->
    KeySetsByType = get_keysets_by_type(TokenOpts),
    _ = load_keysets(KeySetsByType),
    {ok, {#{}, []}}.

%% API Functions

-spec verify(token_string(), source_context()) ->
    {ok, verified_token()} | {error, blacklisted | {verification_failed, Reason :: term()}}.
verify(TokenString, SourceContext) ->
    case determine_token_type(TokenString) of
        {ok, KnownType} ->
            case verify(KnownType, TokenString, SourceContext) of
                {ok, VerifiedToken} ->
                    check_blacklist(VerifiedToken);
                {error, Reason} ->
                    {error, {verification_failed, Reason}}
            end
        % {error, unknown_token_type = Reason} ->
        %     {error, {verification_failed, Reason}}
    end.

%% Internal functions

get_keysets_by_type(TokenOpts) ->
    maps:fold(
        fun(AuthorityID, {TokenType, TokenTypeOpts}, Keysets) ->
            KeysetForType = maps:get(TokenType, Keysets, #{}),
            maps:put(TokenType, KeysetForType#{AuthorityID => TokenTypeOpts}, Keysets)
        end,
        #{},
        TokenOpts
    ).

load_keysets(KeySets) ->
    maps:foreach(fun load_keyset/2, KeySets).

load_keyset(jwt, Keyset) ->
    tktor_token_jwt:load_keyset(Keyset).

%%

%% Nothing else is defined or supported
determine_token_type(_) ->
    {ok, jwt}.

check_blacklist(VerifiedToken) ->
    case tktor_blacklist:is_blacklisted(VerifiedToken) of
        false ->
            {ok, VerifiedToken};
        true ->
            {error, blacklisted}
    end.

verify(jwt, Token, SourceContext) ->
    tktor_token_jwt:verify(Token, SourceContext).
