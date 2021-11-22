-module(tk_token).

-export([verify/2]).
-export([issue/2]).

%%

-type token_id() :: binary().
-type token_string() :: binary().
-type token_data() :: #{
    id := token_id(),
    expiration := expiration(),
    payload := payload(),
    source_context => source_context()
}.
-type payload() :: map().
-type expiration() :: unlimited | non_neg_integer().
-type source_context() :: #{
    request_origin => binary()
}.

-export_type([token_id/0]).
-export_type([token_string/0]).
-export_type([token_data/0]).
-export_type([payload/0]).
-export_type([expiration/0]).
-export_type([source_context/0]).

%%

-type authority_id() :: tk_authdata:authority_id().

%%

%% @NOTE This is all very speculative, I kind of gave up trying to predict the future

-spec verify(token_string(), source_context()) -> {ok, token_data(), authority_id()} | {error, Reason :: _}.
verify(Token, SourceContext) ->
    case determine_token_type(Token) of
        {ok, KnownType} ->
            case verify(KnownType, Token, SourceContext) of
                {ok, VerifiedToken, AuthorityID} ->
                    check_blacklist(VerifiedToken, AuthorityID);
                {error, Reason} ->
                    {error, {verification_failed, Reason}}
            end
        % {error, unknown_token_type = Reason} ->
        %     {error, Reason}
    end.

-spec issue(token_data(), authority_id()) ->
    {ok, token_string()}
    | {error, Reason :: _}.
issue(TokenData, AuthorityID) ->
    case get_type_for_authority(AuthorityID) of
        {ok, TokenType} ->
            issue(TokenType, TokenData, AuthorityID)
        % {error, unknown_token_type = Reason} ->
        %     {error, Reason}
    end.

%%

%% Nothing else is defined or supported
determine_token_type(_) ->
    {ok, jwt}.

get_type_for_authority(_) ->
    {ok, jwt}.

check_blacklist(#{id := TokenID} = TokenData, AuthorityID) ->
    case tk_blacklist:is_blacklisted(TokenID, AuthorityID) of
        false ->
            {ok, TokenData, AuthorityID};
        true ->
            {error, blacklisted}
    end.

verify(jwt, Token, SourceContext) ->
    tk_token_jwt:verify(Token, SourceContext).

issue(jwt, TokenData, AuthorityID) ->
    tk_token_jwt:issue(TokenData, AuthorityID).
