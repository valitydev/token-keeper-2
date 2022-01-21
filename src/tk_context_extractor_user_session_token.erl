-module(tk_context_extractor_user_session_token).
-behaviour(tk_context_extractor).

-export([extract_context/2]).

%%

-type opts() :: #{
    metadata_mappings := #{
        user_id := binary(),
        user_email := binary(),
        user_realm := binary()
    },
    user_realm := binary()
}.

-export_type([opts/0]).

%%

-define(CLAIM_USER_ID, <<"sub">>).
-define(CLAIM_USER_EMAIL, <<"email">>).

%% API functions

-spec extract_context(tk_token:token_data(), opts()) -> tk_context_extractor:extracted_context() | undefined.
extract_context(#{id := TokenID, expiration := Expiration, payload := Payload}, Opts) ->
    case extract_user_data(Payload) of
        {ok, {UserID, UserEmail}} ->
            create_context_and_metadata(TokenID, Expiration, UserID, UserEmail, Opts);
        {error, Reason} ->
            _ = logger:warning("Could not extract user_session_token context, reason: ~p", [Reason]),
            undefined
    end.

%% Internal functions

create_context_and_metadata(TokenID, TokenExpiration, UserID, UserEmail, Opts) ->
    UserRealm = maps:get(user_realm, Opts),
    {
        create_context(TokenID, TokenExpiration, UserID, UserEmail, UserRealm),
        wrap_metadata(
            create_metadata(UserID, UserEmail, UserRealm),
            Opts
        )
    }.

extract_user_data(#{
    ?CLAIM_USER_ID := UserID,
    ?CLAIM_USER_EMAIL := UserEmail
}) ->
    {ok, {UserID, UserEmail}};
extract_user_data(Payload) ->
    RequiredKeys = [?CLAIM_USER_ID, ?CLAIM_USER_EMAIL],
    {error, {missing, RequiredKeys -- maps:keys(Payload)}}.

create_context(TokenID, TokenExpiration, UserID, UserEmail, UserRealm) ->
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_user(
        #{
            id => UserID,
            email => UserEmail,
            realm => #{id => UserRealm}
        },
        Acc0
    ),
    bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(TokenExpiration),
            token => #{id => TokenID}
        },
        Acc1
    ).

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(Expiration) when Expiration =:= unlimited ->
    undefined.

create_metadata(UserID, UserEmail, UserRealm) ->
    #{
        user_id => UserID,
        user_email => UserEmail,
        user_realm => UserRealm
    }.

wrap_metadata(Metadata, ExtractorOpts) ->
    Mappings = maps:get(metadata_mappings, ExtractorOpts),
    tk_utils:remap(genlib_map:compact(Metadata), Mappings).
