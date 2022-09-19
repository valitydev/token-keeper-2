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
-define(CLAIM_EXPIRES_AT, <<"exp">>).
-define(CLAIM_RESOURCE_ACCESS, <<"resource_access">>).

%% API functions

-spec extract_context(tk_token:token_data(), opts()) -> tk_context_extractor:extracted_context() | undefined.
extract_context(TokenData, Opts) ->
    maybe
        {ok, AuthParams} ?= extract_auth_params(TokenData),
        {ok, UserParams0} ?= extract_user_params(TokenData),
        UserParams = add_user_realm(UserParams0, Opts),
        Context = create_context(UserParams, AuthParams),
        Metadata = wrap_metadata(create_metadata(UserParams), Opts),
        {Context, Metadata}
    else
        {error, Reason} ->
            _ = logger:warning("Could not extract user_session_token context, reason: ~p", [Reason]),
            undefined
    end.

%% Internal functions
extract_user_params(#{
    payload := #{
        ?CLAIM_USER_ID := UserID,
        ?CLAIM_USER_EMAIL := UserEmail
    }
}) ->
    {ok, #{
        id => UserID,
        email => UserEmail
    }};
extract_user_params(TokenData) ->
    RequiredKeys = [
        ?CLAIM_USER_ID,
        ?CLAIM_USER_EMAIL
    ],
    {error, {missing, RequiredKeys -- maps:keys(TokenData)}}.

extract_auth_params(#{
    id := TokenID,
    payload := #{
        ?CLAIM_EXPIRES_AT := TokenExp
    } = Payload
}) ->
    {ok,
        genlib_map:compact(#{
            token_id => TokenID,
            token_exp => TokenExp,
            resource_access => genlib_map:get(?CLAIM_RESOURCE_ACCESS, Payload)
        })};
extract_auth_params(TokenData) ->
    RequiredKeys = [
        ?CLAIM_EXPIRES_AT
    ],
    {error, {missing, RequiredKeys -- maps:keys(TokenData)}}.

add_user_realm(UserParams, Opts) ->
    UserParams#{realm => maps:get(user_realm, Opts)}.

create_context(UserParams, AuthParams) ->
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = append_user_context(UserParams, Acc0),
    append_auth_context(AuthParams, Acc1).

append_user_context(UserParams, BouncerCtx) ->
    bouncer_context_helpers:add_user(UserParams, BouncerCtx).

append_auth_context(AuthParams, BouncerCtx) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(maps:get(token_exp, AuthParams)),
            token => #{
                id => maps:get(token_id, AuthParams),
                access => make_auth_access_list(maps:get(resource_access, AuthParams))
            }
        },
        BouncerCtx
    ).

make_auth_expiration(0) ->
    undefined;
make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second).

make_auth_access_list(ResourceAccess) ->
    maps:fold(
        fun(Key, Value, Acc) ->
            Entry = #{
                id => Key,
                roles => maps:get(roles, Value)
            },
            [Entry | Acc]
        end,
        [],
        ResourceAccess
    ).

create_metadata(UserParams) ->
    #{
        user_id => maps:get(id, UserParams),
        user_email => maps:get(email, UserParams),
        user_realm => maps:get(realm, UserParams)
    }.

wrap_metadata(Metadata, ExtractorOpts) ->
    Mappings = maps:get(metadata_mappings, ExtractorOpts),
    tk_utils:remap(genlib_map:compact(Metadata), Mappings).
