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
    UserID = maps:get(?CLAIM_USER_ID, Payload),
    Email = maps:get(?CLAIM_USER_EMAIL, Payload),
    UserRealm = maps:get(user_realm, Opts, undefined),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_user(
        #{
            id => UserID,
            email => Email,
            realm => #{id => UserRealm}
        },
        Acc0
    ),
    Acc2 = bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(Expiration),
            token => #{id => TokenID}
        },
        Acc1
    ),
    {Acc2,
        make_metadata(
            #{
                user_id => UserID,
                user_email => Email,
                user_realm => UserRealm
            },
            Opts
        )}.

%% Internal functions

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(Expiration) when Expiration =:= unlimited ->
    undefined.

make_metadata(Metadata, ExtractorOpts) ->
    Mappings = maps:get(metadata_mappings, ExtractorOpts),
    tk_utils:remap(genlib_map:compact(Metadata), Mappings).
