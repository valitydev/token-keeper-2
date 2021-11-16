-module(tktor_token_jwt).
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

%%

-behaviour(tktor_token).
-export([load_keyset/1]).
-export([verify/2]).

-type keyset() :: #{authority_id() => key_opts()}.

-export_type([keyset/0]).

%%

-type authority_id() :: token_authenticator:authority_id().

-type key_opts() :: #{
    source := keysource()
}.

-type keysource() ::
    {pem_file, file:filename()}.

-type token_string() :: tktor_token:token_string().
-type source_context() :: tktor_token:source_context().
-type verified_token() :: tktor_token:verified_token().

%%

-define(CLAIM_TOKEN_ID, <<"jti">>).
-define(CLAIM_EXPIRES_AT, <<"exp">>).

-define(PTERM_KEY(Key), {?MODULE, Key}).
-define(KEY_BY_KEYNAME(Keyname), ?PTERM_KEY({keyname, Keyname})).
-define(KEY_BY_KID(KID), ?PTERM_KEY({kid, KID})).

%% Behaviour functions

-spec load_keyset(keyset()) -> ok.
load_keyset(KeySet) ->
    LoadedKeys = load_keys(KeySet),
    %% This check looks like it belongs in tktor_token
    _ = assert_keys_unique(LoadedKeys),
    store_keys(LoadedKeys).

-spec verify(token_string(), source_context()) ->
    {ok, verified_token()}
    | {error,
        {alg_not_supported, Alg :: atom()}
        | {key_not_found, KID :: atom()}
        | {invalid_token, Reason :: term()}
        | invalid_signature}.
verify(Token, SourceContext) ->
    case do_verify(Token) of
        {ok, {Claims, Authority}} ->
            {ok, construct_verified_token(Claims, Authority, SourceContext)};
        {error, _} = Error ->
            Error
    end.

%% Internal functions

load_keys(KeySet) ->
    maps:fold(fun load_key/3, [], KeySet).

load_key(Authority, KeyOpts, Acc) ->
    Source = maps:get(source, KeyOpts),
    case load_key_from_source(Source, Authority) of
        {ok, Key} ->
            [Key | Acc];
        {error, Reason} ->
            exit({import_error, Source, Reason})
    end.

derive_kid_from_public_key_pem_entry(JWKPublic) ->
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    jose_base64url:encode(crypto:hash(sha256, Data)).

load_key_from_source({pem_file, Filename}, Authority) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            JWKPublic = jose_jwk:to_public(JWK),
            KID = derive_kid_from_public_key_pem_entry(JWKPublic),
            {ok, construct_key(KID, JWKPublic, Authority)};
        Error = {error, _} ->
            Error
    end.

construct_key(KID, JWK, Authority) ->
    #{
        jwk => JWK,
        kid => KID,
        algs => jose_jwk:verifier(JWK),
        authority => Authority
    }.

%%

assert_keys_unique(KeyInfos) ->
    lists:foldr(fun assert_key_unique/2, [], KeyInfos).

assert_key_unique(#{kid := KID, authority := Authority}, SeenKIDs) ->
    case lists:member(KID, SeenKIDs) of
        true -> exit({import_error, {duplicate_kid, Authority}});
        false -> [KID | SeenKIDs]
    end.

%%

store_keys(KeyInfos) ->
    lists:foreach(fun store_key/1, KeyInfos).

store_key(#{kid := KID} = KeyInfo) ->
    put_key(KID, KeyInfo).

%%

do_verify(Token) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KID = get_kid(Header),
        case get_key(KID) of
            #{} = KeyInfo ->
                case is_supported_alg(Alg, KeyInfo) of
                    true ->
                        verify_with_key(ExpandedToken, KeyInfo);
                    false ->
                        {error, {alg_not_supported, Alg}}
                end;
            undefined ->
                {error, {key_not_found, KID}}
        end
    catch
        throw:({invalid_token, {missing, _}} = Reason) ->
            {error, Reason};
        error:{badarg, Reason} ->
            {error, {invalid_token, Reason}}
    end.

base64url_to_map(Base64) when is_binary(Base64) ->
    {ok, Json} = jose_base64url:decode(Base64),
    jsx:decode(Json, [return_maps]).

get_kid(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_kid(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

is_supported_alg(Alg, #{algs := Algs}) ->
    lists:member(Alg, Algs).

verify_with_key(ExpandedToken, #{jwk := JWK, authority := Authority}) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            _ = validate_claims(Claims),
            {ok, {Claims, Authority}};
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

%%

construct_verified_token(Claims, Authority, SourceContext) ->
    #{
        id => maps:get(?CLAIM_TOKEN_ID, Claims),
        expiration => get_expiration(Claims),
        authority => Authority,
        payload => Claims,
        source_context => SourceContext
    }.

get_expiration(#{?CLAIM_EXPIRES_AT := 0}) ->
    unlimited;
get_expiration(#{?CLAIM_EXPIRES_AT := Expiration}) when is_integer(Expiration) ->
    Expiration;
get_expiration(#{}) ->
    unlimited.

%%

put_key(KID, Value) ->
    %% Official [Erlang Reference Manual](https://www.erlang.org/doc/man/persistent_term.html) recommends
    %% storing one big persistent_term over muliple small ones, reasoning being that "the execution time for storing
    %% a persistent term is proportional to the number of already existing terms". Since we literally never add new
    %% keys after initial configuration at application start, it seems fine to do this here.
    persistent_term:put(?KEY_BY_KID(KID), Value).

get_key(KID) ->
    persistent_term:get(?KEY_BY_KID(KID), undefined).

%%

validate_claims(Claims) ->
    validate_claims(Claims, get_validators()).

validate_claims(Claims, [{Name, Claim, Validator} | Rest]) ->
    _ = Validator(Name, maps:get(Claim, Claims, undefined)),
    validate_claims(Claims, Rest);
validate_claims(Claims, []) ->
    Claims.

get_validators() ->
    [
        {token_id, ?CLAIM_TOKEN_ID, fun check_presence/2}
    ].

check_presence(_, V) when is_binary(V) ->
    V;
check_presence(_, V) when is_integer(V) ->
    V;
check_presence(C, undefined) ->
    throw({invalid_token, {missing, C}}).
