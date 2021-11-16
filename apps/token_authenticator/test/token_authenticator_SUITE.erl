-module(token_authenticator_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([authenticate_invalid_token_type_fail/1]).
-export([authenticate_invalid_token_key_fail/1]).
-export([authenticate_phony_api_key_token_ok/1]).
-export([authenticate_user_session_token_ok/1]).
-export([authenticate_invoice_template_access_token_ok/1]).
-export([authenticate_invoice_template_access_token_no_access/1]).
-export([authenticate_invoice_template_access_token_invalid_access/1]).
-export([authenticate_claim_token_no_context_fail/1]).
-export([authenticate_claim_token_ok/1]).
-export([authenticate_claim_token_comptability_mode_ok/1]).
-export([authenticate_blacklisted_jti_fail/1]).
-export([authenticate_non_blacklisted_jti_ok/1]).

-type config() :: ct_helper:config().
-type group_name() :: atom().
-type test_case_name() :: atom().

-define(CONFIG(Key, C), (element(2, lists:keyfind(Key, 1, C)))).

%%

-define(TOKEN_SOURCE_CONTEXT, ?TOKEN_SOURCE_CONTEXT(<<"http://spanish.inquisition">>)).
-define(TOKEN_SOURCE_CONTEXT(SourceURL), #token_keeper_TokenSourceContext{request_origin = SourceURL}).
-define(USER_TOKEN_SOURCE, <<"https://dashboard.rbk.money">>).

-define(META_PARTY_ID, <<"test.rbkmoney.party.id">>).
-define(META_USER_ID, <<"test.rbkmoney.user.id">>).
-define(META_USER_EMAIL, <<"test.rbkmoney.user.email">>).
-define(META_USER_REALM, <<"test.rbkmoney.user.realm">>).
-define(META_CAPI_CONSUMER, <<"test.rbkmoney.capi.consumer">>).

-define(TK_AUTHORITY_KEYCLOAK, <<"test.rbkmoney.keycloak">>).
-define(TK_AUTHORITY_CAPI, <<"test.rbkmoney.capi">>).

-define(TK_RESOURCE_DOMAIN, <<"test-domain">>).

%%

-spec all() -> [atom()].

all() ->
    [
        {group, detect_token},
        {group, invoice_template_access_token},
        {group, claim_only},
        {group, blacklist}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {detect_token, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_phony_api_key_token_ok,
            authenticate_user_session_token_ok
        ]},
        {invoice_template_access_token, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_invoice_template_access_token_ok,
            authenticate_invoice_template_access_token_no_access,
            authenticate_invoice_template_access_token_invalid_access
        ]},
        {claim_only, [parallel], [
            authenticate_claim_token_no_context_fail,
            authenticate_claim_token_ok,
            authenticate_claim_token_comptability_mode_ok
        ]},
        {blacklist, [parallel], [
            authenticate_blacklisted_jti_fail,
            authenticate_non_blacklisted_jti_ok
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    Apps =
        genlib_app:start_application(woody) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]) ++
            genlib_app:start_application(token_authenticator),
    [{suite_apps, Apps} | C].

-spec end_per_suite(config()) -> ok.
end_per_suite(C) ->
    genlib_app:stop_unload_applications(?CONFIG(suite_apps, C)).

-spec init_per_group(group_name(), config()) -> config().
init_per_group(detect_token = Name, C) ->
    C0 = start_authenticator([
        #{
            id => ?TK_AUTHORITY_KEYCLOAK,
            token => jwt_token("keys/local/private.pem", C),
            storage => ephemeral_storage([extract_method_detect_token()])
        }
    ]),
    [{groupname, Name} | C0 ++ C];
init_per_group(invoice_template_access_token = Name, C) ->
    C0 = start_authenticator([
        #{
            id => ?TK_AUTHORITY_CAPI,
            token => jwt_token("keys/local/private.pem", C),
            storage => ephemeral_storage([extract_method_invoice_tpl_token()])
        }
    ]),
    [{groupname, Name} | C0 ++ C];
init_per_group(claim_only = Name, C) ->
    C0 = start_authenticator([
        #{
            id => ?TK_AUTHORITY_CAPI,
            token => jwt_token("keys/local/private.pem", C),
            storage => ephemeral_storage([
                {claim, #{
                    compatibility =>
                        {true, #{
                            metadata_mappings => #{
                                party_id => ?META_PARTY_ID,
                                consumer => ?META_CAPI_CONSUMER
                            }
                        }}
                }}
            ])
        }
    ]),
    [{groupname, Name} | C0 ++ C];
init_per_group(blacklist = Name, C) ->
    C0 = start_authenticator(
        [
            #{
                id => <<"blacklisting_authority">>,
                token => jwt_token("keys/local/private.pem", C),
                storage => ephemeral_storage([extract_method_detect_token()])
            },
            #{
                id => ?TK_AUTHORITY_CAPI,
                token => jwt_token("keys/secondary/private.pem", C),
                storage => ephemeral_storage([extract_method_detect_token()])
            }
        ],
        get_filename("blacklisted_keys.yaml", C)
    ),
    [{groupname, Name} | C0 ++ C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_GroupName, C) ->
    ok = token_authenticator_ct_sup:stop_authenticator(?CONFIG(sup_pid, C)),
    ok.

-spec init_per_testcase(atom(), config()) -> config().
init_per_testcase(Name, C) ->
    [{testcase, Name} | C].

-spec end_per_testcase(atom(), config()) -> config().
end_per_testcase(_Name, _C) ->
    ok.

%%

-spec authenticate_invalid_token_type_fail(config()) -> _.
authenticate_invalid_token_type_fail(C) ->
    Client = mk_client(C),
    Token = <<"BLAH">>,
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_invalid_token_key_fail(config()) -> _.
authenticate_invalid_token_key_fail(C) ->
    Client = mk_client(C),
    Token = issue_dummy_token(C),
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_phony_api_key_token_ok(config()) -> _.
authenticate_phony_api_key_token_ok(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID},
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client),
    _ = assert_context({api_key_token, JTI, SubjectID}, Context).

-spec authenticate_user_session_token_ok(config()) -> _.
authenticate_user_session_token_ok(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    Claims = get_user_session_token_claims(JTI, SubjectID, SubjectEmail),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{
            ?META_USER_ID := SubjectID,
            ?META_USER_EMAIL := SubjectEmail,
            ?META_USER_REALM := <<"external">>
        },
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), Client),
    _ = assert_context({user_session_token, JTI, SubjectID, SubjectEmail, unlimited}, Context).

-spec authenticate_invoice_template_access_token_ok(config()) -> _.
authenticate_invoice_template_access_token_ok(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    InvoiceTemplateID = unique_id(),
    SubjectID = unique_id(),
    Claims = get_invoice_access_template_token_claims(JTI, SubjectID, InvoiceTemplateID),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID},
        authority = ?TK_AUTHORITY_CAPI
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client),
    _ = assert_context({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Context).

-spec authenticate_invoice_template_access_token_no_access(config()) -> _.
authenticate_invoice_template_access_token_no_access(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_resource_access_claims(JTI, SubjectID, #{}),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_invoice_template_access_token_invalid_access(config()) -> _.
authenticate_invoice_template_access_token_invalid_access(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    InvoiceID = unique_id(),
    SubjectID = unique_id(),
    Claims = get_resource_access_claims(JTI, SubjectID, #{
        ?TK_RESOURCE_DOMAIN => #{
            <<"roles">> => [
                <<"invoices.", InvoiceID/binary, ":read">>
            ]
        }
    }),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_blacklisted_jti_fail(config()) -> _.
authenticate_blacklisted_jti_fail(C) ->
    Client = mk_client(C),
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/local/private.pem", C)),
    ?assertThrow(#token_keeper_AuthDataRevoked{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_non_blacklisted_jti_ok(config()) -> _.
authenticate_non_blacklisted_jti_ok(C) ->
    Client = mk_client(C),
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/secondary/private.pem", C)),
    ?assertMatch(#token_keeper_AuthData{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_claim_token_no_context_fail(config()) -> _.
authenticate_claim_token_no_context_fail(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_base_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client)).

-spec authenticate_claim_token_ok(config()) -> _.
authenticate_claim_token_ok(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    FragmentContent = create_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    Claims = get_claim_token_claims(JTI, SubjectID, FragmentContent, Metadata, undefined),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = ?TK_AUTHORITY_CAPI
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client),
    _ = assert_context({claim_token, JTI}, Context).

-spec authenticate_claim_token_comptability_mode_ok(config()) -> _.
authenticate_claim_token_comptability_mode_ok(C) ->
    Client = mk_client(C),
    JTI = unique_id(),
    SubjectID = unique_id(),
    FragmentContent = create_bouncer_context(JTI),
    Consumer = <<"client">>,
    Claims = get_claim_token_claims(JTI, SubjectID, FragmentContent, undefined, Consumer),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID, ?META_CAPI_CONSUMER := Consumer},
        authority = ?TK_AUTHORITY_CAPI
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, Client),
    _ = assert_context({claim_token, JTI}, Context).

%%

get_base_claims(JTI, SubjectID) ->
    #{
        <<"jti">> => JTI,
        <<"sub">> => SubjectID,
        <<"exp">> => 0
    }.

get_phony_api_key_claims(JTI, SubjectID) ->
    get_base_claims(JTI, SubjectID).

get_user_session_token_claims(JTI, SubjectID, SubjectEmail) ->
    maps:merge(#{<<"email">> => SubjectEmail}, get_base_claims(JTI, SubjectID)).

get_resource_access_claims(JTI, SubjectID, ResourceAccess) ->
    maps:merge(#{<<"resource_access">> => ResourceAccess}, get_base_claims(JTI, SubjectID)).

get_invoice_access_template_token_claims(JTI, SubjectID, InvoiceTemplateID) ->
    get_resource_access_claims(
        JTI,
        SubjectID,
        #{
            ?TK_RESOURCE_DOMAIN => #{
                <<"roles">> => [
                    <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ".invoice_template_invoices:write">>,
                    <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ":read">>
                ]
            }
        }
    ).

create_bouncer_context(JTI) ->
    Fragment = bouncer_context_helpers:add_auth(
        #{
            method => <<"ClaimToken">>,
            token => #{id => JTI}
        },
        bouncer_context_helpers:empty()
    ),
    encode_context_fragment_content(Fragment).

get_claim_token_claims(JTI, SubjectID, FragmentContent, Metadata, Consumer) ->
    genlib_map:compact(#{
        <<"jti">> => JTI,
        <<"sub">> => SubjectID,
        <<"bouncer_ctx">> => #{
            <<"ty">> => <<"v1_thrift_binary">>,
            <<"ct">> => base64:encode(FragmentContent)
        },
        <<"tk_metadata">> => Metadata,
        <<"cons">> => Consumer,
        <<"exp">> => 0
    }).

%%

mk_client(C) ->
    WoodyCtx = woody_context:new(genlib:to_binary(?CONFIG(testcase, C))),
    ServiceURLs = ?CONFIG(service_urls, C),
    {WoodyCtx, ServiceURLs}.

call_authenticate(Token, TokenSourceContext, Client) ->
    call_token_authenticator('Authenticate', {Token, TokenSourceContext}, Client).

call_token_authenticator(Operation, Args, Client) ->
    call(token_authenticator, Operation, Args, Client).

call(ServiceName, Fn, Args, {WoodyCtx, ServiceURLs}) ->
    Service = get_service_spec(ServiceName),
    Opts = #{
        url => maps:get(ServiceName, ServiceURLs),
        event_handler => scoper_woody_event_handler
    },
    case woody_client:call({Service, Fn, Args}, Opts, WoodyCtx) of
        {ok, Response} ->
            Response;
        {exception, Exception} ->
            throw(Exception)
    end.

get_service_spec(token_authenticator) ->
    {tk_token_keeper_thrift, 'TokenAuthenticator'}.

%%

-define(CTX_ENTITY(ID), #bouncer_base_Entity{id = ID}).

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

decode_bouncer_fragment(#bctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    {ok, Fragment, _} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

assert_context(TokenInfo, EncodedContextFragment) ->
    #bctx_v1_ContextFragment{auth = Auth, user = User} = decode_bouncer_fragment(EncodedContextFragment),
    _ = assert_auth(TokenInfo, Auth),
    _ = assert_user(TokenInfo, User).

assert_auth({claim_token, JTI}, Auth) ->
    ?assertEqual(<<"ClaimToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token);
assert_auth({api_key_token, JTI, SubjectID}, Auth) ->
    ?assertEqual(<<"ApiKeyToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch([#bctx_v1_AuthScope{party = ?CTX_ENTITY(SubjectID)}], Auth#bctx_v1_Auth.scope);
assert_auth({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Auth) ->
    ?assertEqual(<<"InvoiceTemplateAccessToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch(
        [
            #bctx_v1_AuthScope{
                party = ?CTX_ENTITY(SubjectID),
                invoice_template = ?CTX_ENTITY(InvoiceTemplateID)
            }
        ],
        Auth#bctx_v1_Auth.scope
    );
assert_auth({user_session_token, JTI, _SubjectID, _SubjectEmail, Exp}, Auth) ->
    ?assertEqual(<<"SessionToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertEqual(make_auth_expiration(Exp), Auth#bctx_v1_Auth.expiration).

assert_user({claim_token, _}, undefined) ->
    ok;
assert_user({api_key_token, _, _}, undefined) ->
    ok;
assert_user({invoice_template_access_token, _, _, _}, undefined) ->
    ok;
assert_user({user_session_token, _JTI, SubjectID, SubjectEmail, _Exp}, User) ->
    ?assertEqual(SubjectID, User#bctx_v1_User.id),
    ?assertEqual(SubjectEmail, User#bctx_v1_User.email),
    ?assertEqual(?CTX_ENTITY(<<"external">>), User#bctx_v1_User.realm).

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

%%

-include_lib("jose/include/jose_jwk.hrl").

issue_token(Claims, Config) ->
    issue_token_with(Claims, get_filename("keys/local/private.pem", Config)).

issue_token_with(Claims, PemFile) ->
    JWK = jose_jwk:from_pem_file(PemFile),
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(JWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

issue_dummy_token(Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0
    },
    BadPemFile = get_filename("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_filename("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

%%

get_filename(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

start_authenticator(Authorities) ->
    start_authenticator(Authorities, undefined).

start_authenticator(Authorities, BlacklistPath) ->
    ServicePath = <<"/v2/authenticator">>,
    SupPid = token_authenticator_ct_sup:start_authenticator(#{
        service => #{
            path => ServicePath
        },
        blacklist => #{
            path => BlacklistPath
        },
        authorities => Authorities
    }),
    Services = #{
        token_authenticator => mk_url("127.0.0.1", 8022, ServicePath)
    },
    [{sup_pid, SupPid}, {service_urls, Services}].

mk_url(IP, Port, Path) ->
    iolist_to_binary(["http://", IP, ":", genlib:to_binary(Port), Path]).

jwt_token(KeyPath, C) ->
    {jwt, #{
        source => {pem_file, get_filename(KeyPath, C)}
    }}.

ephemeral_storage(Sources) ->
    {ephemeral, #{
        authdata_sources => Sources
    }}.

extract_method_detect_token() ->
    {extract_context, #{
        methods => [
            {detect_token, #{
                phony_api_key_opts => #{
                    metadata_mappings => #{
                        party_id => ?META_PARTY_ID
                    }
                },
                user_session_token_opts => #{
                    user_realm => <<"external">>,
                    metadata_mappings => #{
                        user_id => ?META_USER_ID,
                        user_email => ?META_USER_EMAIL,
                        user_realm => ?META_USER_REALM
                    }
                },
                user_session_token_origins => [?USER_TOKEN_SOURCE]
            }}
        ]
    }}.

extract_method_invoice_tpl_token() ->
    {extract_context, #{
        methods => [
            {invoice_template_access_token, #{
                domain => ?TK_RESOURCE_DOMAIN,
                metadata_mappings => #{
                    party_id => ?META_PARTY_ID
                }
            }}
        ]
    }}.
