-module(token_keeper_configurator).

-export([configure_authorities/1]).

-type authority_specs() :: [authority_spec()].

-export_type([authority_specs/0]).

%%

-type authority_id() :: tk_authdata:authority_id().
-type authority_spec(Type, Opts) :: {Type, Opts}.

-type token_spec() :: jwt_token_spec().
-type jwt_token_spec() :: {jwt, tk_token_jwt:key_opts()}.

-type authority_spec() ::
    external_authority_spec()
    | ephemeral_authority_spec()
    | offline_authorty_spec().

-type external_authority_spec() ::
    authority_spec(external, #{
        id => authority_id(),
        token => token_spec(),
        authdata_sources => [tk_authdata_source:authdata_source()]
    }).

-type ephemeral_authority_spec() ::
    authority_spec(ephemeral, #{
        id => authority_id(),
        token => token_spec()
    }).

-type offline_authorty_spec() ::
    authority_spec(offline, #{
        id => authority_id(),
        token => token_spec()
    }).

-type token_keeper_config() :: #{
    authentication_config := authentication_config(),
    authority_handlers := authority_handlers_config(),
    tokens := tokens_config()
}.

-type authentication_config() :: #{authority_id() => authentication_authority_config()}.
-type authority_handlers_config() :: #{authority_id() => authority_handler_config()}.
-type tokens_config() :: #{token_type() => token_handler_config()}.

-type authority(Type, Opts) :: {Type, Opts}.

-type authentication_authority_config() ::
    external_authority_config()
    | ephemeral_authority_config()
    | offline_authority_config().

-type authority_handler_config() ::
    ephemeral_authority_config()
    | offline_authority_config().

-type external_authority_config() ::
    authority(external, #{
        authdata_sources => [tk_authdata_source:authdata_source()]
    }).

-type ephemeral_authority_config() ::
    authority(ephemeral, #{}).

-type offline_authority_config() ::
    authority(offline, #{}).

-type token_type() :: jwt.
-type token_handler_config() :: jwt_token_handler_config().

-type jwt_token_handler_config() :: #{authority_id() => tk_token_jwt:key_opts()}.

%%

-spec configure_authorities(authority_specs()) -> token_keeper_config() | no_return().
configure_authorities(Authorities) ->
    _ = assert_ids_unique(Authorities),
    #{
        authenticator_authorities => configure_authenticator_authorities(Authorities),
        authority_handlers => configure_authority_handlers(Authorities),
        tokens => configure_tokens(Authorities)
    }.

%%

assert_ids_unique(Authorities) ->
    lists:foldr(
        fun({_, #{id := ID}}, SeenIDs) ->
            _ = lists:member(ID, SeenIDs) andalso throw({authority_id_not_unique, ID}),
            [ID | SeenIDs]
        end,
        [],
        Authorities
    ).

%%

configure_authenticator_authorities(Authorities) ->
    lists:foldr(fun fold_authenticator_authority/2, #{}, Authorities).

fold_authenticator_authority({AuthorityType, #{id := AuthorityID} = AuthorityConf}, Acc) ->
    Acc#{AuthorityID => make_payload_conf(AuthorityType, AuthorityConf)}.

make_payload_conf(external = Type, #{authdata_sources := AuthDataSources}) ->
    {Type, #{authdata_sources => AuthDataSources}};
make_payload_conf(Type, _) ->
    {Type, #{}}.

%%

configure_authority_handlers(Authorities) ->
    lists:foldr(fun fold_authority_handler/2, #{}, Authorities).

fold_authority_handler({external, _}, Acc) ->
    %% External authorities dont have thrift interfaces
    Acc;
fold_authority_handler({AuthorityType, #{id := AuthorityID} = AuthorityConf}, Acc) ->
    Acc#{AuthorityID => make_authority_handler(AuthorityType, AuthorityConf)}.

make_authority_handler(Type, _) ->
    {Type, #{}}.

%%

configure_tokens(Authorities) ->
    lists:foldr(fun fold_token_configuration/2, #{}, Authorities).

fold_token_configuration({_, #{id := AuthorityID, token := {TokenType, TokenOpts}}}, Acc) ->
    TokenHandlerOpts = make_token_handler_opts(TokenType, TokenOpts),
    Acc#{TokenType => maps:put(AuthorityID, TokenHandlerOpts, maps:get(TokenType, Acc, #{}))}.

make_token_handler_opts(jwt, TokenOpts) ->
    TokenOpts.
