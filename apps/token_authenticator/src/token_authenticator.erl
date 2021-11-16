-module(token_authenticator).

%%

-export([get_specs/2]).

-type authority_id() :: binary().

-export_type([authority_id/0]).

%%

-type module_config() :: #{}.
-type woody_handlers() :: [woody:http_handler(woody:th_handler())].
-type child_specs() :: list(map()).
-type additional_routes() :: list().

%%

-spec get_specs(module_config(), token_keeper_pulse:handlers()) ->
    {woody_handlers(), child_specs(), additional_routes()}.
get_specs(ModuleConfig, AuditPulse) ->
    BlacklistConfig = maps:get(blacklist, ModuleConfig),
    {TokenConfig, StorageConfig} = configure_authorities(ModuleConfig),
    {get_handler_specs(ModuleConfig, StorageConfig, AuditPulse), get_child_specs(TokenConfig, BlacklistConfig), []}.

%%

get_handler_specs(ModuleConfig, StorageConfig, AuditPulse) ->
    [
        {get_handler_path(ModuleConfig), make_handler(StorageConfig, AuditPulse)}
    ].

get_child_specs(TokenConfig, BlacklistConfig) ->
    [
        tktor_blacklist:child_spec(BlacklistConfig),
        tktor_token:child_spec(TokenConfig)
    ].

%%

get_handler_path(ModuleConfig) ->
    ServiceConfig = maps:get(service, ModuleConfig),
    maps:get(path, ServiceConfig, <<"/v2/authenticator">>).

make_handler(StorageConfig, AuditPulse) ->
    {
        {tk_token_keeper_thrift, 'TokenAuthenticator'},
        {tktor_handler, make_handler_opts(StorageConfig, AuditPulse)}
    }.

make_handler_opts(StorageConfig, AuditPulse) ->
    #{
        storages => StorageConfig,
        pulse => AuditPulse
    }.

%%

configure_authorities(ModuleConfig) ->
    AuthorityConfig = maps:get(authorities, ModuleConfig),
    _ = assert_authority_ids_unique(AuthorityConfig),
    {make_token_config(AuthorityConfig), make_storage_config(AuthorityConfig)}.

assert_authority_ids_unique(AuthorityConfig) ->
    lists:foldr(fun assert_authority_id_unique/2, [], AuthorityConfig).

make_token_config(AuthorityConfig) ->
    lists:foldr(fun split_token_config/2, #{}, AuthorityConfig).

make_storage_config(AuthorityConfig) ->
    lists:foldr(fun split_storage_config/2, #{}, AuthorityConfig).

assert_authority_id_unique(#{id := ID}, Seen) ->
    case lists:member(ID, Seen) of
        true -> throw({misconfiguration, {authority_id_not_unique, ID}});
        false -> [ID | Seen]
    end.

split_storage_config(#{id := AuthorityID, storage := AuthorityStorageConfig}, StorageConfig) ->
    maps:put(AuthorityID, AuthorityStorageConfig, StorageConfig).

split_token_config(#{id := AuthorityID, token := AuthorityTokenConfig}, TokenConfig) ->
    maps:put(AuthorityID, AuthorityTokenConfig, TokenConfig).

%     [make_keyset(AuthorityID, AuthorityTokenConfig) | TokenConfig].

% make_keyset(AuthorityID, {jwt, TokenConfig}) ->
%     #{
%         source => maps:get(source, TokenConfig),
%         authority => AuthorityID
%     }.
