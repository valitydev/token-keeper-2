-module(token_authority).

-export([get_specs/2]).

-type module_config() :: #{}.

%%

-type woody_handlers() :: [woody:http_handler(woody:th_handler())].
-type child_specs() :: list(map()).
-type additional_routes() :: list().

%%

-spec get_specs(any(), token_keeper_pulse:handlers()) -> {woody_handlers(), child_specs(), additional_routes()}.
get_specs(ModuleConfig, AuditPulse) ->
    {get_handler_specs(ModuleConfig, AuditPulse), get_child_specs(ModuleConfig), get_additional_routes(ModuleConfig)}.

%%

-spec get_handler_specs(module_config(), token_keeper_pulse:handlers()) -> woody_handlers().
get_handler_specs(ModuleConfig, _AuditPulse) ->
    ServiceConfig = maps:get(service, ModuleConfig),
    [
        {
            maps:get(prefix, ServiceConfig, <<"/v2/authority">>),
            {{tk_token_keeper_thrift, 'TokenAuthority'}, {token_authority_handler, #{}}}
        }
    ].

-spec get_child_specs(module_config()) -> child_specs().
get_child_specs(_ModuleConfig) ->
    [].

-spec get_additional_routes(module_config()) -> additional_routes().
get_additional_routes(_ModuleConfig) ->
    [].

%%
