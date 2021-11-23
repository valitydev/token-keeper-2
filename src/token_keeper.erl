-module(token_keeper).

%% Application callbacks
-behaviour(application).

-export([start/2]).
-export([stop/1]).

%% Supervisor callbacks
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

%% API Types

-type token() :: binary().
-type token_type() :: api_key_token | user_session_token.
-type token_source() :: #{
    request_origin => binary()
}.

-export_type([token/0]).
-export_type([token_type/0]).
-export_type([token_source/0]).

%%

-define(SERVER, ?MODULE).

%%
%% Application callbacks
%%

-spec start(normal, any()) -> {ok, pid()} | {error, any()}.
start(_StartType, _StartArgs) ->
    token_keeper:start_link().

-spec stop(any()) -> ok.
stop(_State) ->
    ok.

%%
%% Supervisor callbacks
%%

-spec start_link() -> genlib_gen:start_ret().
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec init(Args :: term()) -> genlib_gen:supervisor_ret().
init([]) ->
    {AuditChildSpecs, AuditPulse} = get_audit_specs(),
    EventHandlers = genlib_app:env(?MODULE, woody_event_handlers, [woody_event_handler_default]),
    TokenBlacklistSpec = tk_blacklist:child_spec(genlib_app:env(?MODULE, blacklist, #{})),
    TokenKeeperConfig = token_keeper_configurator:configure_authorities(genlib_app:env(?MODULE, authorities)),
    ServicesConfig = genlib_app:env(?MODULE, services),
    HandlerChildSpec = woody_server:child_spec(
        ?MODULE,
        #{
            ip => get_ip_address(),
            port => get_port(),
            protocol_opts => get_protocol_opts(),
            transport_opts => get_transport_opts(),
            shutdown_timeout => get_shutdown_timeout(),
            event_handler => EventHandlers,
            handlers => get_woody_handlers(TokenKeeperConfig, ServicesConfig, AuditPulse),
            additional_routes => [get_health_route() | get_storage_routes(EventHandlers)]
        }
    ),
    {ok, {
        #{strategy => one_for_all, intensity => 6, period => 30},
        lists:flatten([
            AuditChildSpecs,
            TokenBlacklistSpec,
            get_additional_childspecs(TokenKeeperConfig),
            HandlerChildSpec
        ])
    }}.

%%

get_woody_handlers(TokenKeeperConfig, ServicesConfig, AuditPulse) ->
    AuthenticatorServiceConfig = maps:get(authenticator, ServicesConfig, #{}),
    AuthorityServiceConfig = maps:get(authority, ServicesConfig, #{}),
    #{
        authenticator_authorities := AuthenticatorAuthorities,
        authority_handlers := AuthoritiesConfig
    } = TokenKeeperConfig,
    [
        make_authenticator_handler(AuthenticatorAuthorities, AuthenticatorServiceConfig, AuditPulse)
        | make_authority_handlers(AuthoritiesConfig, AuthorityServiceConfig, AuditPulse)
    ].

make_authenticator_handler(AuthenticatorAuthorities, ServiceConfig, AuditPulse) ->
    {
        maps:get(path, ServiceConfig, <<"/v2/authenticator">>),
        {
            {tk_token_keeper_thrift, 'TokenAuthenticator'},
            {tk_handler, #{
                handler => {tk_handler_authenticator, #{authorities => AuthenticatorAuthorities}},
                pulse => AuditPulse
            }}
        }
    }.

make_authority_handlers(AuthoritiesConfig, ServiceConfig, AuditPulse) ->
    maps:fold(
        fun(AuthorityID, AuthorityConfig, Acc) ->
            [make_authority_handler(AuthorityID, AuthorityConfig, ServiceConfig, AuditPulse) | Acc]
        end,
        [],
        AuthoritiesConfig
    ).

make_authority_handler(AuthorityID, {AuthorityType, AuthorityConf}, ServiceConfig, AuditPulse) ->
    {
        make_authority_path(AuthorityID, maps:get(path_prefix, ServiceConfig, <<"/v2/authority">>)),
        {
            get_authority_handler_service_name(AuthorityType),
            {
                tk_handler,
                #{
                    handler =>
                        {get_authority_handler_mod(AuthorityType),
                            get_authority_handler_opts(AuthorityType, AuthorityID, AuthorityConf)},
                    pulse => AuditPulse
                }
            }
        }
    }.

get_authority_handler_service_name(offline) ->
    {tk_token_keeper_thrift, 'TokenAuthority'};
get_authority_handler_service_name(ephemeral) ->
    {tk_token_keeper_thrift, 'EphemeralTokenAuthority'}.

get_authority_handler_mod(offline) ->
    tk_handler_authority_offline;
get_authority_handler_mod(ephemeral) ->
    tk_handler_authority_ephemeral.

get_authority_handler_opts(_, AuthorityID, _) ->
    #{
        authority_id => AuthorityID
    }.

make_authority_path(AuthorityID, Prefix) ->
    <<Prefix/binary, "/", AuthorityID/binary>>.

%%

get_additional_childspecs(#{tokens := TokenHandlerConfig}) ->
    maps:fold(
        fun(TokenType, TokenOps, Acc) ->
            [get_token_handler_childspec(TokenType, TokenOps) | Acc]
        end,
        [],
        TokenHandlerConfig
    ).

get_token_handler_childspec(jwt, Keyset) ->
    tk_token_jwt:child_spec(Keyset).

get_storage_routes(EventHandlers) ->
    tk_storage_machinegun:get_routes(#{event_handler => EventHandlers}).

-spec get_health_route() -> machinery_utils:woody_routes().
get_health_route() ->
    Check = enable_health_logging(genlib_app:env(?MODULE, health_check, #{})),
    erl_health_handle:get_route(Check).

-spec enable_health_logging(erl_health:check()) -> erl_health:check().
enable_health_logging(Check) ->
    EvHandler = {erl_health_event_handler, []},
    maps:map(
        fun(_, Runner) -> #{runner => Runner, event_handler => EvHandler} end,
        Check
    ).

%%

-spec get_ip_address() -> inet:ip_address().
get_ip_address() ->
    {ok, Address} = inet:parse_address(genlib_app:env(?MODULE, ip, "::")),
    Address.

-spec get_port() -> inet:port_number().
get_port() ->
    genlib_app:env(?MODULE, port, 8022).

-spec get_protocol_opts() -> woody_server_thrift_http_handler:protocol_opts().
get_protocol_opts() ->
    genlib_app:env(?MODULE, protocol_opts, #{}).

-spec get_transport_opts() -> woody_server_thrift_http_handler:transport_opts().
get_transport_opts() ->
    genlib_app:env(?MODULE, transport_opts, #{}).

-spec get_shutdown_timeout() -> timeout().
get_shutdown_timeout() ->
    genlib_app:env(?MODULE, shutdown_timeout, 0).

-spec get_audit_specs() -> {[supervisor:child_spec()], tk_pulse:handlers()}.
get_audit_specs() ->
    Opts = genlib_app:env(?MODULE, audit, #{}),
    case maps:get(log, Opts, #{}) of
        LogOpts = #{} ->
            {ok, ChildSpec, Pulse} = tk_audit_log:child_spec(LogOpts),
            {[ChildSpec], [Pulse]};
        disable ->
            {[], []}
    end.
