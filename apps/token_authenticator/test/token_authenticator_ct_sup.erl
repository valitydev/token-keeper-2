-module(token_authenticator_ct_sup).

-export([start_authenticator/1]).
-export([stop_authenticator/1]).

-behaviour(supervisor).
-export([init/1]).

%%

-spec start_authenticator(map()) -> pid().
start_authenticator(AuthenticatorConfig) ->
    {ok, SupPid} = supervisor:start_link(?MODULE, [AuthenticatorConfig]),
    _ = unlink(SupPid),
    SupPid.

-spec stop_authenticator(pid()) -> _.
stop_authenticator(SupPid) ->
    proc_lib:stop(SupPid, shutdown, 2000).

%%

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([AuthenticatorConfig]) ->
    {AuditChildSpecs, AuditPulse} = get_audit_specs(),
    {
        ModuleWoodyHandlers,
        ModuleChildSpecs,
        ModuleAdditionalRoutes
    } = token_authenticator:get_specs(AuthenticatorConfig, AuditPulse),
    HandlerChildSpec = woody_server:child_spec(
        ?MODULE,
        #{
            ip => {0, 0, 0, 0},
            port => 8022,
            protocol_opts => #{},
            transport_opts => #{},
            shutdown_timeout => 1000,
            event_handler => woody_event_handler_default,
            handlers => ModuleWoodyHandlers,
            additional_routes => ModuleAdditionalRoutes
        }
    ),
    {ok, {
        #{strategy => one_for_all, intensity => 6, period => 30},
        ModuleChildSpecs ++ [HandlerChildSpec | AuditChildSpecs]
    }}.

-spec get_audit_specs() -> {[supervisor:child_spec()], token_keeper_pulse:handlers()}.
get_audit_specs() ->
    {ok, ChildSpec, Pulse} = token_keeper_audit_log:child_spec(#{
        formatter => {logger_logstash_formatter, #{}}
    }),
    {[ChildSpec], [Pulse]}.

%%
