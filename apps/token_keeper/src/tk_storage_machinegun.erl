-module(tk_storage_machinegun).

-include_lib("token_keeper_proto/include/tk_events_thrift.hrl").

%% API
-export([get_routes/1]).

-behaviour(tk_storage).
-export([get/3]).
-export([store/3]).
-export([revoke/3]).

-behaviour(machinery).
-export([init/4]).
-export([process_repair/4]).
-export([process_timeout/3]).
-export([process_call/4]).

-type storage_opts() :: #{}.
-export_type([storage_opts/0]).

-define(NS, tk_authdata).

%%

-type authdata() :: tk_authdata:prototype().
-type authdata_id() :: tk_authdata:id().

-type event_handler() :: woody:ev_handler() | [woody:ev_handler()].

-type automaton() :: #{
    % machinegun's automaton url
    url := binary(),
    event_handler := event_handler(),
    transport_opts => woody_client_thrift_http_transport:transport_options()
}.

-type events() :: tk_events_thrift:'AuthDataChange'().
-type machine() :: machinery:machine(events(), any()).
-type result() :: machinery:result(events(), any()).
-type handler_args() :: machinery:handler_args(any()).
-type handler_opts() :: machinery:handler_args(any()).

%%-------------------------------------
%% API

-spec get_routes(machinery_utils:route_opts()) -> machinery_utils:woody_routes().
get_routes(RouteOpts) ->
    machinery_mg_backend:get_routes([create_handler()], RouteOpts).

%%-------------------------------------
%% tk_storage behaviour implementation

-spec get(authdata_id(), storage_opts(), tk_handler:ctx()) -> {ok, authdata()} | {error, _Reason}.
get(ID, _Opts, Ctx) ->
    case machinery:get(?NS, ID, backend(Ctx)) of
        {ok, #{history := History}} ->
            {ok, collapse_history(History)};
        {error, _} = Err ->
            Err
    end.

-spec store(authdata(), storage_opts(), tk_handler:ctx()) -> ok | {error, exists}.
store(#{id := AuthDataID} = AuthData, _Opts, Ctx) ->
    machinery:start(?NS, AuthDataID, AuthData, backend(Ctx)).

-spec revoke(authdata_id(), storage_opts(), tk_handler:ctx()) -> ok | {error, notfound}.
revoke(ID, _Opts, Ctx) ->
    case machinery:call(?NS, ID, revoke, backend(Ctx)) of
        {ok, _Reply} ->
            ok;
        {error, notfound} = Err ->
            Err
    end.

%%-------------------------------------
%% machinery behaviour implementation

-spec init(machinery:args(authdata()), machine(), handler_args(), handler_opts()) -> result().
init(AuthData, _Machine, _, _) ->
    #{
        events => [
            {created, #tk_events_AuthDataCreated{
                id = maps:get(id, AuthData),
                status = maps:get(status, AuthData),
                context = maps:get(context, AuthData),
                metadata = maps:get(metadata, AuthData)
            }}
        ]
    }.

-spec process_repair(machinery:args(_), machine(), handler_args(), handler_opts()) -> no_return().
process_repair(_Args, _Machine, _, _) ->
    erlang:error({not_implemented, process_repair}).

-spec process_timeout(machine(), handler_args(), handler_opts()) -> no_return().
process_timeout(_Machine, _, _) ->
    erlang:error({not_implemented, process_timeout}).

-spec process_call(machinery:args(revoke), machine(), handler_args(), handler_opts()) ->
    {machinery:response(ok), result()}.
process_call(revoke, #{history := History}, _, _) ->
    AuthData = collapse_history(History),
    Events = change_status(revoked, AuthData),
    {ok, #{events => Events}}.

%%-------------------------------------
%% internal

change_status(NewStatus, #{status := NewStatus}) ->
    [];
change_status(NewStatus, #{status := _OtherStatus}) ->
    [{status_changed, #tk_events_AuthDataStatusChanged{status = NewStatus}}].

%%

create_handler() ->
    {?MODULE, #{
        path => <<"/v1/stateproc/storage">>,
        backend_config => #{
            schema => machinery_mg_schema_generic
        }
    }}.

backend(#{woody_context := WC}) ->
    case genlib_app:env(token_keeper, service_clients, #{}) of
        #{automaton := Automaton} ->
            machinery_mg_backend:new(WC, #{
                client => get_woody_client(Automaton),
                schema => machinery_mg_schema_generic
            });
        #{} ->
            erlang:error({misconfiguration, {service_clients, automaton}})
    end.

-spec get_woody_client(automaton()) -> machinery_mg_client:woody_client().
get_woody_client(#{url := Url} = Automaton) ->
    genlib_map:compact(#{
        url => Url,
        event_handler => maps:get(event_handler, Automaton, [scoper_woody_event_handler]),
        transport_opts => maps:get(transport_opts, Automaton, undefined)
    }).

%%

collapse_history(History) ->
    collapse_history(History, undefined).

collapse_history([], AuthData) when AuthData =/= undefined ->
    AuthData;
collapse_history([{_, _, {created, AuthData}} | Rest], undefined) ->
    #tk_events_AuthDataCreated{id = ID, context = Ctx, status = Status, metadata = Meta} = AuthData,
    collapse_history(Rest, #{id => ID, context => Ctx, status => Status, metadata => Meta});
collapse_history([{_, _, {status_changed, StatusChanged}} | Rest], AuthData) when AuthData =/= undefined ->
    #tk_events_AuthDataStatusChanged{status = Status} = StatusChanged,
    collapse_history(Rest, AuthData#{status => Status}).
