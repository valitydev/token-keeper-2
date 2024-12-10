-module(tk_audit_log).

-export([child_spec/1]).

-behaviour(tk_pulse).

-export([handle_beat/3]).

-behaviour(gen_server).

-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).

-define(HANDLER_ID, ?MODULE).

-define(DEFAULT_LOG_LEVEL, notice).
-define(DEFAULT_FORMATTER, {logger_formatter, #{single_line => true}}).

-type opts() :: #{
    % Which log level to use for audit events? Defaults to `notice`.
    level => logger:level(),
    backend => logger_backend_opts(),
    % http://erlang.org/doc/man/logger.html#type-formatter_config
    formatter => {module(), logger:formatter_config()}
}.

% NOTE
% Keep in sync with `opts()`.
-define(OPTS, [level, backend, formatter]).

-type logger_backend_opts() :: #{
    % Where to log? Defaults to `standard_io`.
    type => standard_io | standard_error | file,
    % Log file location. No default, MUST be set if `type` is `file`.
    file => file:filename(),
    % How often to force fsync on log file, in ms? Defaults to 1000.
    % http://erlang.org/doc/man/logger_std_h.html
    filesync_repeat_interval => pos_integer() | no_repeat,
    max_no_bytes => pos_integer() | infinity,
    max_no_files => non_neg_integer()
}.

-opaque st() :: {logger:level(), _Formatter :: {module(), logger:formatter_config()}}.

-export_type([opts/0]).
-export_type([st/0]).

%%

-spec child_spec(opts()) -> {ok, supervisor:child_spec(), tk_pulse:handler(st())}.
child_spec(Opts) ->
    _ = assert_strict_opts(?OPTS, Opts),
    Level = validate_log_level(maps:get(level, Opts, ?DEFAULT_LOG_LEVEL)),
    Formatter = maps:get(formatter, Opts, ?DEFAULT_FORMATTER),
    BackendConfig = mk_logger_backend_config(maps:get(backend, Opts, #{})),
    Config = #{
        id => ?HANDLER_ID,
        module => logger_std_h,
        config => BackendConfig,
        formatter => Formatter
    },
    ChildSpec = #{
        id => ?MODULE,
        start => {gen_server, start_link, [{local, ?HANDLER_ID}, ?MODULE, {Level, Config}, []]},
        restart => permanent,
        shutdown => 5000
    },
    Pulse = {?MODULE, {Level, Formatter}},
    {ok, ChildSpec, Pulse}.

validate_log_level(Level) ->
    eq = logger:compare_levels(Level, Level),
    Level.

mk_logger_backend_config(BackendOpts) ->
    % NOTE
    % Those are options only relevant for `logger_h_common` module, see its implementation for
    % details.
    Common = [filesync_repeat_interval],
    CommonOpts = maps:with(Common, BackendOpts),
    {ok, BackendConfig} = logger_std_h:check_config(
        ?HANDLER_ID,
        set,
        undefined,
        tune_backend_config(maps:without(Common, BackendOpts))
    ),
    maps:merge(
        CommonOpts,
        BackendConfig
    ).

tune_backend_config(#{type := file} = Opts) ->
    _ = maps:get(file, Opts),
    % NOTE
    % All those options chosen to push message loss probability as close to zero as possible.
    maps:merge(
        #{
            % Protects against accidental write loss upon file rotation.
            file_check => 0
        },
        Opts
    );
tune_backend_config(Opts) ->
    Opts.

assert_strict_opts(Ks, Opts) ->
    case maps:without(Ks, Opts) of
        Empty when map_size(Empty) == 0 ->
            ok;
        Unrecognized ->
            erlang:error({unrecognized_opts, Unrecognized})
    end.

%%

-spec init({logger:level(), logger:handler_config()}) -> {ok, _State}.
init({Level, Config}) ->
    % NOTE
    % Here we're hijacking `logger_h_common` facility which drives log handler activities and
    % periodic filesyncing. This gives us a thin wrapper supporting both logger handler API and
    % an ability to make strictly synchronous writes which aren't really available through regular
    % logger API. Note that we deliberately gave up on overload protection facilities (provided
    % through `logger_olp`).
    case logger_h_common:init(Config) of
        {ok, State1} ->
            Formatter = maps:get(formatter, Config),
            StartEvent = mk_log_event(Level, "audit log started", #{}),
            {ok, State2} = emit_log_sync(log_to_binary(StartEvent, Formatter), State1),
            undefined = erlang:put(?MODULE, {Level, Formatter}),
            {ok, State2};
        Error ->
            erlang:exit(Error)
    end.

-spec handle_call({?MODULE, binary()} | _Call, _From, State) -> {reply, ok | _Result, State}.
handle_call({?MODULE, Bin}, _From, State1) ->
    {Result, State2} = emit_log_sync(Bin, State1),
    {reply, Result, State2};
handle_call(Call, From, State) ->
    logger_h_common:handle_call(Call, From, State).

-spec handle_cast(_Cast, State) -> {noreply, State}.
handle_cast(Cast, State) ->
    logger_h_common:handle_cast(Cast, State).

-spec handle_info(_Info, State) -> {noreply, State}.
handle_info(Info, State) ->
    logger_h_common:handle_info(Info, State).

-spec terminate(_Reason, _State) -> _.
terminate(Reason, State1) ->
    {Level, Formatter} = erlang:get(?MODULE),
    StopEvent = mk_log_event(Level, "audit log stopped", #{}),
    {_, State2} = emit_log_sync(log_to_binary(StopEvent, Formatter), State1),
    logger_h_common:terminate(Reason, State2).

% NOTE
% Be warned that this is IMPLEMENTATION DETAILS and is SUBJECT TO CHANGE!
% This code was adapted from `logger_h_common:handle_load/2` function found in kernel-7.2 app
% which is part of Erlang OTP 23.2.3 release.
% Please take care to update it when upgrading to newer Erlang OTP releases.
emit_log_sync(
    Bin,
    #{
        id := Name,
        module := Module,
        handler_state := HandlerState
    } = State
) ->
    {Result, HS1} = Module:write(Name, sync, Bin, HandlerState),
    {Result, State#{
        handler_state => HS1,
        last_op => write
    }}.

%%

-type beat() :: tk_pulse:beat().
-type metadata() :: tk_pulse:metadata().

-spec handle_beat(beat(), metadata(), st()) -> ok.
handle_beat(Beat, Metadata, {DefaultLevel, Formatter}) ->
    case get_level(Beat, DefaultLevel) of
        undefined ->
            ok;
        Level ->
            log(
                Level,
                get_message(Beat),
                extract_metadata(Metadata, get_beat_metadata(Beat)),
                Formatter
            )
    end.

log(Level, Message, Metadata, Formatter) ->
    Event = mk_log_event(Level, Message, Metadata),
    ok = gen_server:call(?HANDLER_ID, {?MODULE, log_to_binary(Event, Formatter)}).

log_to_binary(Log, {Formatter, FormatterConfig}) ->
    string_to_binary(Formatter:format(Log, FormatterConfig)).

string_to_binary(String) ->
    case unicode:characters_to_binary(String) of
        Binary when is_binary(Binary) ->
            Binary;
        Error ->
            erlang:error(Error)
    end.

mk_log_event(Level, Message, Metadata) ->
    #{
        level => Level,
        msg => {Message, []},
        meta => add_default_metadata(Metadata)
    }.

add_default_metadata(Meta1) ->
    Meta2 = Meta1#{type => audit},
    Meta3 = maps:merge(get_process_metadata(), Meta2),
    logger:add_default_metadata(Meta3).

get_process_metadata() ->
    genlib:define(logger:get_process_metadata(), #{}).

log_allowed(Level) ->
    case logger:allow(Level, ?MODULE) of
        true -> Level;
        false -> undefined
    end.

%%

get_level({{authenticator, authenticate}, started}, _Level) -> log_allowed(debug);
get_level(_, Level) -> Level.

get_message({Op, {failed, _}}) ->
    get_message({Op, failed});
get_message({Op, Event}) ->
    EncodedOp = encode_op(Op),
    EncodedEvent = atom_to_binary(Event),
    <<EncodedOp/binary, " ", EncodedEvent/binary>>.

get_beat_metadata({Op, Event}) when is_atom(Op) ->
    #{Op => build_event(Event)};
get_beat_metadata({{Op, Sub}, Event}) when is_atom(Op) ->
    #{Op => get_beat_metadata({Sub, Event})}.

build_event({failed, Error}) ->
    #{
        event => failed,
        error => encode_error(Error)
    };
build_event(Event) ->
    #{event => Event}.

encode_op(Op) when is_atom(Op) ->
    atom_to_binary(Op);
encode_op({Namespace, Sub}) when is_atom(Namespace) ->
    iolist_to_binary([atom_to_binary(Namespace), <<".">>, encode_op(Sub)]).

encode_error({Class, Details}) when is_atom(Class) ->
    #{class => Class, details => genlib:format(Details)};
encode_error(Class) when is_atom(Class) ->
    #{class => Class};
encode_error(Other) ->
    #{details => genlib:format(Other)}.

extract_metadata(Metadata, Acc) ->
    Acc1 = extract_opt_meta(token, Metadata, fun encode_token/1, Acc),
    Acc2 = extract_opt_meta(source, Metadata, fun encode_token_source/1, Acc1),
    Acc3 = extract_opt_meta(authority_id, Metadata, fun encode_authority_id/1, Acc2),
    Acc4 = extract_opt_meta(authdata_id, Metadata, fun encode_authdata_id/1, Acc3),
    extract_woody_ctx(maps:get(woody_ctx, Metadata, undefined), Acc4).

extract_opt_meta(K, Metadata, EncodeFun, Acc) ->
    case maps:find(K, Metadata) of
        {ok, V} -> Acc#{K => EncodeFun(V)};
        error -> Acc
    end.

encode_token(TokenInfo) ->
    #{
        jti => maps:get(id, TokenInfo),
        payload => maps:get(payload, TokenInfo)
    }.

encode_token_source(#{} = TokenSourceContext) ->
    TokenSourceContext.

encode_authority_id(AuthorityID) when is_binary(AuthorityID) ->
    AuthorityID.

encode_authdata_id(AuthDataID) when is_binary(AuthDataID) ->
    AuthDataID.

extract_woody_ctx(#{rpc_id := RpcID} = WoodyCtx, Acc) ->
    extract_woody_meta(WoodyCtx, extract_woody_rpc_id(RpcID, Acc));
extract_woody_ctx(undefined, Acc) ->
    Acc.

extract_woody_rpc_id(#{span_id := _, trace_id := _, parent_id := _} = RpcID, Acc) ->
    maps:merge(Acc, RpcID).

extract_woody_meta(#{meta := Meta}, Acc) when map_size(Meta) > 0 ->
    Acc#{woody => #{metadata => Meta}};
extract_woody_meta(#{}, Acc) ->
    Acc.
