-module(tktor_handler).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% Woody handler

-behaviour(woody_server_thrift_handler).
-export([handle_function/4]).

-type handle_ctx() :: #{
    woody_ctx := woody_context:ctx()
}.

-export_type([handle_ctx/0]).

%% Internal types

-type authority_id() :: token_authenticator:authority_id().
-type storage_opts() :: tktor_storage:opts().
-type storages() :: #{authority_id() => storage_opts()}.

-type opts() :: #{
    storages := storages(),
    pulse => token_keeper_pulse:handlers()
}.

-record(state, {
    storages :: storages(),
    woody_context :: woody_context:ctx(),
    pulse :: token_keeper_pulse:handlers(),
    pulse_metadata :: token_keeper_pulse:metadata()
}).

%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()} | no_return().
handle_function(Op, Args, WoodyCtx, Opts) ->
    State = make_state(WoodyCtx, Opts),
    handle_function_(Op, Args, State).

handle_function_('AddExistingToken', _, _State) ->
    erlang:error(not_implemented);
handle_function_('Authenticate' = Op, {Token, TokenSourceContext}, State) ->
    _ = pulse_op_stated(Op, State),
    case tktor_token:verify(Token, decode_source_context(TokenSourceContext)) of
        {ok, VerifiedToken} ->
            State1 = save_pulse_metadata(#{token => VerifiedToken}, State),
            case get_authdata(VerifiedToken, State#state.storages) of
                {ok, #{status := Status} = AuthDataPrototype} when Status =/= revoked ->
                    EncodedAuthData = encode_auth_data(tktor_authdata:from_prototype(AuthDataPrototype, Token)),
                    _ = pulse_op_succeeded(Op, State1),
                    {ok, EncodedAuthData};
                {ok, _} ->
                    _ = pulse_op_failed(Op, authdata_revoked, State),
                    woody_error:raise(business, #token_keeper_AuthDataRevoked{});
                {error, Reason} ->
                    _ = pulse_op_failed(Op, Reason, State),
                    woody_error:raise(business, #token_keeper_AuthDataNotFound{})
            end;
        {error, {verification_failed, _} = Reason} ->
            _ = pulse_op_failed(Op, Reason, State),
            woody_error:raise(business, #token_keeper_InvalidToken{});
        {error, blacklisted = Reason} ->
            _ = pulse_op_failed(Op, Reason, State),
            woody_error:raise(business, #token_keeper_AuthDataRevoked{})
    end.

%% Internal functions

make_state(WoodyCtx, Opts) ->
    #state{
        storages = maps:get(storages, Opts),
        woody_context = WoodyCtx,
        pulse = maps:get(pulse, Opts, []),
        pulse_metadata = #{woody_ctx => WoodyCtx}
    }.

get_authdata(#{authority := AuthorityId} = VerifiedToken, Storages) ->
    case tktor_storage:get_authdata(VerifiedToken, maps:get(AuthorityId, Storages)) of
        {ok, AuthData} ->
            {ok, maybe_add_authority_id(AuthData, AuthorityId)};
        {error, _} = Error ->
            Error
    end.

maybe_add_authority_id(AuthData = #{authority := _}, _AuthorityID) ->
    AuthData;
maybe_add_authority_id(AuthData, AuthorityID) ->
    AuthData#{authority => AuthorityID}.

%%

decode_source_context(#token_keeper_TokenSourceContext{
    request_origin = RequestOrigin
}) ->
    genlib_map:compact(#{
        request_origin => RequestOrigin
    }).

encode_auth_data(
    #{
        token := Token,
        status := Status,
        context := Context,
        authority := Authority
    } = AuthData
) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = Token,
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{}),
        authority = Authority
    }.

%%

save_pulse_metadata(Metadata, State = #state{pulse_metadata = PulseMetadata}) ->
    State#state{pulse_metadata = maps:merge(Metadata, PulseMetadata)}.

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

pulse_op_failed(Op, Reason, State) ->
    handle_beat(Op, {failed, Reason}, State).

handle_beat(Op, Event, State) ->
    token_keeper_pulse:handle_beat({Op, Event}, State#state.pulse_metadata, State#state.pulse).
