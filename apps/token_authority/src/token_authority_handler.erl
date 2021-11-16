-module(token_authority_handler).

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

-type opts() :: #{
    pulse => token_keeper_pulse:handlers()
}.

-record(state, {
    woody_context :: woody_context:ctx(),
    pulse :: token_keeper_pulse:handlers(),
    pulse_metadata :: token_keeper_pulse:metadata()
}).

%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()} | no_return().
handle_function(Op, Args, WoodyCtx, Opts) ->
    State = make_state(WoodyCtx, Opts),
    handle_function_(Op, Args, State).

handle_function_('Create' = Op, {_ID, _ContextFragment, _Metadata}, State) ->
    %% Create - создает новую AuthData, используя переданные в качестве
    %% аргументов данные и сохраняет их в хранилище, после чего выписывает
    %% новый JWT-токен, в котором содержится AuthDataID (на данный момент
    %% предполагается, что AuthDataID == jwt-клейму “JTI”). По умолчанию
    %% status токена - active; authority - id выписывающей authority.
    _ = handle_beat(Op, started, State);
% AuthorityConf = get_autority_config(get_issuing_authority()),
% AuthData = issue_auth_data(ID, ContextFragment, Metadata, AuthorityConf),
% case store(AuthData, build_context(State)) of
%     ok ->
%         {ok, Token} = tk_token_jwt:issue(ID, #{}, get_signer(AuthorityConf)),
%         EncodedAuthData = encode_auth_data(AuthData#{token => Token}),
%         _ = handle_beat(Op, succeeded, State),
%         {ok, EncodedAuthData};
%     {error, exists} ->
%         _ = handle_beat(Op, {failed, exists}, State),
%         woody_error:raise(business, #token_keeper_AuthDataAlreadyExists{})
% end;
handle_function_('Get' = Op, {_ID}, State) ->
    _ = handle_beat(Op, started, State);
% case get_authdata_by_id(ID, build_context(State)) of
%     {ok, AuthData} ->
%         EncodedAuthData = encode_auth_data(AuthData),
%         _ = handle_beat(Op, succeeded, State),
%         {ok, EncodedAuthData};
%     {error, Reason} ->
%         _ = handle_beat(Op, {failed, Reason}, State),
%         woody_error:raise(business, #token_keeper_AuthDataNotFound{})
% end;
handle_function_('Revoke' = Op, {_ID}, State) ->
    _ = handle_beat(Op, started, State).
% case revoke(ID, build_context(State)) of
%     ok ->
%         _ = handle_beat(Op, succeeded, State),
%         {ok, ok};
%     {error, notfound} ->
%         _ = handle_beat(Op, {failed, notfound}, State),
%         woody_error:raise(business, #token_keeper_AuthDataNotFound{})
% end.

%% Internal functions

% issue_auth_data(ID, ContextFragment, Metadata, {_, Authority}) ->
%     tk_authority:create_authdata(ID, ContextFragment, Metadata, Authority).

% %%

% build_context(#state{woody_context = WC}) ->
%     #{woody_ctx => WC}.

make_state(WoodyCtx, Opts) ->
    #state{
        woody_context = WoodyCtx,
        pulse = maps:get(pulse, Opts, []),
        pulse_metadata = #{woody_ctx => WoodyCtx}
    }.

% %%

% get_authdata_by_id(ID, Ctx) ->
%     tk_storage:get(ID, Ctx).

% store(AuthData, Ctx) ->
%     tk_storage:store(AuthData, Ctx).

% revoke(ID, Ctx) ->
%     tk_storage:revoke(ID, Ctx).

% %%

% encode_auth_data(AuthData) ->
%     #token_keeper_AuthData{
%         id = maps:get(id, AuthData, undefined),
%         token = maps:get(token, AuthData, undefined),
%         status = maps:get(status, AuthData),
%         context = maps:get(context, AuthData),
%         metadata = maps:get(metadata, AuthData, #{}),
%         authority = maps:get(authority, AuthData, undefined)
%     }.

% get_signer({AuthorityID, AuthorityConf}) ->
%     SignerKID = tk_authority:get_signer(AuthorityConf),
%     case tk_token_jwt:get_key_authority(SignerKID) of
%         {ok, AuthorityID} ->
%             SignerKID;
%         {ok, OtherAuthorityID} ->
%             error({misconfiguration, {issuing, {key_ownership_error, {AuthorityID, OtherAuthorityID}}}});
%         _ ->
%             error({misconfiguration, {issuing, {no_key, SignerKID}}})
%     end.

% get_autority_config(AuthorityID) ->
%     Authorities = application:get_env(token_keeper, authorities, #{}),
%     case maps:get(AuthorityID, Authorities, undefined) of
%         Config when Config =/= undefined ->
%             {AuthorityID, Config};
%         undefined ->
%             throw({misconfiguration, {no_such_authority, AuthorityID}})
%     end.

% get_issuing_authority() ->
%     maps:get(authority, get_issuing_config()).

% get_issuing_config() ->
%     case application:get_env(token_keeper, issuing, undefined) of
%         Config when Config =/= undefined ->
%             Config;
%         undefined ->
%             error({misconfiguration, {issuing, not_configured}})
%     end.

% %%

handle_beat(Op, Event, State) ->
    token_keeper_pulse:handle_beat({encode_pulse_op(Op), Event}, State#state.pulse_metadata, State#state.pulse).

encode_pulse_op('Create') ->
    create;
encode_pulse_op('Get') ->
    get;
encode_pulse_op('Revoke') ->
    revoke.
