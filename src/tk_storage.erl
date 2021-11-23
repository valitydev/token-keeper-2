-module(tk_storage).

-export([get/2]).
-export([store/2]).
-export([revoke/2]).

%%

-callback get(authdata_id(), storage_opts(), tk_handler:ctx()) -> {ok, authdata()} | {error, _Reason}.
-callback store(authdata(), storage_opts(), tk_handler:ctx()) -> ok | {error, _Reason}.
-callback revoke(authdata_id(), storage_opts(), tk_handler:ctx()) -> ok | {error, _Reason}.

%%

-type authdata() :: tk_authdata:prototype().
-type authdata_id() :: tk_authdata:id().

-type storage_type() :: machinegun.
-type storage_opts() :: tk_storage_machinegun:storage_opts().

-type storage_config() :: machinegun_storage_config().
-type machinegun_storage_config() :: {machinegun, tk_storage_machinegun:storage_opts()}.

%%

-spec get(authdata_id(), tk_handler:ctx()) -> {ok, authdata()} | {error, _Reason}.
get(AuthDataID, Ctx) ->
    call(get, AuthDataID, get_storage_config(), Ctx).

-spec store(authdata(), tk_handler:ctx()) -> ok | {error, exists}.
store(AuthData, Ctx) ->
    call(store, AuthData, get_storage_config(), Ctx).

-spec revoke(authdata_id(), tk_handler:ctx()) -> ok | {error, notfound}.
revoke(AuthDataID, Ctx) ->
    call(revoke, AuthDataID, get_storage_config(), Ctx).

%%

-spec get_storage_config() -> storage_config().
get_storage_config() ->
    %% No other storages are supported
    {machinegun, #{}}.

-spec get_storage_handler(storage_type()) -> machinery:logic_handler(_).
get_storage_handler(machinegun) ->
    tk_storage_machinegun.

call(Func, Operand, {Storage, Opts}, Ctx) ->
    Handler = get_storage_handler(Storage),
    Handler:Func(Operand, Opts, Ctx).
