-module(tk_blacklist).

-behaviour(supervisor).

%% API

-export([is_blacklisted/2]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%%

-type options() :: #{
    %% Path to blacklist file
    path => binary()
}.

-export_type([options/0]).

%%

-define(TERM_KEY, {?MODULE, mappings}).

%%

-spec child_spec(options()) -> supervisor:child_spec() | no_return().
child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec is_blacklisted(tk_token:token_id(), tk_authdata:authority_id()) -> boolean().
is_blacklisted(TokenID, AuthorityID) ->
    match_entry(AuthorityID, TokenID, get_entires()).

%%

match_entry(AuthorityID, Token, Entries) ->
    case maps:get(AuthorityID, Entries, undefined) of
        AuthorityEntries when AuthorityEntries =/= undefined ->
            lists:member(Token, AuthorityEntries);
        undefined ->
            false
    end.

%%

-spec init(options()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Options) ->
    _ = load_blacklist_conf(maps:get(path, Options, undefined)),
    {ok, {#{}, []}}.

-define(ENTRIES_KEY, "entries").

load_blacklist_conf(undefined) ->
    _ = logger:warning("No token blacklist file specified! Blacklisting functionality will be disabled."),
    put_entires(#{});
load_blacklist_conf(Filename) ->
    [Mappings] = yamerl_constr:file(Filename),
    Entries = process_entries(proplists:get_value(?ENTRIES_KEY, Mappings)),
    put_entires(Entries).

process_entries(Entries) ->
    lists:foldl(
        fun({K, V}, Acc) ->
            Acc#{list_to_binary(K) => [list_to_binary(V0) || V0 <- V]}
        end,
        #{},
        Entries
    ).

%%

put_entires(Entries) ->
    persistent_term:put(?TERM_KEY, Entries).

get_entires() ->
    persistent_term:get(?TERM_KEY).