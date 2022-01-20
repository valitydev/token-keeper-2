-module(tk_ct_config).

%% Super basic config helper

-export([authenticator/2]).
-export([authorities/1]).
-export([ephemeral_authority/2]).
-export([offline_authority/3]).
-export([jwt_tokens/2]).
-export([blacklist/1]).
-export([storages/1]).
-export([machinegun_storage/2]).

-type authoritites() :: #{binary() => tk_handler:authority_opts()}.

%%

-spec authenticator(binary(), map()) -> {authenticator, tk_handler:authenticator_opts()}.
authenticator(HandlerPath, Authorities) ->
    {authenticator, #{
        service => #{
            path => HandlerPath
        },
        authorities => make_authenticator_authoritites(Authorities)
    }}.

-spec authorities(authoritites()) -> {authorities, authoritites()}.
authorities(Authorities) ->
    {authorities, Authorities}.

-spec ephemeral_authority(binary(), atom()) -> tk_handler:authority_opts().
ephemeral_authority(Path, TokenType) ->
    make_authority(
        Path,
        {ephemeral, #{
            token => #{
                type => TokenType
            }
        }}
    ).

-spec offline_authority(binary(), atom(), binary()) -> tk_handler:authority_opts().
offline_authority(Path, TokenType, StorageName) ->
    make_authority(
        Path,
        {offline, #{
            token => #{
                type => TokenType
            },
            storage => #{
                name => StorageName
            }
        }}
    ).

-spec jwt_tokens(any(), any()) -> any().
jwt_tokens(Bindings, Keyset) ->
    {tokens, #{
        jwt => #{
            authority_bindings => Bindings,
            keyset => make_jwt_keyset(Keyset)
        }
    }}.

-spec blacklist(any()) -> any().
blacklist(Path) ->
    {blacklist, #{
        path => Path
    }}.

-spec storages(any()) -> any().
storages(Authorities) ->
    {storages, Authorities}.

-spec machinegun_storage(any(), any()) -> any().
machinegun_storage(Namespace, Url) ->
    {machinegun, #{
        namespace => Namespace,
        automaton => #{
            url => Url,
            event_handler => [scoper_woody_event_handler],
            transport_opts => #{}
        }
    }}.

%%

make_authority(Path, Type) ->
    #{
        service => #{
            path => Path
        },
        type => Type
    }.

make_authenticator_authoritites(Authorities) ->
    maps:map(
        fun(_, Sources) ->
            #{sources => Sources}
        end,
        Authorities
    ).

make_jwt_keyset(Keyset) ->
    maps:map(
        fun(_, Source) ->
            #{source => Source}
        end,
        Keyset
    ).
