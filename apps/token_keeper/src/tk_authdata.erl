-module(tk_authdata).

-export([create_prototype/4]).

%%

-type prototype() :: #{
    id => id(),
    status := status(),
    context := encoded_context_fragment(),
    authority => authority_id(),
    metadata => metadata()
}.

-type id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type authority_id() :: binary().
-type metadata() :: #{binary() => binary()}.

-export_type([prototype/0]).
-export_type([id/0]).
-export_type([status/0]).
-export_type([authority_id/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).

%%

-spec create_prototype(id() | undefined, encoded_context_fragment(), metadata(), authority_id()) -> prototype().
create_prototype(ID, ContextFragment, Metadata, Authority) ->
    AuthData = #{
        status => active,
        context => ContextFragment,
        metadata => Metadata,
        authority => Authority
    },
    add_id(AuthData, ID).

%%

add_id(AuthData, undefined) ->
    AuthData;
add_id(AuthData, ID) ->
    AuthData#{id => ID}.
