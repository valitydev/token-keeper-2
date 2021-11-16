-module(tktor_authdata).

-export([from_prototype/2]).

%%

-type prototype() :: #{
    id => id(),
    status := status(),
    context := encoded_context_fragment(),
    authority => token_authenticator:authority_id(),
    metadata => metadata()
}.

-type id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{binary() => binary()}.

-export_type([prototype/0]).
-export_type([id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).

%%

-type token() :: tktor_token:token_string().

-type t() :: #{
    id => id(),
    token := token(),
    status := status(),
    context := encoded_context_fragment(),
    authority := token_authenticator:authority_id(),
    metadata => metadata()
}.

%%

-spec from_prototype(prototype(), token()) -> t().
from_prototype(#{status := _, context := _, authority := _} = Prototype, Token) ->
    Prototype#{token => Token}.
