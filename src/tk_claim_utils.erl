-module(tk_claim_utils).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([decode_authdata/1]).
-export([encode_authdata/1]).

-export([decode_bouncer_claim/1]).
-export([encode_bouncer_claim/1]).

%%

-type authdata() :: tk_authdata:prototype().
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().

-type claim() :: term().
-type claims() :: tk_token:payload().

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_TK_METADATA, <<"tk_metadata">>).

-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).
-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

%%

-spec decode_authdata(claims()) ->
    {ok, authdata()}
    | {error, not_found | {claim_decode_error, {unsupported, claim()} | {malformed, binary()}}}.
decode_authdata(#{?CLAIM_BOUNCER_CTX := BouncerClaim} = Claims) ->
    case decode_bouncer_claim(BouncerClaim) of
        {ok, ContextFragment} ->
            case get_metadata(Claims) of
                {ok, Metadata} ->
                    {ok, create_authdata(ContextFragment, Metadata)};
                {error, no_metadata_claim} ->
                    {error, not_found}
            end;
        {error, Reason} ->
            {error, {claim_decode_error, Reason}}
    end;
decode_authdata(_Claims) ->
    {error, not_found}.

-spec encode_authdata(authdata()) -> claims().
encode_authdata(#{context := ContextFragment} = AuthData) ->
    #{
        ?CLAIM_BOUNCER_CTX => encode_bouncer_claim(ContextFragment),
        ?CLAIM_TK_METADATA => encode_metadata(AuthData)
    }.

%%

-spec decode_bouncer_claim(claims()) -> {ok, encoded_context_fragment()} | {error, {malformed, binary()}}.
decode_bouncer_claim(#{
    ?CLAIM_CTX_TYPE := ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
    ?CLAIM_CTX_CONTEXT := Content
}) ->
    try
        {ok, #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = base64:decode(Content)
        }}
    catch
        % NOTE
        % The `base64:decode/1` fails in unpredictable ways.
        error:_ ->
            {error, {malformed, Content}}
    end;
decode_bouncer_claim(Ctx) ->
    {error, {unsupported, Ctx}}.

-spec encode_bouncer_claim(encoded_context_fragment()) -> claims().
encode_bouncer_claim(
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = Content
    }
) ->
    #{
        ?CLAIM_CTX_TYPE => ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
        ?CLAIM_CTX_CONTEXT => base64:encode(Content)
    }.

%%

encode_metadata(#{metadata := Metadata}) ->
    Metadata;
encode_metadata(#{}) ->
    #{}.

get_metadata(#{?CLAIM_TK_METADATA := Metadata}) ->
    {ok, Metadata};
get_metadata(_Claims) ->
    {error, no_metadata_claim}.

create_authdata(ContextFragment, Metadata) ->
    #{
        context => ContextFragment,
        metadata => Metadata
    }.
