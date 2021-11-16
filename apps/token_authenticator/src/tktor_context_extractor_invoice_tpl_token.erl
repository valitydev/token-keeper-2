-module(tktor_context_extractor_invoice_tpl_token).

%% NOTE:
%% This is here because of a historical decision to make InvoiceTemplateAccessToken(s) never expire,
%% therefore a lot of them do not have a standart bouncer context claim built-in.
%% It is advisable to get rid of this exctractor when this issue will be solved.

-behaviour(tktor_context_extractor).

-export([extract_context/2]).

%%

-type opts() :: #{
    domain := binary(),
    metadata_mappings := #{
        party_id := binary()
    }
}.

-export_type([opts/0]).

%%

-define(CLAIM_PARTY_ID, <<"sub">>).
-define(CLAIM_RESOURCE_ACCESS, <<"resource_access">>).

%% API functions

-spec extract_context(tktor_token:verified_token(), opts()) -> tktor_context_extractor:extracted_context() | undefined.
extract_context(#{id := TokenID, payload := Payload}, Opts) ->
    PartyID = maps:get(?CLAIM_PARTY_ID, Payload),
    case extract_invoice_template_rights(Payload, Opts) of
        {ok, InvoiceTemplateID} ->
            BCtx = create_bouncer_ctx(TokenID, PartyID, InvoiceTemplateID),
            {BCtx,
                make_metadata(
                    #{
                        %% @TEMP: This is a temporary hack.
                        %% When some external services will stop requiring woody user
                        %% identity to be present it must be removed too
                        party_id => PartyID
                    },
                    Opts
                )};
        {error, Reason} ->
            _ = logger:warning("Failed to extract invoice template rights: ~p", [Reason]),
            undefined
    end.

%%

extract_invoice_template_rights(TokenPayload, Opts) ->
    Domain = maps:get(domain, Opts),
    case get_acl(Domain, get_resource_hierarchy(), TokenPayload) of
        {ok, TokenACL} ->
            match_invoice_template_acl(TokenACL);
        {error, Reason} ->
            {error, {acl, Reason}}
    end.

match_invoice_template_acl(TokenACL) ->
    Patterns = [
        fun({[party, {invoice_templates, ID}], [read]}) -> ID end,
        fun({[party, {invoice_templates, ID}, invoice_template_invoices], [write]}) -> ID end
    ],
    case match_acl(Patterns, TokenACL) of
        [[InvoiceTemplateID], [InvoiceTemplateID]] ->
            {ok, InvoiceTemplateID};
        Matches ->
            {error, {acl_mismatch, Matches}}
    end.

match_acl(Patterns, TokenACL) ->
    [match_acl_pattern(TokenACL, Pat) || Pat <- Patterns].

match_acl_pattern(TokenACL, Pat) ->
    lists:usort([Match || Entry <- TokenACL, Match <- run_pattern(Entry, Pat)]).

run_pattern(Entry, Pat) when is_function(Pat, 1) ->
    try
        [Pat(Entry)]
    catch
        error:function_clause -> []
    end.

get_acl(Domain, Hierarchy, TokenPayload) ->
    case maps:get(?CLAIM_RESOURCE_ACCESS, TokenPayload, undefined) of
        #{Domain := #{<<"roles">> := Roles}} ->
            try
                TokenACL = tktor_legacy_acl:decode(Roles, Hierarchy),
                {ok, tktor_legacy_acl:to_list(TokenACL)}
            catch
                error:Reason -> {error, {invalid, Reason}}
            end;
        _ ->
            {error, missing}
    end.

create_bouncer_ctx(TokenID, PartyID, InvoiceTemplateID) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"InvoiceTemplateAccessToken">>,
            token => #{id => TokenID},
            scope => [
                #{
                    party => #{id => PartyID},
                    invoice_template => #{id => InvoiceTemplateID}
                }
            ]
        },
        bouncer_context_helpers:empty()
    ).

make_metadata(Metadata, ExtractorOpts) ->
    Mappings = maps:get(metadata_mappings, ExtractorOpts),
    token_keeper_utils:remap(genlib_map:compact(Metadata), Mappings).

get_resource_hierarchy() ->
    #{
        party => #{invoice_templates => #{invoice_template_invoices => #{}}}
    }.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-define(TEST_ACL, [
    {some_other_stuff, 123, <<"abc">>},
    {second, <<"abc">>},
    {doubles, 123},
    more_stuff,
    {test_acl, 123},
    {doubles, 456},
    {first, 123}
]).

-spec match_acl_base_test() -> _.

match_acl_base_test() ->
    [[123]] = match_acl(
        [
            fun({test_acl, Int}) -> Int end
        ],
        ?TEST_ACL
    ).

-spec match_acl_dupes_test() -> _.

match_acl_dupes_test() ->
    [[123, 456]] = match_acl(
        [
            fun({doubles, Int}) -> Int end
        ],
        ?TEST_ACL
    ).

-spec match_acl_order_test() -> _.

match_acl_order_test() ->
    [[123], [<<"abc">>]] = match_acl(
        [
            fun({first, Int}) -> Int end,
            fun({second, Bin}) -> Bin end
        ],
        ?TEST_ACL
    ).

-spec match_acl_no_match_test() -> _.

match_acl_no_match_test() ->
    [[], []] = match_acl(
        [
            fun({foo, _}) -> wait end,
            fun({bar, _, _}) -> no end
        ],
        ?TEST_ACL
    ).

-endif.
