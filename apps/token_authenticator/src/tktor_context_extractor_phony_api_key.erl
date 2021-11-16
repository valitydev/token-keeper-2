-module(tktor_context_extractor_phony_api_key).
-behaviour(tktor_context_extractor).

-export([extract_context/2]).

%%

-type opts() :: #{
    metadata_mappings := #{
        party_id := binary()
    }
}.

-export_type([opts/0]).

%%

-define(CLAIM_PARTY_ID, <<"sub">>).

%% API functions

-spec extract_context(tktor_token:verified_token(), opts()) -> tktor_context_extractor:extracted_context() | undefined.
extract_context(#{id := TokenID, payload := Payload}, Opts) ->
    PartyID = maps:get(?CLAIM_PARTY_ID, Payload),
    ContextFragment = bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => TokenID},
            scope => [#{party => #{id => PartyID}}]
        },
        bouncer_context_helpers:empty()
    ),
    {ContextFragment,
        make_metadata(
            #{
                party_id => PartyID
            },
            Opts
        )}.

%%

make_metadata(Metadata, Opts) ->
    Mappings = maps:get(metadata_mappings, Opts),
    token_keeper_utils:remap(genlib_map:compact(Metadata), Mappings).
