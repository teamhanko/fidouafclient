package io.hanko.fidouafclient.client.msg.trustedFacets;

import com.fasterxml.jackson.annotation.JsonProperty

class TrustedFacetsList (
    @JsonProperty(required = true) val trustedFacets: List<TrustedFacets>
)
