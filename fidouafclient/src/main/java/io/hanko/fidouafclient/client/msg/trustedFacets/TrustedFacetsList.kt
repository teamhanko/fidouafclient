package io.hanko.fidouafclient.client.msg.trustedFacets;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class TrustedFacetsList(
        val trustedFacets: List<TrustedFacets>
)
