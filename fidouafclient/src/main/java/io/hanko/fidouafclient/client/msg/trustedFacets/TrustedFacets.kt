package io.hanko.fidouafclient.client.msg.trustedFacets

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.client.msg.Version

@JsonClass(generateAdapter = true)
class TrustedFacets (
    val version: Version?,
    val ids: List<String>?
)
