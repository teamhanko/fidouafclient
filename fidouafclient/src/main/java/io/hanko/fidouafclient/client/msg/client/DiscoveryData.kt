package io.hanko.fidouafclient.client.msg.client

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.authenticator.msgs.Authenticator
import io.hanko.fidouafclient.client.msg.Version

@JsonClass(generateAdapter = true)
class DiscoveryData (
    val supportedUAFVersions: List<Version>,
    val clientVendor: String,
    val clientVersion: Version,
    val availableAuthenticators: List<Authenticator>
)
