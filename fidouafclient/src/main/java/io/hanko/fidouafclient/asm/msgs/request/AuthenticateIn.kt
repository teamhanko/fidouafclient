package io.hanko.fidouafclient.asm.msgs.request

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.client.msg.Transaction

@JsonClass(generateAdapter = true)
data class AuthenticateIn (
    val appID: String,
    val keyIDs: List<String>,
    val finalChallenge: String,
    val transaction: Transaction?
)
