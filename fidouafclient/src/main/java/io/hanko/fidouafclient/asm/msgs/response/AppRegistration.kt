package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class AppRegistration (
    val appID: String,
    val keyIDs: List<String>
)
