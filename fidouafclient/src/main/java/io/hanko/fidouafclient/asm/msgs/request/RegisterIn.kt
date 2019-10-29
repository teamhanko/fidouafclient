package io.hanko.fidouafclient.asm.msgs.request;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class RegisterIn (
    val appID: String,
    val username: String,
    val finalChallenge: String,
    val attestationType: Short
)
