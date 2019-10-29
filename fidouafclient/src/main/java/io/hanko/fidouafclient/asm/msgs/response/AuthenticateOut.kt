package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class AuthenticateOut (
    val assertion: String,
    val assertionScheme: String
)
