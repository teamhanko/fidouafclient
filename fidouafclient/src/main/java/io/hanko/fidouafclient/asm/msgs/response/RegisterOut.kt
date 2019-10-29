package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class RegisterOut (
    val assertion: String,
    val assertionScheme: String
)
