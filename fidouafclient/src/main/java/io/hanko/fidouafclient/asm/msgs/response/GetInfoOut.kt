package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class GetInfoOut (
    val Authenticators: List<AuthenticatorInfo>
)
