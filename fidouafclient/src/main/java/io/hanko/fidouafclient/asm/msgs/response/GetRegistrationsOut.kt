package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class GetRegistrationsOut (
    val appRegs: List<AppRegistration>
)
