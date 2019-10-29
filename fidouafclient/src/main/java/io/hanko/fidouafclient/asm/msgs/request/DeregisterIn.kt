package io.hanko.fidouafclient.asm.msgs.request

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class DeregisterIn(val appID: String, val keyID: String)
