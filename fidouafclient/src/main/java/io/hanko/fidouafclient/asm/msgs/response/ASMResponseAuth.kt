package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.client.msg.Extension

@JsonClass(generateAdapter = true)
class ASMResponseAuth
(
        override val statusCode: Short, // id of type ASM-StatusCode
        val responseData: AuthenticateOut,
        override val exts: List<Extension>?
) : ASMResponse(statusCode, exts)
