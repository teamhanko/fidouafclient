package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.client.msg.Extension

@JsonClass(generateAdapter = true)
open class ASMResponse (
    open val statusCode: Short, // id of type ASM-StatusCode
    open val exts: List<Extension>?
)
