package io.hanko.fidouafclient.asm.msgs.response

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.client.msg.Extension

@JsonClass(generateAdapter = true)
class ASMResponseGetInfo (
        override val statusCode: Short, // id of type ASM-StatusCode
        val responseData: GetInfoOut,
        override val exts: List<Extension>?
): ASMResponse(statusCode, exts)
