package io.hanko.fidouafclient.asm.msgs.response

import io.hanko.fidouafclient.client.msg.Extension

open class ASMResponse (
    open val statusCode: Short, // id of type ASM-StatusCode
    open val exts: List<Extension>?
)
