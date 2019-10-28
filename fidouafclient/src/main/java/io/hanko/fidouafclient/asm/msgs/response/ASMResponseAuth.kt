package io.hanko.fidouafclient.asm.msgs.response

import io.hanko.fidouafclient.client.msg.Extension

class ASMResponseAuth
(
        override val statusCode: Short, // id of type ASM-StatusCode
        val responseData: AuthenticateOut,
        override val exts: List<Extension>?
) : ASMResponse(statusCode, exts)
