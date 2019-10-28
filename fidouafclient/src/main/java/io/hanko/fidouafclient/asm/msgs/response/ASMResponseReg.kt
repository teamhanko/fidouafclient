package io.hanko.fidouafclient.asm.msgs.response

import io.hanko.fidouafclient.client.msg.Extension

class ASMResponseReg(
        override val statusCode: Short, // id of type ASM-StatusCode
        val responseData: RegisterOut,
        override val exts: List<Extension>?
) : ASMResponse(statusCode, exts)
