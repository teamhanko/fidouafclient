package io.hanko.fidouafclient.asm.msgs.response

import io.hanko.fidouafclient.client.msg.Extension

class ASMResponseGetInfo (
        override val statusCode: Short, // id of type ASM-StatusCode
        val responseData: GetInfoOut,
        override val exts: List<Extension>?
): ASMResponse(statusCode, exts)
