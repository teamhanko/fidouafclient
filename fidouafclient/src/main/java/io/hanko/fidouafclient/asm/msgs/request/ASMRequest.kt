package io.hanko.fidouafclient.asm.msgs.request

import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.client.msg.Extension
import io.hanko.fidouafclient.client.msg.Version
import io.hanko.fidouafclient.util.Util

open class ASMRequest(open val requestType: RequestType, open val asmVersion: Version) {
    companion object {
        fun fromJson(json: String): ASMRequest {
            val request = Util.objectMapper.readValue(json, ASMRequest::class.java)

            return when (request.requestType) {
                RequestType.Register -> Util.objectMapper.readValue(json, ASMRequestReg::class.java)
                RequestType.Authenticate -> Util.objectMapper.readValue(json, ASMRequestAuth::class.java)
                RequestType.Deregister -> Util.objectMapper.readValue(json, ASMRequestDereg::class.java)
                else -> request
            }
        }
    }
}

class ASMRequestReg(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: RegisterIn,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)

data class ASMRequestAuth(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: AuthenticateIn,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)

class ASMRequestDereg(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: List<DeregisterIn>,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)