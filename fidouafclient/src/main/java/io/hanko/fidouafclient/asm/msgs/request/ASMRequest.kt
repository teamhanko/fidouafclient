package io.hanko.fidouafclient.asm.msgs.request

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.client.msg.Extension
import io.hanko.fidouafclient.client.msg.Version
import io.hanko.fidouafclient.util.Util

@JsonClass(generateAdapter = true)
open class ASMRequest(open val requestType: RequestType, open val asmVersion: Version) {
    companion object {
        fun fromJson(json: String): ASMRequest {
            val request = Util.moshi.adapter(ASMRequest::class.java).fromJson(json)!!


            return when (request.requestType) {
                RequestType.Register -> Util.moshi.adapter(ASMRequestReg::class.java).fromJson(json)!!
                RequestType.Authenticate -> Util.moshi.adapter(ASMRequestAuth::class.java).fromJson(json)!!
                RequestType.Deregister -> Util.moshi.adapter(ASMRequestDereg::class.java).fromJson(json)!!
                else -> request
            }
        }
    }
}

@JsonClass(generateAdapter = true)
class ASMRequestReg(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: RegisterIn,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)

@JsonClass(generateAdapter = true)
data class ASMRequestAuth(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: AuthenticateIn,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)

@JsonClass(generateAdapter = true)
class ASMRequestDereg(
        override val requestType: RequestType,
        override val asmVersion: Version,
        val authenticatorIndex: Short,
        val args: List<DeregisterIn>,
        val exts: List<Extension>?
): ASMRequest(requestType, asmVersion)