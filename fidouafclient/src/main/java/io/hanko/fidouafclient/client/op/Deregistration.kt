package io.hanko.fidouafclient.client.op

import android.util.Log
import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg
import io.hanko.fidouafclient.asm.msgs.request.DeregisterIn
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.client.msg.UafDeregistrationRequest
import io.hanko.fidouafclient.client.msg.Version
import io.hanko.fidouafclient.client.msg.client.ErrorCode
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.util.ClientUtil
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Util
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class Deregistration(val facetId: String, val channelBinding: String) {

    private val mainScope = CoroutineScope(Dispatchers.Main + Job())

    fun processRequests(deregistrationRequests: List<UafDeregistrationRequest>, sendToAsm: (String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit, skipTrustedFacetValidation: Boolean) {
        val deregistrationRequest = deregistrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 1 }
                ?: deregistrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 0 }

        if (deregistrationRequest == null) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNSUPPORTED_VERSION, null)
            return
        } else if (deregistrationRequest.authenticators.any { if (it.aaid.isNotEmpty() && it.keyID.isNotEmpty()) !isValidAAID(it.aaid) || !Util.isBase64UrlEncoded(it.keyID) else if (it.aaid.isNotEmpty() && it.keyID.isEmpty()) !isValidAAID(it.aaid) else false }) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            return
        } else if (deregistrationRequest.header.appID == null || deregistrationRequest.header.appID.isEmpty() || deregistrationRequest.header.appID == facetId) {
            sendToAsm(facetId, deregistrationRequest, sendToAsm, sendReturnIntent)
        } else if (Util.isValidHttpsUrl(deregistrationRequest.header.appID)) {
            if (skipTrustedFacetValidation) {
                this.sendToAsm(deregistrationRequest.header.appID, deregistrationRequest, sendToAsm, sendReturnIntent)
            } else {
                mainScope.launch {
                    val trustedFacets = ClientUtil.getTrustedFacetsAsync(deregistrationRequest.header.appID)
                    if (trustedFacets != null && ClientUtil.isFacetIdValid(trustedFacets, Version(1, 0), facetId))
                        this@Deregistration.sendToAsm(deregistrationRequest.header.appID, deregistrationRequest, sendToAsm, sendReturnIntent)
                    else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null)
                }
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }

        //////////////////////////////////////////////////////////////
        val appID = if (deregistrationRequest.header.appID == null || deregistrationRequest.header.appID.isEmpty()) {
            facetId
        } else {
            deregistrationRequest.header.appID
        }

        if (Util.isValidHttpsUrl(appID)) {
            if (skipTrustedFacetValidation) {
                this.sendToAsm(appID, deregistrationRequest, sendToAsm, sendReturnIntent)
            } else {
                mainScope.launch {
                    val trustedFacets = ClientUtil.getTrustedFacetsAsync(appID)
                    if (trustedFacets != null && ClientUtil.isFacetIdValid(trustedFacets, Version(1, 0), facetId))
                        this@Deregistration.sendToAsm(appID, deregistrationRequest, sendToAsm, sendReturnIntent)
                    else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null)
                }
            }
        } else {
            this.sendToAsm(appID, deregistrationRequest, sendToAsm, sendReturnIntent)
        }
    }

    private fun isValidAAID(aaid: String): Boolean {
        val regex = "^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$".toRegex()
        return regex.matches(aaid)
    }

    fun processASMResponse(sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, "[{}]")
    }

    private fun sendToAsm(appID: String, deregistrationRequest: UafDeregistrationRequest, sendToAsm: (String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        val deleteAllKeys = deregistrationRequest.authenticators.any {
            (it.aaid.isEmpty() && it.keyID.isEmpty()) ||
                    (it.aaid == AuthenticatorMetadata.authenticator.aaid && it.keyID.isEmpty())
        }
        val relevantKeyIds = deregistrationRequest.authenticators.filter { it.aaid == AuthenticatorMetadata.authenticator.aaid }.map { it.keyID }
        val deregisterIn = if (deleteAllKeys) {
            Crypto.getStoredKeyIds(appID, null)?.map { DeregisterIn(appID, it) } ?: emptyList()
        } else {
            relevantKeyIds.map { DeregisterIn(appID, it) }
        }

        if (deregisterIn.isEmpty()) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, "[{}]")
        } else {
            val asmRequestDereg = ASMRequestDereg(
                    requestType = RequestType.Deregister,
                    asmVersion = deregistrationRequest.header.upv,
                    authenticatorIndex = 0,
                    args = deregisterIn,
                    exts = null
            )

            try {
                sendToAsm(Util.objectMapper.writeValueAsString(asmRequestDereg))
            } catch (ex: Exception) {
                Log.e("Deregistration", "Error while sending asmDeregRequest to ASM", ex)
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null)
            }
        }
    }
}
