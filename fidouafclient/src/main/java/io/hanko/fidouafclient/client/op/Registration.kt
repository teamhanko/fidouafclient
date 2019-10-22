package io.hanko.fidouafclient.client.op;

import android.util.Base64
import android.util.Log
import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg
import io.hanko.fidouafclient.asm.msgs.request.RegisterIn
import io.hanko.fidouafclient.asm.msgs.response.RegisterOut
import io.hanko.fidouafclient.client.msg.*
import io.hanko.fidouafclient.client.msg.client.ErrorCode
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.util.ClientUtil
import io.hanko.fidouafclient.util.Util
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets
import java.util.*

class Registration(val facetId: String, val channelBinding: String) {

    private val TAG: String = "Registration"
    private var registrationRequest: UafRegistrationRequest? = null
    private var appID: String? = null
    private var finalChallengeParams: FinalChallengeParams? = null
    private val mainScope = CoroutineScope(Dispatchers.Main + Job())

    fun processRequests(registrationRequests: List<UafRegistrationRequest>, sendToAsm: (message: String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit, skipTrustedFacetValidation: Boolean) {
        val regRequest = registrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 1 }
                ?: registrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 0 }
        registrationRequest = regRequest

        val challengeBytes = Base64.decode(regRequest?.challenge ?: "", Base64.URL_SAFE)

        if (regRequest == null) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNSUPPORTED_VERSION, null)
        } else if (regRequest.policy.accepted.any { it.any { !it.isValid() } } ||
                regRequest.policy.disallowed?.any { !it.isValid() } == true ||
                regRequest.policy.accepted.isEmpty() ||
                challengeBytes.size < 8 || challengeBytes.size > 64) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        } else if (regRequest.header.appID == null || regRequest.header.appID.isEmpty() || Objects.equals(regRequest.header.appID, facetId)) {
            appID = facetId
            this.sendToAsm(regRequest, sendToAsm, sendReturnIntent)
        } else if (Util.isValidHttpsUrl(regRequest.header.appID)) {
            appID = regRequest.header.appID
            if (skipTrustedFacetValidation) {
                this.sendToAsm(regRequest, sendToAsm, sendReturnIntent)
            } else {
                mainScope.launch {
                    val trustedFacets = ClientUtil.getTrustedFacetsAsync(appID!!)
                    if (trustedFacets != null && ClientUtil.isFacetIdValid(trustedFacets, Version(1, 0), facetId))
                        this@Registration.sendToAsm(regRequest, sendToAsm, sendReturnIntent)
                    else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null)
                }
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    fun processASMResponse(registerOut: RegisterOut, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        val registrationAssertion = AuthenticatorRegistrationAssertion(
                assertionScheme = registerOut.assertionScheme,
                assertion = registerOut.assertion,
                tcDisplayPNGCharacteristics = null,
                exts = null)

        val registrationResponse = listOf(RegistrationResponse(
                registrationRequest!!.header,
                Base64.encodeToString(Util.objectMapper.writeValueAsString(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
                Collections.singletonList(registrationAssertion)
        ))

        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, Util.objectMapper.writeValueAsString(registrationResponse))
    }

    private fun sendToAsm(registrationRequest: UafRegistrationRequest, sendToAsm: (message: String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        finalChallengeParams = FinalChallengeParams(
                appID!!,
                registrationRequest.challenge,
                facetId,
                Util.objectMapper.readValue(channelBinding, ChannelBinding::class.java)
        )

        val registerIn = RegisterIn()
        registerIn.attestationType = 15880 // Attestation Surrogate
        registerIn.username = registrationRequest.username
        registerIn.appID = appID
        registerIn.finalChallenge = Base64.encodeToString(Util.objectMapper.writeValueAsString(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        val asmRequestReg = ASMRequestReg(
                requestType = RequestType.Register,
                asmVersion = registrationRequest.header.upv,
                authenticatorIndex = 0,
                args = registerIn,
                exts = null
        )

        try { // try-catch as workaround for Huawei smartphones, because they won´t call method
            sendToAsm(Util.objectMapper.writeValueAsString(asmRequestReg)) //, MainASM_REG_REQUEST_CODE, ClientUtil.getAsmFromPolicy(registrationRequest.policy, appID!!))
        } catch (ex: Exception) {
            Log.e(TAG, "Error while sending asmRegistrationRequest to ASM", ex)
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null)
        }
    }
}
