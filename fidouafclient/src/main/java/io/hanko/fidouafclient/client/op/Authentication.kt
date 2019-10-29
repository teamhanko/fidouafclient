package io.hanko.fidouafclient.client.op

import android.util.Base64
import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth
import io.hanko.fidouafclient.asm.msgs.request.AuthenticateIn
import io.hanko.fidouafclient.asm.msgs.response.AuthenticateOut
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.client.msg.*
import io.hanko.fidouafclient.client.msg.client.ErrorCode
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.util.ClientUtil
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Util
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class Authentication(val facetId: String, val channelBinding: String) {

    private val TAG = "Authentication"
    private var authenticationRequest: UafAuthenticationRequest? = null
    private var appID: String? = null
    private var finalChallengeParams: FinalChallengeParams? = null
    private val mainScope = CoroutineScope(Dispatchers.Main + Job())

    fun processRequests(authenticationRequests: List<UafAuthenticationRequest>, sendToAsm: (String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit, skipTrustedFacetValidation: Boolean) {
        val authReq = authenticationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 1 }
                ?: authenticationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 0 }
        authenticationRequest = authReq

        val challengeBytes = Base64.decode(authReq?.challenge ?: "", Base64.URL_SAFE)

        if (authReq == null) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNSUPPORTED_VERSION, null)
        } else if (authReq.policy.accepted.any { it.any { !it.isValid() } } ||
                authReq.policy.disallowed?.any { !it.isValid() } == true ||
                authReq.policy.accepted.isEmpty() ||
                challengeBytes.size < 8 || challengeBytes.size > 64 ||
                !validateTransaction(authReq.transaction)) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        } else if (authReq.header.appID == null || authReq.header.appID.isEmpty() || authReq.header.appID == facetId) {
            appID = facetId
            this.sendToAsm(authReq, sendToAsm, sendReturnIntent)
        } else if (Util.isValidHttpsUrl(authReq.header.appID)) {
            appID = authReq.header.appID
            if (skipTrustedFacetValidation) {
                this.sendToAsm(authReq, sendToAsm, sendReturnIntent)
            } else {
                mainScope.launch {
                    val trustedFacets = ClientUtil.getTrustedFacetsAsync(appID!!)
                    if (trustedFacets != null && ClientUtil.isFacetIdValid(trustedFacets, Version(1, 0), facetId))
                        this@Authentication.sendToAsm(authReq, sendToAsm, sendReturnIntent)
                    else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null)
                }
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun validateTransaction(transaction: List<Transaction>?): Boolean {
        if (transaction == null) {
            return true
        } else if (transaction.none { it.contentType == AuthenticatorMetadata.authenticator.tcDisplayContentType } ||
                transaction.filter { it.contentType == AuthenticatorMetadata.authenticator.tcDisplayContentType }.any { it.content.length > 200 } ||
                transaction.any { !isTransactionContentValid(it.content) }) {
            return false
        }

        return true
    }

    private fun isTransactionContentValid(content: String): Boolean {
        return try {
            Base64.decode(content, Base64.URL_SAFE).isNotEmpty() && !content.contains("/") && !content.contains("+") && !content.contains("=")
        } catch (ex: Exception) {
            false
        }
    }

    fun processASMResponse(authenticateOut: AuthenticateOut, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        val authenticationAssertion = AuthenticatorSignAssertion(authenticateOut.assertionScheme, authenticateOut.assertion, null)

        val authenticationResponse = listOf(AuthenticationResponse(
                authenticationRequest!!.header,
                Base64.encodeToString(Util.moshi.adapter(FinalChallengeParams::class.java).toJson(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
                listOf(authenticationAssertion)
        ))

        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, Util.moshi.adapter(Array<AuthenticationResponse>::class.java).toJson(authenticationResponse.toTypedArray()))
    }

    private fun sendToAsm(authenticationRequest: UafAuthenticationRequest, sendToAsm: (String) -> Unit, sendReturnIntent: (UAFIntentType?, ErrorCode, String?) -> Unit) {
        val allowedMatchCriterias = authenticationRequest.policy.accepted.filter {
            return@filter if (it.size == 1) // check that secondary list has one element, because we only support use of the embedded authenticator
                it.any { matchCriteria -> matchCriteria.matchesAuthenticator(AuthenticatorMetadata.authenticator, appID!!, false) }
            else
                false
        }.flatten()
        val disallowedMatchCriterias = authenticationRequest.policy.disallowed?.filter { it.matchesAuthenticator(AuthenticatorMetadata.authenticator, appID!!, false) }
                ?: emptyList()

        val allowedKeyIds = allowedMatchCriterias.flatMap { it.keyIDs ?: emptyList() }
        val disallowedKeyIds = disallowedMatchCriterias.flatMap { it.keyIDs ?: emptyList() }
        val filteredKeyIds = Crypto.getStoredKeyIds(appID!!, null)
                ?.filter { if (allowedKeyIds.isNotEmpty()) allowedKeyIds.contains(it) else true }
                ?.filter { !disallowedKeyIds.contains(it) }
                ?: emptyList()


        finalChallengeParams = FinalChallengeParams(appID!!, authenticationRequest.challenge, facetId, Util.moshi.adapter(ChannelBinding::class.java).fromJson(channelBinding)!!)

        if (filteredKeyIds.isEmpty()) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null)
            return
        }

        val authenticateIn = AuthenticateIn(
                appID = appID!!,
                finalChallenge = Base64.encodeToString(Util.moshi.adapter(FinalChallengeParams::class.java).toJson(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
                transaction = if (authenticationRequest.transaction != null && authenticationRequest.transaction.isNotEmpty()) {
                    authenticationRequest.transaction.find { it.contentType == "text/plain" }
                } else {
                    null
                },
                keyIDs = allowedKeyIds
        )

        this.sendToAsm(authenticateIn, authenticationRequest, sendToAsm)
    }

    private fun sendToAsm(authenticateIn: AuthenticateIn, authenticationRequest: UafAuthenticationRequest, sendToAsm: (String) -> Unit) {
        val asmRequestAuth = ASMRequestAuth(
                requestType = RequestType.Authenticate,
                asmVersion = authenticationRequest.header.upv,
                authenticatorIndex = 0,
                args = authenticateIn,
                exts = null
        )

        sendToAsm(Util.moshi.adapter(ASMRequestAuth::class.java).toJson(asmRequestAuth))
    }
}
