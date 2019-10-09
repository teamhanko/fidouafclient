package io.hanko.fidouafclient.client.op;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;

import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg;
import io.hanko.fidouafclient.asm.msgs.request.RegisterIn;
import io.hanko.fidouafclient.asm.msgs.response.RegisterOut;
import io.hanko.fidouafclient.client.MainActivity;
import io.hanko.fidouafclient.client.interfaces.AsmStart;
import io.hanko.fidouafclient.client.interfaces.FacetIds;
import io.hanko.fidouafclient.client.msg.AuthenticatorRegistrationAssertion;
import io.hanko.fidouafclient.client.msg.ChannelBinding;
import io.hanko.fidouafclient.client.msg.FinalChallengeParams;
import io.hanko.fidouafclient.client.msg.RegistrationResponse;
import io.hanko.fidouafclient.client.msg.UafRegistrationRequest;
import io.hanko.fidouafclient.client.msg.Version;
import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.utility.ErrorCode;
import io.hanko.fidouafclient.utility.FidoUafUtils;
import io.hanko.fidouafclient.utility.FidoUafUtilsKotlin;
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class Registration(val context: Context, val activity: AsmStart, val facetId: String, val channelBinding: String): FacetIds {

    private val TAG: String = "Registration"
    private val gson = Gson()
    private var registrationRequest: UafRegistrationRequest? = null
    private var appID: String? = null
    private var finalChallengeParams: FinalChallengeParams? = null
    private val mainScope = CoroutineScope(Dispatchers.Main + Job())

    fun processRequests(registrationRequests: List<UafRegistrationRequest>) {
        registrationRequest = registrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 1 } ?: registrationRequests.find { it.header.upv.major == 1 && it.header.upv.minor == 0 }

        if (registrationRequest?.policy?.accepted?.any { it.any { !it.isValid() } } == true ||
            registrationRequest?.policy?.disallowed?.any { !it.isValid() } == true ||
            registrationRequest?.policy?.accepted?.isEmpty() == true) {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        } else {

            if (registrationRequest == null) {
                activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNSUPPORTED_VERSION, null)
            } else if (registrationRequest!!.challenge.isEmpty()) {
                activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            } else if (registrationRequest!!.header.appID == null || registrationRequest!!.header.appID!!.isEmpty() || Objects.equals(registrationRequest!!.header.appID, facetId)) {
                appID = facetId
                sendToAsm(true)
            } else if (registrationRequest!!.header.appID!!.contains("https://")) {
                appID = registrationRequest!!.header.appID
                // TODO:
                mainScope.launch {
                    val trustedFacets = FidoUafUtilsKotlin.getTrustedFacetsAsync(appID!!)
                    sendToAsm(if (trustedFacets != null) FidoUafUtilsKotlin.isFacetIdValid(trustedFacets, Version(1, 0), facetId) else false)
                }
//            FidoUafUtils.GetTrustedFacetsTask getTrustedFacetsTask = new FidoUafUtils.GetTrustedFacetsTask(this)
//            getTrustedFacetsTask.execute(registrationRequest.getHeader().getAppID())
            } else {
                activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            }
        }
    }
    
    fun processASMResponse(registerOut: RegisterOut) {
        val registrationAssertion = AuthenticatorRegistrationAssertion(
                assertionScheme = registerOut.assertionScheme,
                assertion = registerOut.assertion,
                tcDisplayPNGCharacteristics = null,
                exts = null)
        //registrationAssertion = registerOut.assertion;
        //registrationAssertion.assertionScheme = registerOut.assertionScheme;

//        RegistrationResponse[] registrationResponse = new RegistrationResponse[1];
        val registrationResponse = listOf(RegistrationResponse(
                registrationRequest!!.header,
                Base64.encodeToString(gson.toJson(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
                Collections.singletonList(registrationAssertion)
                ))
//        registrationResponse[0].header = registrationRequest.getHeader();
//        registrationResponse[0].fcParams = Base64.encodeToString(gson.toJson(finalChallengeParams).getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
//        registrationResponse[0].assertions = new AuthenticatorRegistrationAssertion[]{registrationAssertion};

        activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, gson.toJson(registrationResponse));
    }

    private fun sendToAsm(isFacetIdValid: Boolean) {
        if (isFacetIdValid) {
            finalChallengeParams = FinalChallengeParams(
                    appID!!,
                    registrationRequest!!.challenge,
                    facetId,
                    gson.fromJson(channelBinding, ChannelBinding::class.java)
            )
//            finalChallengeParams.appID = appID;
//            finalChallengeParams.challenge = registrationRequest.getChallenge();
//            finalChallengeParams.facetID = facetId;
//            finalChallengeParams.channelBinding = gson.fromJson(channelBinding, ChannelBinding.class);

            val registerIn = RegisterIn()
            registerIn.attestationType = 15880 // Attestation Surrogate
            registerIn.username = registrationRequest!!.username
            registerIn.appID = appID
            registerIn.finalChallenge = Base64.encodeToString(gson.toJson(finalChallengeParams).toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            
            val asmRequestReg = ASMRequestReg()
            asmRequestReg.asmVersion = registrationRequest!!.header.upv
            asmRequestReg.requestType = Request.Register
            asmRequestReg.authenticatorIndex = 0 // authenticator in this App will always have index = 0
            asmRequestReg.args = registerIn

            try { // try-catch as workaround for Huawei smartphones, because they won´t call method
                activity.sendToAsm(gson.toJson(asmRequestReg), MainActivity.ASM_REG_REQUEST_CODE, FidoUafUtilsKotlin.getAsmFromPolicy(context, registrationRequest!!.policy, appID!!))
            } catch (ex: Exception) {
                Log.e(TAG, "Error while sending asmRegistrationRequest to ASM", ex)
                activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null)
            }
        } else {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null)
        }
    }

    override fun processTrustedFacetIds(trustedFacetJson: String) {
        sendToAsm(FidoUafUtils.isFacetIdValid(trustedFacetJson, registrationRequest!!.header.upv, facetId))
    }
}
