package io.hanko.fidouafclient.client

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule

import com.google.gson.Gson

import org.json.JSONException
import org.json.JSONObject

import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseReg
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig
import io.hanko.fidouafclient.client.interfaces.AsmStart
import io.hanko.fidouafclient.client.msg.*
import io.hanko.fidouafclient.client.msg.client.DiscoveryData
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.client.msg.client.UAFMessage
import io.hanko.fidouafclient.client.op.Authentication
import io.hanko.fidouafclient.client.op.Deregistration
import io.hanko.fidouafclient.client.op.Registration
import io.hanko.fidouafclient.utility.*
import java.lang.Exception

data class V(val major: Int, val minor: Int)

class MainActivity: AppCompatActivity(), AsmStart {

    private val TAG: String = "MainActivity"
    private var componentName: String? = null
    private val gson = Gson()
    private var facetId: String? = null

    companion object {
        const val ASM_REG_REQUEST_CODE = 1111
        const val ASM_AUTH_REQUEST_CODE = 2222
        const val ASM_DEREG_REQUEST_CODE = 3333
    }

    private var registrationProcess: Registration? = null
    private var authenticationProcess: Authentication? = null
    private var deregistrationProcess: Deregistration? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setFinishOnTouchOutside(false)

        componentName = ComponentName(applicationContext, MainActivity::class.java).flattenToString()
        val callingIntent = intent
        val extras = callingIntent.extras

        facetId = FidoUafUtils.getFacetIDWithName(applicationContext, callingActivity!!.packageName)
        if (ClientUtil.validateRequestIntent(callingIntent)) {
            try {
                processUafRequest(extras)
            } catch (ex: Exception) {
                Log.e(TAG, "Error while processing UAF request", ex)
                sendReturnIntent(null, ErrorCode.UNKNOWN, null)
            }
        } else {
            sendReturnIntent(ClientUtil.getReturnIntentType(callingIntent), ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun processDiscoveryRequest() {
        val discoveryData = DiscoveryData(
                listOf(Version(1, 0), Version(1, 1)),
                "Hanko",
                Version(1,0),
                listOf(AuthenticatorConfig.authenticator)
        )

        sendReturnIntent(UAFIntentType.DISCOVER_RESULT, ErrorCode.NO_ERROR, gson.toJson(discoveryData))
    }

    private fun processCheckPolicyRequest(extras: Bundle) {
        val message: String? = extras.getString("message")
        if (message != null) {
            val uafOperationMessageString = gson.fromJson(message, UAFMessage::class.java).uafProtocolMessage
            val requests = parseUafOperationMessage(uafOperationMessageString)
            if (requests.isEmpty()) {
                sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.PROTOCOL_ERROR, null)
                return
            }

            val policy = when (requests[0].header.op) {
                Operation.Reg -> requests.filterIsInstance<UafRegistrationRequest>()[0].policy
                Operation.Auth -> requests.filterIsInstance<UafAuthenticationRequest>()[0].policy
                Operation.Dereg -> null
            }

            when {
                policy == null -> sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.NO_ERROR, null)
                FidoUafUtilsKotlin.canEvaluatePolicy(this, policy, requests[0].header.appID ?: "") -> sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.NO_ERROR, null)
                else -> sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            }
        } else {
            sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun processUafOperationRequest(extras: Bundle) {
        val channelBinding: String? = extras.getString("channelBindings")
        val message: String? = extras.getString("message")
        if (channelBinding != null && message != null) {
            try {
                val uafOperationMessage = gson.fromJson(message, UAFMessage::class.java).uafProtocolMessage
                processUafRequest(uafOperationMessage, channelBinding)
            } catch (ex: Exception) {
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            }
        } else {
            // no channelBinding and message are given, but are required
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun processUafRequest(extras: Bundle) {
        // could throw IllegalArgumentException if string can not translated to an enum value
        when (UAFIntentType.valueOf(extras.getString("UAFIntentType"))) {
            UAFIntentType.DISCOVER -> processDiscoveryRequest()
            UAFIntentType.CHECK_POLICY -> processCheckPolicyRequest(extras)
            UAFIntentType.UAF_OPERATION_COMPLETION_STATUS -> finish()
            UAFIntentType.UAF_OPERATION -> processUafOperationRequest(extras)
            else -> sendReturnIntent(null, ErrorCode.UNKNOWN, null)
        }
    }

    private fun validateUafRequests(requests: Array<UafRequest>): Boolean {
        return requests.groupBy { V(it.header.upv.major, it.header.upv.major) }
                .none { it.value.size > 1 } && // check that only 1 request per version exists
                requests.none { it.header.appID?.length ?: 0 > 512 } &&
                requests.none { it.header.serverData?.length ?: 0 > 1536 || it.header.serverData?.length ?: 1 < 1 } && // check that serverData length is not larger than 1536 and not smaller than 1 if it exists
                requests.none { it.header.exts?.any { it.id.length > 32 || it.id.isEmpty() } ?: false }
    }

    private fun validateExtensions(requests: Array<UafRequest>): Boolean {
        return requests.none { it.header.exts?.any { !AuthenticatorConfig.authenticator.supportedExtensionIDs.contains(it.id) && it.fail_if_unknown } ?: false }
    }

    private fun processUafRequest(uafOperationMessage: String, channelBinding: String) {

        val request = parseUafOperationMessage(uafOperationMessage)
        if (request.isEmpty() || !validateUafRequests(request.filterIsInstance<UafRequest>().toTypedArray())) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            return
        }

        if (!validateExtensions(request.filterIsInstance<UafRequest>().toTypedArray())) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
            return
        }

        if (facetId == null) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
            return
        }

        when(request[0].header.op) {
            Operation.Reg -> {
                registrationProcess = Registration(this, this, facetId!!, channelBinding)
                registrationProcess!!.processRequests(request.filterIsInstance<UafRegistrationRequest>())
            }
            Operation.Auth -> {
                authenticationProcess = Authentication(this, this, facetId, channelBinding)
                authenticationProcess!!.processRequests(request.filterIsInstance<UafAuthenticationRequest>().toTypedArray())
            }
            Operation.Dereg -> {
                deregistrationProcess = Deregistration(this, this, facetId, channelBinding)
                deregistrationProcess!!.processRequests(request.filterIsInstance<UafDeregistrationRequest>().toTypedArray())
            }
        }

//        val requests = gson.fromJson(uafOperationMessage, Array<UafRequest>::class.java)
//        if (requests.isEmpty()) {
//            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
//            return
//        }
//        when (requests[0].header.op) {
//            Operation.Reg -> {
//                registrationProcess = Registration(this, this, facetId, channelBinding)
//                registrationProcess!!.processRequests(gson.fromJson(uafOperationMessage, Array<UafRegistrationRequest>::class.java))
//            }
//            Operation.Auth -> {
//                authenticationProcess = Authentication (this, this, facetId, channelBinding)
//                authenticationProcess!!.processRequests(gson.fromJson(uafOperationMessage, Array<UafAuthenticationRequest>::class.java))
//            }
//            Operation.Dereg -> {
//                deregistrationProcess = Deregistration (this, this, facetId, channelBinding)
//                deregistrationProcess!!.processRequests(gson.fromJson(uafOperationMessage, Array<UafDeregistrationRequest>::class.java))
//            }
//            else -> sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
//        }
    }

    private fun parseUafOperationMessage(uafOperationMessage: String): Array<out UafRequest> {
        val objectMapper = ObjectMapper()
                .registerKotlinModule()
                .registerModule(
                        SimpleModule()
                                .addDeserializer(String::class.java, ForceStringDeserializer())
                                .addDeserializer(Int::class.java, ForceIntDeserializer())
                                .addDeserializer(Long::class.java, ForceLongDeserializer())
                                .addDeserializer(MatchCriteria::class.java, MatchCriteriaDeserializer())
                )
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

        val requests = objectMapper.readValue(uafOperationMessage, Array<UafRequest>::class.java)
        if (requests.isEmpty()) {
            return emptyArray()
        }

        return when (requests[0].header.op) {
            Operation.Reg -> objectMapper.readValue(uafOperationMessage, Array<UafRegistrationRequest>::class.java)
            Operation.Auth -> objectMapper.readValue(uafOperationMessage, Array<UafAuthenticationRequest>::class.java)
            Operation.Dereg -> objectMapper.readValue(uafOperationMessage, Array<UafDeregistrationRequest>::class.java)
        }
    }

    /**
     * return Intent to calling App
     *
     * @param resultCode
     * @param resultIntent
     */
    private fun returnUafResponse(resultCode: Int, resultIntent: Intent) {
        setResult(resultCode, resultIntent)
        finishAndRemoveTask()
    }

    /**
     * build an Intent which will be returned to calling App
     *
     * @param uafIntentType
     * @param errorCode
     * @param message
     */
    override fun sendReturnIntent(uafIntentType: UAFIntentType?, errorCode: ErrorCode, message: String?) {
        val uafIntentTypeString = uafIntentType?.name ?: "undefined"
        val resultIntent = Intent()
        if (message != null) {
            val jsonObject = JSONObject()
            try {
                jsonObject.put("uafProtocolMessage", message)
                resultIntent.putExtra("message", jsonObject.toString())
            } catch (ex: JSONException) {
                Log.e(TAG, ex.message)
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
            }
        }
        resultIntent.putExtra("UAFIntentType", uafIntentTypeString)
        resultIntent.putExtra("componentName", componentName)
        resultIntent.putExtra("errorCode", errorCode.id)
        returnUafResponse(RESULT_OK, resultIntent)
    }

    /**
     * send ASMRequest to ASM
     *
     * @param message
     * @param requestCode
     */
    override fun sendToAsm(message: String, requestCode: Int, activity: Class<*>?) {
//        Intent asmIntent = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        if (activity != null) {
            val asmIntent = Intent(this, activity) // send Request to our ASM and don´t give the User the choice if there are more than our ASM
            asmIntent.type = "application/fido.uaf_asm+json"
            asmIntent.putExtra("message", message)

            startActivityForResult(asmIntent, requestCode)
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, "")
        }
    }

    /**
     * get result from ASM and process ASMResponse accordingly by Operation
     *
     * @param requestCode
     * @param resultCode
     * @param data
     */
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (data != null) {
            // Operation is identified by requestCode
            val message = data.getStringExtra("message")
            val asmResponse = gson.fromJson(message, ASMResponse::class.java)
            if (requestCode == ASM_REG_REQUEST_CODE) {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id)
                    registrationProcess!!.processASMResponse(gson.fromJson(message, ASMResponseReg::class.java).responseData)
                else
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
            } else if (requestCode == ASM_AUTH_REQUEST_CODE) {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id)
                    authenticationProcess!!.processASMResponse(gson.fromJson(message, ASMResponseAuth::class.java).responseData)
                else
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
            } else {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id) {
                    deregistrationProcess!!.processASMResponse()
                } else {
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
                }
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.USER_CANCELLED, null)
        }
    }

    private fun convertStatusCodeToErrorCode(statusCode: Short): ErrorCode {
        return when (statusCode) {
            StatusCode.UAF_ASM_STATUS_USER_CANCELLED.id -> ErrorCode.USER_CANCELLED
            StatusCode.UAF_ASM_STATUS_OK.id -> ErrorCode.NO_ERROR
            StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY.id -> ErrorCode.KEY_DISAPPEARED_PERMANENTLY
            else -> ErrorCode.UNKNOWN
        }
    }
}
