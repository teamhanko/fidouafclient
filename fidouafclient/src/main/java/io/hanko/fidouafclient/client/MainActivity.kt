package io.hanko.fidouafclient.client

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import io.hanko.fidouafclient.asm.AsmActivity
import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseReg
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.client.msg.*
import io.hanko.fidouafclient.client.msg.client.DiscoveryData
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.client.msg.client.UAFMessage
import io.hanko.fidouafclient.client.op.Authentication
import io.hanko.fidouafclient.client.op.Deregistration
import io.hanko.fidouafclient.client.op.Registration
import io.hanko.fidouafclient.client.msg.client.ErrorCode
import io.hanko.fidouafclient.util.ClientUtil
import io.hanko.fidouafclient.util.Util
import io.hanko.fidouafclient.util.Util.moshi
import org.json.JSONException
import org.json.JSONObject

data class V(val major: Int, val minor: Int)

class MainActivity : AppCompatActivity() {

    private val TAG: String = "MainActivity"
    private var componentName: String? = null
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

        Log.w(TAG, "Time: ${System.currentTimeMillis()} onCreate")

        setFinishOnTouchOutside(false)

        componentName = ComponentName(applicationContext, MainActivity::class.java).flattenToString()
        val callingIntent = intent
        val extras = callingIntent.extras

        facetId = ClientUtil.getFacetIDWithName(applicationContext, callingActivity!!.packageName)
        if (ClientUtil.validateRequestIntent(callingIntent) && extras != null) {
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
                listOf(Version(1, 1), Version(1, 0)),
                "Hanko",
                Version(1, 0),
                listOf(AuthenticatorMetadata.authenticator)
        )

        sendDiscoveryReturnIntent(moshi.adapter(DiscoveryData::class.java).toJson(discoveryData))
    }

    private fun processCheckPolicyRequest(extras: Bundle) {
        val message: String? = extras.getString(Util.INTENT_MESSAGE_NAME)
        if (message != null) {
            val uafOperationMessageString = moshi.adapter(UAFMessage::class.java).fromJson(message)?.uafProtocolMessage
                    ?: ""
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
                ClientUtil.canEvaluatePolicy(policy, requests[0].header.appID
                        ?: "") -> sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.NO_ERROR, null)
                else -> sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null)
            }
        } else {
            sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun processUafOperationRequest(extras: Bundle) {
        val channelBinding: String? = extras.getString("channelBindings")
        val message: String? = extras.getString(Util.INTENT_MESSAGE_NAME)
        val skipTrustedFacetValidation: Boolean = extras.getBoolean("skipTrustedFacetValidation", false)
        Log.w("Message", "$message")
        if (channelBinding != null && message != null) {
            try {
                val uafOperationMessage = moshi.adapter(UAFMessage::class.java).fromJson(message)?.uafProtocolMessage
                        ?: ""
                processUafRequest(uafOperationMessage, channelBinding, skipTrustedFacetValidation)
            } catch (ex: Exception) {
                Log.w(TAG, "Error while processing UAF request", ex)
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            }
        } else {
            // no channelBinding and message are given, but are required
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
        }
    }

    private fun processUafRequest(extras: Bundle) {
        // could throw IllegalArgumentException if string can not translated to an enum value
        val uafType = extras.getString("UAFIntentType")?.let { UAFIntentType.valueOf(it) }
        when (uafType) {
            UAFIntentType.DISCOVER -> processDiscoveryRequest()
            UAFIntentType.CHECK_POLICY -> processCheckPolicyRequest(extras)
            UAFIntentType.UAF_OPERATION_COMPLETION_STATUS -> finish()
            UAFIntentType.UAF_OPERATION -> processUafOperationRequest(extras)
            else -> sendReturnIntent(null, ErrorCode.UNKNOWN, null)
        }
    }

    private fun validateUafRequests(requests: List<UafRequest>): Boolean {
        return requests.groupBy { V(it.header.upv.major, it.header.upv.minor) }
                .none { it.value.size > 1 } && // check that only 1 request per version exists
                requests.none { it.header.appID?.length ?: 0 > 512 } &&
                requests.none { it.header.serverData?.length ?: 0 > 1536 || it.header.serverData?.length ?: 1 < 1 } && // check that serverData length is not larger than 1536 and not smaller than 1 if it exists
                requests.none { request ->
                    request.header.exts?.any { it.id.length > 32 || it.id.isEmpty() } ?: false
                }
    }

    private fun validateExtensions(requests: List<UafRequest>): Boolean {
        return requests.none {
            it.header.exts?.any { !AuthenticatorMetadata.authenticator.supportedExtensionIDs.contains(it.id) && it.fail_if_unknown }
                    ?: false
        }
    }

    private fun processUafRequest(uafOperationMessage: String, channelBinding: String, skipTrustedFacetValidation: Boolean) {

        val request = parseUafOperationMessage(uafOperationMessage)
        if (request.isEmpty() || !validateUafRequests(request)) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null)
            return
        }

        if (!validateExtensions(request)) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
            return
        }

        if (facetId == null) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
            return
        }

        when (request[0].header.op) {
            Operation.Reg -> {
                registrationProcess = Registration(facetId!!, channelBinding)
                registrationProcess!!.processRequests(request.filterIsInstance<UafRegistrationRequest>(), sendToAsm(ASM_REG_REQUEST_CODE), this::sendReturnIntent, skipTrustedFacetValidation)
            }
            Operation.Auth -> {
                authenticationProcess = Authentication(facetId!!, channelBinding)
                authenticationProcess!!.processRequests(request.filterIsInstance<UafAuthenticationRequest>(), sendToAsm(ASM_AUTH_REQUEST_CODE), this::sendReturnIntent, skipTrustedFacetValidation)
            }
            Operation.Dereg -> {
                deregistrationProcess = Deregistration(facetId!!, channelBinding)
                deregistrationProcess!!.processRequests(request.filterIsInstance<UafDeregistrationRequest>(), sendToAsm(ASM_DEREG_REQUEST_CODE), this::sendReturnIntent, skipTrustedFacetValidation)
            }
        }
    }

    private fun parseUafOperationMessage(uafOperationMessage: String): List<UafRequest> {
        val requests: List<UafRequest> = moshi.adapter(Array<UafRequest>::class.java).fromJson(uafOperationMessage)?.toList()
                ?: emptyList()
        if (requests.isEmpty()) {
            return emptyList()
        }

        return when (requests[0].header.op) {
            Operation.Reg ->
                moshi.adapter(Array<UafRegistrationRequest>::class.java).fromJson(uafOperationMessage)?.toList()
            Operation.Auth ->
                moshi.adapter(Array<UafAuthenticationRequest>::class.java).fromJson(uafOperationMessage)?.toList()
            Operation.Dereg ->
                moshi.adapter(Array<UafDeregistrationRequest>::class.java).fromJson(uafOperationMessage)?.toList()
        } ?: emptyList()
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
     * Build an intent which will be returned to calling activity
     *
     * @param uafIntentType
     * @param errorCode
     * @param message
     */
    fun sendReturnIntent(uafIntentType: UAFIntentType?, errorCode: ErrorCode, message: String?) {
        Log.w(TAG, "Time: ${System.currentTimeMillis()} sendReturnIntent")
        val uafIntentTypeString = uafIntentType?.name ?: "undefined"
        val resultIntent = Intent()
        if (message != null) {
            val jsonObject = JSONObject()
            try {
                jsonObject.put("uafProtocolMessage", message)
                resultIntent.putExtra(Util.INTENT_MESSAGE_NAME, jsonObject.toString())
            } catch (ex: JSONException) {
                Log.e(TAG, "${ex.message}")
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
                return
            }
        }
        resultIntent.putExtra("UAFIntentType", uafIntentTypeString)
        resultIntent.putExtra("componentName", componentName)
        resultIntent.putExtra("errorCode", errorCode.id)
        returnUafResponse(RESULT_OK, resultIntent)
    }

    private fun sendDiscoveryReturnIntent(discoverData: String) {
        val resultIntent = Intent()
        resultIntent.putExtra("discoveryData", discoverData)
        resultIntent.putExtra("UAFIntentType", UAFIntentType.DISCOVER_RESULT.name)
        resultIntent.putExtra("componentName", componentName)
        resultIntent.putExtra("errorCode", ErrorCode.NO_ERROR.id)
        returnUafResponse(RESULT_OK, resultIntent)
    }

    fun sendToAsm(requestCode: Int): (message: String) -> Unit {
        return { message: String ->
            //            val asmIntent = Intent("org.fidoalliance.intent.FIDO_OPERATION")
            val asmIntent = Intent(this, AsmActivity::class.java) // send RequestType to our ASM and don´t give the User the choice if there are more than our ASM
            asmIntent.type = "application/fido.uaf_asm+json"
            asmIntent.putExtra(Util.INTENT_MESSAGE_NAME, message)

            startActivityForResult(asmIntent, requestCode)
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

        try {
            if (data != null) {
                // Operation is identified by requestCode
                val message = data.getStringExtra(Util.INTENT_MESSAGE_NAME)
                val asmResponse = moshi.adapter(ASMResponse::class.java).fromJson(message ?: "")
                if (requestCode == ASM_REG_REQUEST_CODE && asmResponse != null) {
                    if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id) {
//                    registrationProcess!!.p
                        val responseData = moshi.adapter(ASMResponseReg::class.java).fromJson(message!!)?.responseData
                                ?: throw IllegalArgumentException("Response Data must not be empty")
                        registrationProcess!!.processASMResponse(responseData, this::sendReturnIntent)
                    } else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
                } else if (requestCode == ASM_AUTH_REQUEST_CODE && asmResponse != null) {
                    if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id) {
                        val responseData = moshi.adapter(ASMResponseAuth::class.java).fromJson(message!!)?.responseData
                                ?: throw IllegalArgumentException("Response Data must not be empty")
                        authenticationProcess!!.processASMResponse(responseData, this::sendReturnIntent)
                    } else
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
                } else if (requestCode == ASM_DEREG_REQUEST_CODE && asmResponse != null) {
                    if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.id) {
                        deregistrationProcess!!.processASMResponse(this::sendReturnIntent)
                    } else {
                        sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null)
                    }
                } else {
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
                }
            } else {
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.USER_CANCELLED, null)
            }
        } catch (ex: Exception) {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null)
        }
    }

    private fun convertStatusCodeToErrorCode(statusCode: Short): ErrorCode {
        return when (statusCode) {
            StatusCode.UAF_ASM_STATUS_OK.id -> ErrorCode.NO_ERROR
            StatusCode.UAF_ASM_STATUS_ERROR.id -> ErrorCode.UNKNOWN
            StatusCode.UAF_ASM_STATUS_ACCESS_DENIED.id -> ErrorCode.AUTHENTICATOR_ACCESS_DENIED
            StatusCode.UAF_ASM_STATUS_USER_CANCELLED.id -> ErrorCode.USER_CANCELLED
            StatusCode.UAF_ASM_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT.id -> ErrorCode.INVALID_TRANSACTION_CONTENT
            StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY.id -> ErrorCode.KEY_DISAPPEARED_PERMANENTLY
            StatusCode.UAF_ASM_STATUS_AUTHENTICATOR_DISCONNECTED.id -> ErrorCode.NO_SUITABLE_AUTHENTICATOR
            StatusCode.UAF_ASM_STATUS_USER_NOT_RESPONSIVE.id -> ErrorCode.USER_NOT_RESPONSIVE
            StatusCode.UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES.id -> ErrorCode.INSUFFICIENT_AUTHENTICATOR_RESOURCES
            StatusCode.UAF_ASM_STATUS_USER_LOCKOUT.id -> ErrorCode.USER_LOCKOUT
            StatusCode.UAF_ASM_STATUS_USER_NOT_ENROLLED.id -> ErrorCode.USER_NOT_ENROLLED
            else -> ErrorCode.UNKNOWN
        }
    }
}
