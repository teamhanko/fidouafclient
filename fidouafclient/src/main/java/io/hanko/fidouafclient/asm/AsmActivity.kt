package io.hanko.fidouafclient.asm

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import io.hanko.fidouafclient.R
import io.hanko.fidouafclient.asm.msgs.RequestType
import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.request.ASMRequest
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseGetInfo
import io.hanko.fidouafclient.asm.msgs.response.AuthenticatorInfo
import io.hanko.fidouafclient.asm.msgs.response.GetInfoOut
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.authenticator.op.Auth
import io.hanko.fidouafclient.authenticator.op.Dereg
import io.hanko.fidouafclient.authenticator.op.Reg
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Preferences
import io.hanko.fidouafclient.util.Util
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors


class AsmActivity : AppCompatActivity() {

    companion object {
        const val INTENT_MESSAGE_NAME = "message"
    }

    private val TAG = "AsmActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)

        setFinishOnTouchOutside(false)

        val requestMessage = intent.getStringExtra(INTENT_MESSAGE_NAME)
        val asmRequest = ASMRequest.fromJson(requestMessage!!)

        when {
            asmRequest.requestType == RequestType.Register && asmRequest is ASMRequestReg -> startRegistration(asmRequest)
            asmRequest.requestType == RequestType.Authenticate && asmRequest is ASMRequestAuth -> startAuthentication(asmRequest)
            asmRequest.requestType == RequestType.Deregister && asmRequest is ASMRequestDereg -> processDeregistration(asmRequest)
            asmRequest.requestType == RequestType.GetInfo -> processGetInfo()
            asmRequest.requestType == RequestType.GetRegistrations -> sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR)
            asmRequest.requestType == RequestType.OpenSettings -> sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR)
            else -> sendErrorResponse(null)
        }
    }

    private fun processGetInfo() {
        val biometricManager = BiometricManager.from(this)
        val asmResponseGetInfo = ASMResponseGetInfo(
                responseData = GetInfoOut(Authenticators = listOf(
                        AuthenticatorInfo.fromAuthenticator(AuthenticatorMetadata.authenticator, biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS)
                )),
                statusCode = StatusCode.UAF_ASM_STATUS_OK.id,
                exts = null
        )
        sendResponse(Util.moshi.adapter(ASMResponseGetInfo::class.java).toJson(asmResponseGetInfo))
    }

    private fun startRegistration(request: ASMRequestReg) {
        val newKeyId = Crypto.generateKeyID(request.args.appID)

        if (newKeyId != null && Crypto.generateKeyPair(newKeyId, request.args.appID)) {
            val biometricPrompt = getBiometricPrompt(processRegistration(request, newKeyId), processRegistrationError(request.args.appID, newKeyId))
            val promptInfo = getPromptInfo(R.string.uafclient_biometric_prompt_title_reg, R.string.uafclient_biometric_prompt_description_reg)
            biometricPrompt.authenticate(promptInfo)
        } else {
            sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR)
        }
    }

    private fun processRegistrationError(appId: String, keyId: String): () -> Unit {
        return {
            Crypto.deleteKey(keyId, appId) // delete key if registration failed
        }
    }

    private fun startAuthentication(request: ASMRequestAuth) {
        // get stored keyIds for an appId and when keyIds are specified than filter against those
        val storedKeyIds = Crypto.getStoredKeyIds(request.args.appID, request.args.keyIDs.toList())
                ?: emptyList()
        when {
            storedKeyIds.isEmpty() -> sendErrorResponse(StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY)
            storedKeyIds.size == 1 -> startBiometricPromptForAuthentication(request.copy(args = request.args.copy(keyIDs = storedKeyIds)))
            storedKeyIds.size > 1 -> showKeyIdSelectionDialog(request, storedKeyIds)
            else -> sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR)
        }
    }

    private fun showKeyIdSelectionDialog(request: ASMRequestAuth, storedKeyIds: List<String>) {
        val preference = Preferences.create(this, Preferences.PREFERENCE)
        val keyAliases = storedKeyIds.mapNotNull { Crypto.getKeyStoreAlias(request.args.appID, it) }
        val keyUsernamesMap = preference.all.filter { keyAliases.contains(it.key) } as Map<String, String>
        val usernameList = keyUsernamesMap.map { it.value }

        AlertDialog.Builder(this)
                .setTitle(R.string.uafclient_account_chooser_title)
                .setSingleChoiceItems(usernameList.toTypedArray(), -1) { dialogInterface, i ->
                    dialogInterface.dismiss()
                    val selectedKeyAlias = keyUsernamesMap.filter { it.value == usernameList[i] }.keys.toList()
                    val newReq = request.copy(args = request.args.copy(keyIDs = selectedKeyAlias.map { it.split(":")[1] }))
                    startBiometricPromptForAuthentication(newReq)
                }
                .setOnCancelListener {
                    sendErrorResponse(StatusCode.UAF_ASM_STATUS_USER_CANCELLED)
                }
                .show()
    }

    private fun startBiometricPromptForAuthentication(request: ASMRequestAuth) {
        val biometricPrompt = getBiometricPrompt(processAuthentication(request), null)
        val promptInfo = getPromptInfo(
                R.string.uafclient_biometric_prompt_title_auth,
                R.string.uafclient_biometric_prompt_description_auth,
                request.args.transaction?.content?.let { String(Base64.decode(it, Base64.URL_SAFE), StandardCharsets.UTF_8) })
        biometricPrompt.authenticate(promptInfo)
    }

    private fun getPromptInfo(@StringRes titleId: Int, @StringRes descriptionId: Int, transactionText: String? = null): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
                .setConfirmationRequired(true)
                .setTitle(getString(titleId))
                .setSubtitle(getString(descriptionId))
                .setDescription(transactionText)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL or BiometricManager.Authenticators.BIOMETRIC_STRONG)
        } else {
            builder.setDeviceCredentialAllowed(true)
        }

        return builder.build()
    }

    private fun getBiometricPrompt(processRequest: () -> Unit, processError: (() -> Unit)?): BiometricPrompt {
        val executor = Executors.newSingleThreadExecutor()
        return BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                val statusCode = when (errorCode) {
                    BiometricPrompt.ERROR_CANCELED -> StatusCode.UAF_ASM_STATUS_ACCESS_DENIED
                    BiometricPrompt.ERROR_HW_NOT_PRESENT -> StatusCode.UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES
                    BiometricPrompt.ERROR_HW_UNAVAILABLE -> StatusCode.UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES
                    BiometricPrompt.ERROR_LOCKOUT -> StatusCode.UAF_ASM_STATUS_USER_LOCKOUT
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> StatusCode.UAF_ASM_STATUS_USER_LOCKOUT
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> StatusCode.UAF_ASM_STATUS_USER_CANCELLED
                    BiometricPrompt.ERROR_NO_BIOMETRICS -> StatusCode.UAF_ASM_STATUS_USER_NOT_ENROLLED
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> StatusCode.UAF_ASM_STATUS_USER_NOT_ENROLLED
                    BiometricPrompt.ERROR_NO_SPACE -> StatusCode.UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES
                    BiometricPrompt.ERROR_TIMEOUT -> StatusCode.UAF_ASM_STATUS_USER_NOT_RESPONSIVE
                    BiometricPrompt.ERROR_UNABLE_TO_PROCESS -> StatusCode.UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES
                    BiometricPrompt.ERROR_USER_CANCELED -> StatusCode.UAF_ASM_STATUS_USER_CANCELLED
                    BiometricPrompt.ERROR_VENDOR -> StatusCode.UAF_ASM_STATUS_ERROR
                    else -> StatusCode.UAF_ASM_STATUS_ERROR
                }
                processError?.let { it() }
                sendErrorResponse(statusCode)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                processError?.let { it() }
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_ACCESS_DENIED)
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                processRequest()
            }
        })
    }

    private fun processRegistration(asmRequest: ASMRequestReg, keyId: String): () -> Unit {
        return {
            val reg = Reg(this)
            val response = reg.reg(asmRequest, keyId)
            sendResponse(response)
        }
    }

    private fun processAuthentication(asmRequest: ASMRequestAuth): () -> Unit {
        return {
            val auth = Auth()
            val response = auth.auth(asmRequest)
            sendResponse(response)
        }
    }

    private fun processDeregistration(request: ASMRequestDereg) {
        val dereg = Dereg(this)
        sendResponse(dereg.dereg(request))
    }

    private fun sendErrorResponse(statusCode: StatusCode?) {
        val asmResponse = ASMResponse(
                statusCode = (statusCode ?: StatusCode.UAF_ASM_STATUS_ERROR).id,
                exts = null
        )
        sendResponse(Util.moshi.adapter(ASMResponse::class.java).toJson(asmResponse))
    }

    private fun sendResponse(asmResponse: String) {
        val responseIntent = Intent()
        responseIntent.putExtra(INTENT_MESSAGE_NAME, asmResponse)
        setResult(RESULT_OK, responseIntent)
        finishAndRemoveTask()
    }
}
