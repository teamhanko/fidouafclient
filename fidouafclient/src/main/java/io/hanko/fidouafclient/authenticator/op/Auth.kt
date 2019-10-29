package io.hanko.fidouafclient.authenticator.op

import android.util.Base64
import android.util.Log
import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth
import io.hanko.fidouafclient.asm.msgs.response.AuthenticateOut
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.authenticator.util.SHA
import io.hanko.fidouafclient.authenticator.util.tlv.TagsEnum
import io.hanko.fidouafclient.authenticator.util.tlv.UnsignedUtil
import io.hanko.fidouafclient.client.msg.Transaction
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Util
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class Auth {

    private val TAG = "Authenticator"

    companion object {
        private fun getKeyId(asmRequestAuth: ASMRequestAuth): String? {
            val keyAliases = Crypto.getStoredKeyIds(asmRequestAuth.args.appID, asmRequestAuth.args.keyIDs)
            return if (keyAliases != null && keyAliases.isNotEmpty()) {
                keyAliases[0]
            } else {
                null
            }
        }
    }

    fun auth(asmRequestAuth: ASMRequestAuth): String {
        try {
            val keyID = getKeyId(asmRequestAuth)

            if (keyID != null) {

                val outputStream = ByteArrayOutputStream()
                outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id))
                val uafV1SignedData = getUafV1SignedDataTag(keyID, asmRequestAuth)
                val signatureTag = getSignatureTag(uafV1SignedData, asmRequestAuth.args.appID, keyID)

                outputStream.write(UnsignedUtil.encodeInt(uafV1SignedData.size + signatureTag.size))
                outputStream.write(uafV1SignedData)
                outputStream.write(signatureTag)

                val assertion = outputStream.toByteArray()

                val authenticateOut = AuthenticateOut(
                        assertionScheme = "UAFV1TLV",
                        assertion = Base64.encodeToString(assertion, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                )

                val asmResponseAuth = ASMResponseAuth(
                        statusCode = StatusCode.UAF_ASM_STATUS_OK.id,
                        responseData = authenticateOut,
                        exts = null
                )

                return Util.moshi.adapter(ASMResponseAuth::class.java).toJson(asmResponseAuth)
            } else {
                return generateErrorResponse()
            }
        } catch (ex: Exception) {
            Log.e(TAG, "Authentication signature could not be generated", ex)
            return generateErrorResponse()
        }
    }

    private fun getUafV1SignedDataTag(keyId: String, asmRequestAuth: ASMRequestAuth): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(getAaidTag())
        outputStream.write(getAssertionInfoTag(asmRequestAuth.args.transaction))
        outputStream.write(getAuthenticatorNonceTag())
        outputStream.write(getFinalChallengeTag(asmRequestAuth.args.finalChallenge))
        outputStream.write(getTransactionContentHashTag(asmRequestAuth.args.transaction))
        outputStream.write(getKeyIdTag(keyId))
        outputStream.write(getCountersTag())

        val value = outputStream.toByteArray()

        val arrayOutputStream = ByteArrayOutputStream()
        arrayOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_SIGNED_DATA.id))
        arrayOutputStream.write(UnsignedUtil.encodeInt(value.size))
        arrayOutputStream.write(value)

        return arrayOutputStream.toByteArray()
    }

    private fun getAaidTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AAID.id))
        val value = AuthenticatorMetadata.authenticator.aaid.toByteArray()
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getAssertionInfoTag(transaction: Transaction?): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ASSERTION_INFO.id))

        val authenticationMode: Byte = if (transaction != null) {
            0x02
        } else {
            0x01
        }

        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator_fingerprint version // 0x01 0x00 = 1
        // 1 byte = Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature. // 0x02 0x00 = 2
        val value = byteArrayOf(0x01, 0x00, authenticationMode, 0x02, 0x00)

        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getAuthenticatorNonceTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AUTHENTICATOR_NONCE.id))
        val value = ByteArray(8)
        SecureRandom().nextBytes(value)
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getFinalChallengeTag(finalChallenge: String): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_FINAL_CHALLENGE.id))
        val value = SHA.sha(finalChallenge.toByteArray(), "SHA-256")
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getTransactionContentHashTag(transaction: Transaction?): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id))
        if (transaction != null) {
            val value = SHA.sha(Base64.decode(transaction.content, Base64.URL_SAFE), "SHA-256")
            outputStream.write(UnsignedUtil.encodeInt(value.size))
            outputStream.write(value)
        } else {
            outputStream.write(UnsignedUtil.encodeInt(0))
        }

        return outputStream.toByteArray()
    }

    private fun getKeyIdTag(keyID: String): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_KEYID.id))
        val value = Base64.decode(keyID, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getCountersTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_COUNTERS.id))
        outputStream.write(UnsignedUtil.encodeInt(4))
        outputStream.write(UnsignedUtil.encodeInt32(0))

        return outputStream.toByteArray()
    }

    private fun getSignatureTag(signedData: ByteArray, appId: String, keyId: String): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_SIGNATURE.id))
        val value = Crypto.getSignatureForKeyID(keyId, signedData, appId)
                ?: throw IllegalArgumentException("Assertion Signature could not be generated")
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }


    private fun generateErrorResponse(): String {
        return try {
            val asmResponse = ASMResponse(
                    statusCode = StatusCode.UAF_ASM_STATUS_ERROR.id,
                    exts = null
            )
            Util.moshi.adapter(ASMResponse::class.java).toJson(asmResponse)
        } catch (ex: Exception) {
            Log.e(TAG, "Could not generate error response.", ex)
            ""
        }
    }
}
