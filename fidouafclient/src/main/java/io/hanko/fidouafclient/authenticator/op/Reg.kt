package io.hanko.fidouafclient.authenticator.op

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseReg
import io.hanko.fidouafclient.asm.msgs.response.RegisterOut
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.authenticator.util.SHA
import io.hanko.fidouafclient.authenticator.util.tlv.TagsEnum
import io.hanko.fidouafclient.authenticator.util.tlv.UnsignedUtil
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Preferences
import io.hanko.fidouafclient.util.Util
import java.io.ByteArrayOutputStream

class Reg(context: Context) {

    private val TAG = "Authenticator"
    private var sharedPreferences: SharedPreferences = Preferences.create(context, Preferences.PREFERENCE)

    /**
     *
     * @param asmRequestReg
     * @return stringified ASMResponse json
     */
    fun reg(asmRequestReg: ASMRequestReg, keyId: String): String {

        try {
            val outputStream = ByteArrayOutputStream()
            outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_REG_ASSERTION.id))
            val uafV1Krd = getUafV1Krd(keyId, asmRequestReg.args.finalChallenge, asmRequestReg.args.appID)
            val attestationTag = getAttestationTag(uafV1Krd, asmRequestReg.args.appID, keyId)

            outputStream.write(UnsignedUtil.encodeInt(uafV1Krd.size + attestationTag.size))
            outputStream.write(uafV1Krd)
            outputStream.write(attestationTag)

            val assertion = outputStream.toByteArray()

            val registerOut = RegisterOut(
                    assertionScheme = "UAFV1TLV",
                    assertion = Base64.encodeToString(assertion, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            )

            val asmResponseReg = ASMResponseReg(
                    statusCode = StatusCode.UAF_ASM_STATUS_OK.id,
                    responseData = registerOut,
                    exts = null
            )

            Preferences.setParam(sharedPreferences, Crypto.getKeyStoreAlias(asmRequestReg.args.appID, keyId)
                    ?: throw Exception("Could not generate KeyStoreAlias"), asmRequestReg.args.username)
            return Util.moshi.adapter(ASMResponseReg::class.java).toJson(asmResponseReg)
        } catch (ex: Exception) {
            Log.e(TAG, "Registration Attestation could not be generated", ex)
        }
        return generateErrorResponse()
    }

    private fun getUafV1Krd(keyId: String, finalChallenge: String, appId: String): ByteArray {

        val outputStream = ByteArrayOutputStream()
        outputStream.write(getAaidTag())
        outputStream.write(getAsserionInfoTag())
        outputStream.write(getFinalChallengeTag(finalChallenge))
        outputStream.write(getKeyIdTag(keyId))
        outputStream.write(getCountersTag())
        outputStream.write(getPublicKeyTag(keyId, appId))

        val value = outputStream.toByteArray()

        val arrayOutputStream = ByteArrayOutputStream()
        arrayOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_KRD.id))
        arrayOutputStream.write(UnsignedUtil.encodeInt(value.size))
        arrayOutputStream.write(value)

        return arrayOutputStream.toByteArray()
    }

    private fun getAttestationTag(signedData: ByteArray, appId: String, keyId: String): ByteArray {

        // TAG_SIGNATURE
        val signatureOutputStream = ByteArrayOutputStream()
        signatureOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_SIGNATURE.id))
        val sig = Crypto.getSignatureForKeyID(keyId, signedData, appId)
                ?: throw Exception("Attestation Signature could not be generated")
        signatureOutputStream.write(UnsignedUtil.encodeInt(sig.size))
        signatureOutputStream.write(sig)

        val signatureTag = signatureOutputStream.toByteArray()

        // TAG_ATTESTATION_BASIC_SURROGATE
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id))
        outputStream.write(UnsignedUtil.encodeInt(signatureTag.size))
        outputStream.write(signatureTag)

        return outputStream.toByteArray()
    }

    private fun getAaidTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AAID.id))
        val value = AuthenticatorMetadata.authenticator.aaid.toByteArray()
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

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

    private fun getFinalChallengeTag(finalChallenge: String): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_FINAL_CHALLENGE.id))
        val value = SHA.sha(finalChallenge.toByteArray(), "SHA-256")
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getCountersTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_COUNTERS.id))
        outputStream.write(UnsignedUtil.encodeInt(8))
        outputStream.write(UnsignedUtil.encodeInt32(0))
        outputStream.write(UnsignedUtil.encodeInt32(0))

        return outputStream.toByteArray()
    }

    private fun getPublicKeyTag(keyId: String, appId: String): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_PUB_KEY.id))
        val value = Crypto.getPublicKeyForKeyId(keyId, appId)?.encoded
                ?: throw IllegalArgumentException("Public key for keyId: $keyId not found")
        outputStream.write(UnsignedUtil.encodeInt(value.size))
        outputStream.write(value)

        return outputStream.toByteArray()
    }

    private fun getAsserionInfoTag(): ByteArray {
        val outputStream = ByteArrayOutputStream()
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ASSERTION_INFO.id))
        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator_fingerprint version // 0x01 0x00 = 1
        // 1 byte = For Registration this must be 0x01 indicating that the user has explicitly verified the action. // 0x01 = 1
        // 2 byte = Signature Algorithm and Encoding of the attestation signature. // 0x02 0x00 = 2
        // 2 byte = Public Key algorithm and encoding of the newly generated UAuth.pub key. // 0x01 0x01 = 257
        val value = byteArrayOf(0x01, 0x00, 0x01, 0x02, 0x00, 0x01, 0x01)
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
