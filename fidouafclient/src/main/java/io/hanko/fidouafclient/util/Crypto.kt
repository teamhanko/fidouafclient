package io.hanko.fidouafclient.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.*
import java.security.spec.ECGenParameterSpec

object Crypto {

    const val KEYSTORE = "AndroidKeyStore"
    private const val TAG = "Crypto"

    fun generateKeyPair(keyId: String, appId: String): Boolean {
        try {
            val keyAlias = getKeyStoreAlias(appId, keyId) ?: return false
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            keyPairGenerator.initialize(
                    KeyGenParameterSpec.Builder(
                            keyAlias,
                            KeyProperties.PURPOSE_SIGN
                    ).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(2)
                            .build()
            )

            keyPairGenerator.generateKeyPair()
            return true
        } catch (ex: Exception) {
            Log.e(TAG, "KeyPair could not be generated", ex)
            return false
        }
    }

    fun getStoredKeyIds(appID: String, keyIds: List<String>?): List<String>? {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val storedAliases = keyStore.aliases().toList()

        if (keyIds?.isNotEmpty() == true) {
            val keyAliases = keyIds.map { getKeyStoreAlias(appID, it) }
            return storedAliases.filter { sa -> keyAliases.any { it == sa } }.map { it.split(":")[1] }
        } else {
            val appIdHash = getAppIdHash(appID) ?: return null
            return storedAliases.filter { it.startsWith(appIdHash) }.map { it.split(":")[1] }
        }
    }

    fun generateKeyID(appId: String): String? {
        val bytes = ByteArray(30)
        SecureRandom().nextBytes(bytes)
        val tmp = appId + Base64.encodeToString(bytes, Base64.DEFAULT)

        return try {
            val messageDigest = MessageDigest.getInstance("SHA256")
            messageDigest.update(tmp.toByteArray())
            Base64.encodeToString(messageDigest.digest(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (ex: NoSuchAlgorithmException) {
            Log.e(TAG, "KeyID could not be generated", ex)
            null
        }
    }

    fun getKeyStoreAlias(appID: String, keyID: String): String? {
        val appIdHash = getAppIdHash(appID)
        return if (appIdHash != null) {
            "$appIdHash:$keyID"
        } else {
            null
        }
    }

    fun getAppIdHash(appID: String): String? {
        return try {
            val messageDigest = MessageDigest.getInstance("SHA256")
            messageDigest.update(appID.toByteArray())
            Base64.encodeToString(messageDigest.digest(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (ex: NoSuchAlgorithmException) {
            Log.e(TAG, "AppID hash could not be generated", ex)
            null
        }
    }

    fun getPublicKeyForKeyId(keyId: String, appId: String): PublicKey? {
        return try {
            val keyAlias = getKeyStoreAlias(appId, keyId) ?: return null
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

            val storedKeyAlias = keyStore.aliases().toList().find { it.startsWith(keyAlias) }
                    ?: return null

            val entry = keyStore.getEntry(storedKeyAlias, null)
            (entry as KeyStore.PrivateKeyEntry).certificate.publicKey
        } catch (ex: Exception) {
            Log.e(TAG, "Could not get public key for keyId: $keyId and appId: $appId", ex)
            null
        }
    }

    fun deleteKey(keyId: String, appId: String) {
        try {
            val keyAlias = getKeyStoreAlias(appId, keyId) ?: return
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

            val storedKeyAlias = keyStore.aliases().toList().find { it.startsWith(keyAlias) }
                    ?: return

            keyStore.deleteEntry(storedKeyAlias)
        } catch (ex: Exception) {
            Log.e(TAG, "Could not delete key with keyId: $keyId and appId: $appId", ex)
        }
    }

    fun getSignatureForKeyID(keyId: String, signedData: ByteArray, appId: String): ByteArray? {
        try {
            val keyAlias = getKeyStoreAlias(appId, keyId)
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

            val entry = keyStore.getEntry(keyAlias, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                return null
            }

            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(entry.privateKey)
            signature.update(signedData)
            return signature.sign()
        } catch (ex: Exception) {
            Log.e(TAG, "could not generate signature for keyId: $keyId and appId: $appId", ex)
            return null
        }
    }
}
