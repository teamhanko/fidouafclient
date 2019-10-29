package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass
import io.hanko.fidouafclient.authenticator.msgs.Authenticator
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Util
import java.security.KeyStore

@JsonClass(generateAdapter = true)
class MatchCriteria
(
        val aaid: List<String>? = null,
        val vendorID: List<String>? = null,
        val keyIDs: List<String>? = null,
        val userVerification: Long? = null,
        val keyProtection: Int? = null,
        val matcherProtection: Int? = null,
        val attachmentHint: Long? = null,
        val tcDisplay: Int? = null,
        val authenticationAlgorithms: List<Int>? = null,
        val assertionSchemes: List<String>? = null,
        val attestationTypes: List<Int>? = null,
        val authenticatorVersion: Int? = null,
        val exts: List<Extension>? = null
) {

    fun isValid(): Boolean {
        if (exts != null && exts.any { it.id.length > 32 || it.id.isEmpty() }) {
            return false
        }

        if (aaid == null) {
            if (authenticationAlgorithms == null || assertionSchemes == null) {
                return false
            }
        }

        if (aaid != null) {
            if (vendorID != null ||
                    userVerification != null ||
                    keyProtection != null ||
                    matcherProtection != null ||
                    tcDisplay != null ||
                    authenticationAlgorithms != null ||
                    assertionSchemes != null ||
                    attestationTypes != null) {
                return false
            }
        }

        if (keyIDs != null) {
            return keyIDs.all { Util.isBase64UrlEncoded(it) }
        }

        return true
    }

    fun matchesAuthenticator(authenticator: Authenticator, appId: String, isRegistration: Boolean): Boolean {
        if ((aaid != null && aaid.size != 1) || (aaid != null && aaid[0] != authenticator.aaid)) {
            return false
        }

        if ((vendorID != null && vendorID.size != 1) || (vendorID != null && vendorID[0] != authenticator.aaid.split("#")[0])) {
            return false
        }

        if (userVerification != null && userVerification != authenticator.userVerification) {
            return false
        }

        if (keyProtection != null && keyProtection != authenticator.keyProtection.toInt()) {
            return false
        }

        if (matcherProtection != null && matcherProtection != authenticator.matcherProtection.toInt()) {
            return false
        }

        if (attachmentHint != null && attachmentHint != authenticator.attachmentHint) {
            return false
        }

        if (tcDisplay != null && !(tcDisplay != 0x01 || tcDisplay != 0x02 || tcDisplay != 0x03)) {
            return false
        }

        if ((authenticationAlgorithms != null && authenticationAlgorithms.size != 1) || (authenticationAlgorithms != null && authenticationAlgorithms[0] != authenticator.authenticationAlgorithm.toInt())) {
            return false
        }

        if ((assertionSchemes != null && assertionSchemes.size != 1) || (assertionSchemes != null && assertionSchemes[0] != authenticator.assertionScheme)) {
            return false
        }

        if ((attestationTypes != null && attestationTypes.size != 1) || (attestationTypes != null && attestationTypes[0] != authenticator.attestationTypes[0].toInt())) {
            return false
        }

        if (keyIDs != null && !isKeyIdRegisteredForAuthenticator(appId, keyIDs) && isRegistration) {
            return false
        }

        return true
    }

    private fun isKeyIdRegisteredForAuthenticator(appId: String, keyIDs: List<String>): Boolean {
        if (keyIDs.isEmpty() || keyIDs.none { Util.isBase64UrlEncoded(it) }) {
            return false
        }

        val requestedKeyAliases = keyIDs.mapNotNull { Crypto.getKeyStoreAlias(appId, it) }
        val keyStore = KeyStore.getInstance(Crypto.KEYSTORE).apply { load(null) }
        return keyStore.aliases().toList().any { requestedKeyAliases.contains(it) }
    }
}