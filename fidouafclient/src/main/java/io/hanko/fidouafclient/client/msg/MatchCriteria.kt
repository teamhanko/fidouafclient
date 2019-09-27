package io.hanko.fidouafclient.client.msg

import android.content.Context
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig
import io.hanko.fidouafclient.authenticator.msgs.Authenticator
import io.hanko.fidouafclient.utility.Preferences

class MatchCriteria
(
        val aaid: List<String>?,
        val vendorID: List<String>?,
        val keyIDs: List<String>?,
        val userVerification: Long?,
        val keyProtection: Int?,
        val matcherProtection: Int?,
        val attachmentHint: Long?,
        val tcDisplay: Int?,
        val authenticationAlgorithms: List<Int>?,
        val assertionSchemes: List<String>?,
        val attestationTypes: List<Int>?,
        val authenticatorVersion: Int?,
        val exts: List<Extension>?
) {

    fun matchesAuthenticator(authenticator: Authenticator, context: Context, appId: String): Boolean {
        if ((aaid != null && aaid[0] != authenticator.aaid) || (aaid != null && aaid.size != 1)) {
            return false
        }

        if ((vendorID != null && vendorID[0] != authenticator.aaid.split("#")[0]) || (vendorID != null && vendorID.size != 1)) {
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

        if (keyIDs != null && !isKeyIdRegisteredForAuthenticator(context, keyIDs, authenticator.aaid, appId)) {
            return false
        }

        return true
    }

    private fun isKeyIdRegisteredForAuthenticator(context: Context, keyIDs: List<String>?, aaid: String, appId: String): Boolean {
        if (keyIDs == null || keyIDs.isEmpty()) {
            return false
        }

        val preferenceName = if (aaid == AuthenticatorConfig.authenticator_fingerprint.aaid) Preferences.FINGERPRINT_PREFERENCE else Preferences.LOCKSCREEN_PREFERENCE
        val sharedPreferences = Preferences.create(context, preferenceName)
        val registeredKeyIds = Preferences.getParamSet(sharedPreferences, appId)

        return registeredKeyIds.any { keyIDs.contains(it) }
    }
}