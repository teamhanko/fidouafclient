package io.hanko.fidouafclient.utility

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import io.hanko.fidouafclient.asm.AsmFingerprintActivity
import io.hanko.fidouafclient.asm.AsmLockscreenActivity
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig
import io.hanko.fidouafclient.authenticator.msgs.Authenticator
import io.hanko.fidouafclient.client.msg.MatchCriteria
import io.hanko.fidouafclient.client.msg.Policy
import io.hanko.fidouafclient.client.msg.TrustedFacets.TrustedFacetsList
import io.hanko.fidouafclient.client.msg.Version
import kotlinx.coroutines.*
import java.io.ByteArrayInputStream
import java.lang.Exception
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object FidoUafUtilsKotlin {

    private val TAG = "FidoUafUtils"
    private val ioScope = CoroutineScope(Dispatchers.IO + Job())

    fun getFacetId(context: Context, callingUid: Int): String? {
        val packageNames: Array<String> = context.packageManager.getPackagesForUid(callingUid)
                ?: return null

        if (packageNames.isEmpty()) {
            return null
        }

        try {
            val packageInfo = context.packageManager.getPackageInfo(packageNames[0], PackageManager.GET_SIGNATURES)

            val certBytes = packageInfo.signatures[0].toByteArray()
            val input = ByteArrayInputStream(certBytes)

            val cf = CertificateFactory.getInstance("X509")
            val cert = cf.generateCertificate(input) as X509Certificate

            val md = MessageDigest.getInstance("SHA1")

            return "android:apk-key-hash:" + Base64.encodeToString(md.digest(cert.encoded), Base64.DEFAULT or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (ex: Exception) {
            Log.e(TAG, "Error while calculating FacetID", ex)
            return null
        }
    }

    fun isFacetIdValid(trustedFacetsJson: String, version: Version, facetId: String): Boolean {
        val trustedFacetList = Gson().fromJson(trustedFacetsJson, TrustedFacetsList::class.java)

        return trustedFacetList.trustedFacets.filter { it.version == version }.any { it.ids.contains(facetId) }
    }

    fun canEvaluatePolicy(context: Context, policy: Policy, appId: String): Boolean {
        val authenticator = extractPreferredAuthenticatorAaidFromPolicy(context, policy, appId)
        return authenticator != null
    }

    fun extractPreferredAuthenticatorAaidFromPolicy(context: Context, policy: Policy, appId: String): String? {
        val acceptedAuthenticators = policy.accepted.map {
            if (it.size == 1) {
                return@map getAuthenticatorFromMatchCriteria(it.first(), context, appId)
            } else {
                return@map null
            }
        }.filterNotNull()

        val disallowedAuthenticators = policy.disallowed.map { return@map getAuthenticatorFromMatchCriteria(it, context, appId) }.filterNotNull()

        // filter out all disallowed authenticators
        val filteredAuthenticators = (acceptedAuthenticators + disallowedAuthenticators)
                .groupBy { it }
                .filter { it.value.size == 1 }
                .flatMap { it.value }

        return filteredAuthenticators.firstOrNull()
    }

    private fun getAuthenticatorFromMatchCriteria(matchCriteria: MatchCriteria, context: Context, appId: String): String? {
        return when {
            matchCriteria.matchesAuthenticator(AuthenticatorConfig.authenticator_fingerprint, context, appId) && canUseFingerprintAuthenticator(context) -> AuthenticatorConfig.authenticator_fingerprint.aaid
            matchCriteria.matchesAuthenticator(AuthenticatorConfig.authenticator_lockscreen, context, appId) && canUseLockscreenAuthenticator(context) -> AuthenticatorConfig.authenticator_lockscreen.aaid
            else -> null
        }
    }

    fun canUseFingerprintAuthenticator(context: Context): Boolean {
        val fingerprintManager: FingerprintManager? = context.getSystemService(FingerprintManager::class.java)
        return fingerprintManager != null && fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
    }

    fun canUseLockscreenAuthenticator(context: Context): Boolean {
        val keyguardManager: KeyguardManager? = context.getSystemService(KeyguardManager::class.java)
        return keyguardManager != null && keyguardManager.isDeviceSecure
    }

    fun getAsmFromPolicy(context: Context, policy: Policy, appId: String): Class<*>? {
        val aaid = extractPreferredAuthenticatorAaidFromPolicy(context, policy, appId)
        if (aaid != null && aaid.isNotEmpty()) {
            return getAsmFromAaid(context, aaid)
        }
        return null
    }

    fun getAsmFromAaid(context: Context, aaid: String): Class<*>? {
        return when {
            isFingerprint(context, aaid) -> AsmFingerprintActivity::class.java
            isLockscreen(context, aaid) -> AsmLockscreenActivity::class.java
            else -> null
        }
    }

    private fun isFingerprint(context: Context, aaid: String): Boolean {
        val fingerprintManager: FingerprintManager? = context.getSystemService(FingerprintManager::class.java)
        return aaid == AuthenticatorConfig.authenticator_fingerprint.aaid && fingerprintManager != null && fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
    }

    private fun isLockscreen(context: Context, aaid: String): Boolean {
        val keyguardManager: KeyguardManager? = context.getSystemService(KeyguardManager::class.java)
        return aaid == AuthenticatorConfig.authenticator_lockscreen.aaid && keyguardManager != null && keyguardManager.isDeviceSecure
    }

    fun getAsmFromKeyId(context: Context, appId: String, keyIds: Array<String>): GetAsmResponse? {
        val lockscreenPref = Preferences.create(context, Preferences.LOCKSCREEN_PREFERENCE)
        val fingerprintPref = Preferences.create(context, Preferences.FINGERPRINT_PREFERENCE)

        val lockscreenKeyIds = Preferences.getParamSet(lockscreenPref, appId)
        val fingerprintKeyIds = Preferences.getParamSet(fingerprintPref, appId)

        return keyIds.map {
            when {
                fingerprintKeyIds.contains(it) -> return@map GetAsmResponse(AsmFingerprintActivity::class.java, it)
                lockscreenKeyIds.contains(it) -> return@map GetAsmResponse(AsmLockscreenActivity::class.java, it)
                else -> return@map null
            }
        }.filterNotNull().firstOrNull()
    }

    fun getTrustedFacets(url: String): Deferred<String?> {
        return ioScope.async {
            return@async withTimeoutOrNull(5000) {
                return@withTimeoutOrNull Curl.get(url).payload
            }
        }
    }
}