package io.hanko.fidouafclient.utility

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.util.Base64
import android.util.Log
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.google.gson.Gson
import io.hanko.fidouafclient.asm.AsmFingerprintActivity
import io.hanko.fidouafclient.asm.AsmLockscreenActivity
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig
import io.hanko.fidouafclient.client.msg.MatchCriteria
import io.hanko.fidouafclient.client.msg.Policy
import io.hanko.fidouafclient.client.msg.trustedFacets.TrustedFacetsList
import io.hanko.fidouafclient.client.msg.Version
import kotlinx.coroutines.*
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.lang.Exception
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object FidoUafUtilsKotlin {

    private val TAG = "FidoUafUtils"
    private val ioScope = CoroutineScope(Dispatchers.IO + Job())
    private val objectMapper = ObjectMapper()
            .registerKotlinModule()
            .registerModule(
                    SimpleModule()
                            .addDeserializer(String::class.java, ForceStringDeserializer())
                            .addDeserializer(Int::class.java, ForceIntDeserializer())
            )
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

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
        return try {
            val trustedFacetList = objectMapper.readValue(trustedFacetsJson, TrustedFacetsList::class.java)
            //Gson().fromJson(trustedFacetsJson, TrustedFacetsList::class.java)

            trustedFacetList.trustedFacets.filter { it.version?.major == version.major && it.version.minor == version.minor }.any {
                it.ids?.contains(facetId) ?: false
            }
        } catch (ex: Exception) {
            Log.w(TAG, "could not validate FacetId", ex)
            false
        }
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
        }.filterNotNull().groupBy { it }.keys

        val disallowedAuthenticators = (policy.disallowed?.map { return@map getAuthenticatorFromMatchCriteria(it, context, appId) }?.filterNotNull() ?: emptyList()).groupBy { it }.keys

        // filter out all disallowed authenticators
        val filteredAuthenticators = (acceptedAuthenticators + disallowedAuthenticators)
                .groupBy { it }
                .filter { it.value.size == 1 }
                .flatMap { it.value }

        return filteredAuthenticators.firstOrNull()
    }

    private fun getAuthenticatorFromMatchCriteria(matchCriteria: MatchCriteria, context: Context, appId: String): String? {
        return when {
            matchCriteria.matchesAuthenticator(AuthenticatorConfig.authenticator, context, appId) && canUseFingerprintAuthenticator(context) -> AuthenticatorConfig.authenticator.aaid
            else -> null
        }
    }

    private fun canUseFingerprintAuthenticator(context: Context): Boolean {
        val fingerprintManager: FingerprintManager? = context.getSystemService(FingerprintManager::class.java)
        return fingerprintManager != null && fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
    }

    private fun canUseLockscreenAuthenticator(context: Context): Boolean {
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
        return aaid == AuthenticatorConfig.authenticator.aaid && fingerprintManager != null && fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
    }

    private fun isLockscreen(context: Context, aaid: String): Boolean {
        val keyguardManager: KeyguardManager? = context.getSystemService(KeyguardManager::class.java)
        return aaid == AuthenticatorConfig.authenticator.aaid && keyguardManager != null && keyguardManager.isDeviceSecure
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

    suspend fun getTrustedFacetsAsync(url: String): String? {
        return withTimeoutOrNull(5000) {
            return@withTimeoutOrNull ioScope.async {
                Log.w(TAG, "Get TrustedFacetList from $url")
//                return@async URL(url).readText()
                return@async getTrustedFacetList(url)
            }.await()
        }
    }

    private suspend fun getTrustedFacetList(url: String): String? {
        val urlConnection = createConnection(url)
        return getTrustedFacetList(urlConnection)
    }

    private suspend fun getTrustedFacetList(urlConnection: HttpURLConnection, count: Int = 0): String? {
        try {
            val httpStatusCode = urlConnection.responseCode
            Log.w(TAG, "HttpStatusCode: $httpStatusCode")
            return if ((httpStatusCode == HttpURLConnection.HTTP_MOVED_PERM
                            || httpStatusCode == HttpURLConnection.HTTP_MOVED_TEMP
                            || httpStatusCode == HttpURLConnection.HTTP_SEE_OTHER)
                    && count < 5) { // redirect only if http status code indicates redirect and follow redirect only 5 times, so we can't get stuck in a redirect loop
                val redirectAuthorizationHeader = urlConnection.getHeaderField("FIDO-AppID-Redirect-Authorized")?.toBoolean()
                if (redirectAuthorizationHeader == true) {
                    val newUrl = urlConnection.getHeaderField("Location")
                    val newConnection = createConnection(newUrl)
                    getTrustedFacetList(newConnection, count + 1)
                } else {
                    null
                }
            } else if (httpStatusCode == HttpURLConnection.HTTP_OK || httpStatusCode == HttpURLConnection.HTTP_CREATED) {
                readStream(urlConnection.inputStream)
            } else {
                null
            }
        } catch (ex: Exception) {
            return null
        } finally {
            urlConnection.disconnect()
        }
    }

    private fun readStream(stream: InputStream): String {
        return stream.bufferedReader().use { it.readText() }
    }

    private suspend fun createConnection(urlString: String, method: String = "GET", output: Boolean = false): HttpURLConnection {
        val url = URL(urlString)
        val urlConnection = url.openConnection() as HttpURLConnection
        urlConnection.doOutput = output
        urlConnection.requestMethod = method
        urlConnection.useCaches = false
        urlConnection.connectTimeout = 1000
        urlConnection.readTimeout = 1000
        urlConnection.setRequestProperty("Content-Type", "application/json")
        urlConnection.instanceFollowRedirects = false
        urlConnection.connect()

        return urlConnection
    }
}