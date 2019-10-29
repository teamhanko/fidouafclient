package io.hanko.fidouafclient.util

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import android.util.Log
import io.hanko.fidouafclient.asm.AsmActivity
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata
import io.hanko.fidouafclient.client.msg.MatchCriteria
import io.hanko.fidouafclient.client.msg.Policy
import io.hanko.fidouafclient.client.msg.Version
import io.hanko.fidouafclient.client.msg.client.UAFIntentType
import io.hanko.fidouafclient.client.msg.trustedFacets.TrustedFacetsList
import kotlinx.coroutines.*
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object ClientUtil {

    private val TAG = "ClientUtil"
    private val ioScope = CoroutineScope(Dispatchers.IO + Job())
    private const val expectedIntentType = "application/fido.uaf_client+json"

    fun validateRequestIntent(requestIntent: Intent): Boolean {
        val extras = requestIntent.extras

        // return false if not all necessary fields are available
        return extras != null && !extras.isEmpty && extras.containsKey("UAFIntentType") && requestIntent.type == expectedIntentType
    }

    fun getReturnIntentType(requestIntent: Intent): UAFIntentType? {
        return when(requestIntent.getStringExtra("UAFIntentType")) {
            "DISCOVER" -> UAFIntentType.DISCOVER_RESULT
            "CHECK_POLICY" -> UAFIntentType.CHECK_POLICY_RESULT
            "UAF_OPERATION" -> UAFIntentType.UAF_OPERATION_RESULT
            else -> null
        }
    }

    fun getFacetIDWithName(context: Context, packageName: String): String? {
        try {
            val cert = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                info.signingInfo.signingCertificateHistory[0].toByteArray()
            } else {
                val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                info.signatures[0].toByteArray()
            }
            val input = ByteArrayInputStream(cert)

            val cf = CertificateFactory.getInstance("X509")
            val c = cf.generateCertificate(input) as X509Certificate

            val md = MessageDigest.getInstance("SHA1")

            return "android:apk-key-hash:" + Base64.encodeToString(md.digest(c.encoded), Base64.DEFAULT or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (ex: Exception) {
            Log.e(TAG, "Error while getting FacetID", ex)
        }

        return null
    }

    fun isFacetIdValid(trustedFacetsJson: String, version: Version, facetId: String): Boolean {
        return try {
            val trustedFacetList = Util.moshi.adapter(TrustedFacetsList::class.java).fromJson(trustedFacetsJson) ?: TrustedFacetsList(emptyList())

            trustedFacetList.trustedFacets.filter { it.version?.major == version.major && it.version.minor == version.minor }.any {
                it.ids?.contains(facetId) ?: false
            }
        } catch (ex: Exception) {
            Log.w(TAG, "FacetId could not be validated", ex)
            false
        }
    }

    fun canEvaluatePolicy(policy: Policy, appId: String): Boolean {
        val authenticator = extractPreferredAuthenticatorAaidFromPolicy(policy, appId, false)
        return authenticator != null
    }

    private fun extractPreferredAuthenticatorAaidFromPolicy(policy: Policy, appId: String, isRegistration: Boolean): String? {
        val acceptedAuthenticators = policy.accepted.map {
            if (it.size == 1) {
                return@map getAuthenticatorFromMatchCriteria(it.first(), appId, isRegistration)
            } else {
                return@map null
            }
        }.filterNotNull().groupBy { it }.keys

        val disallowedAuthenticators = (policy.disallowed?.map { return@map getAuthenticatorFromMatchCriteria(it, appId, isRegistration) }?.filterNotNull() ?: emptyList()).groupBy { it }.keys

        // filter out all disallowed authenticators
        val filteredAuthenticators = (acceptedAuthenticators + disallowedAuthenticators)
                .groupBy { it }
                .filter { it.value.size == 1 }
                .flatMap { it.value }

        return filteredAuthenticators.firstOrNull()
    }

    private fun getAuthenticatorFromMatchCriteria(matchCriteria: MatchCriteria, appId: String, isRegistration: Boolean): String? {
        return when {
            matchCriteria.matchesAuthenticator(AuthenticatorMetadata.authenticator, appId, isRegistration) -> AuthenticatorMetadata.authenticator.aaid
            else -> null
        }
    }

    fun getAsmFromPolicy(policy: Policy, appId: String): Class<*>? {
        val aaid = extractPreferredAuthenticatorAaidFromPolicy(policy, appId, true)
        if (aaid != null && aaid.isNotEmpty()) {
            return getAsmFromAaid(aaid)
        }
        return null
    }

    fun getAsmFromAaid(aaid: String): Class<*>? {
        return when (aaid) {
            AuthenticatorMetadata.authenticator.aaid -> AsmActivity::class.java
            else -> null
        }
    }

    suspend fun getTrustedFacetsAsync(url: String): String? {
        return withTimeoutOrNull(5000) {
            return@withTimeoutOrNull ioScope.async {
                try {
                    Log.w(TAG, "Get TrustedFacetList from $url")
                    return@async getTrustedFacetList(url)
                } catch (ex: Exception) {
                    Log.e(TAG, "Error getting TrustedFacetList", ex)
                    return@async null
                }
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