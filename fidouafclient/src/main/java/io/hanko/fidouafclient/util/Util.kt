package io.hanko.fidouafclient.util

import android.util.Base64
import android.util.Log
import com.squareup.moshi.Moshi
import java.net.URL

object Util {

    const val INTENT_MESSAGE_NAME = "message"

    val moshi: Moshi = Moshi.Builder()
            .add(OptionalStringJsonAdapter())
            .add(OptionalLongJsonAdapter())
            .add(OptionalIntJsonAdapter())
            .add(StringJsonAdapter())
            .add(IntJsonAdapter())
            .add(LongJsonAdapter())
            .build()

    fun isValidHttpsUrl(urlString: String?): Boolean {
        return try {
            urlString?.let {
                val url = URL(urlString)
                return@let url.protocol == "https"
            } ?: false
        } catch (ex: Exception) {
            Log.e("Util", "Malformed url", ex)
            false
        }
    }

    fun isBase64UrlEncoded(string: String): Boolean {
        val regex = "[a-zA-z0-9\\-_]*".toRegex() // check if string contains only allowed base64 url characters (a-z, A-Z, 0-9, -, _)
        return regex.matches(string) && canDecodeBase64Url(string)
    }

    private fun canDecodeBase64Url(string: String): Boolean {
        return try {
            Base64.decode(string, Base64.URL_SAFE).isNotEmpty()
        } catch (ex: Exception) {
            false
        }
    }
}