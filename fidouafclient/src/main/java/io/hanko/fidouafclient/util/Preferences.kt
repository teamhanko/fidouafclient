package io.hanko.fidouafclient.util;

import android.content.Context
import android.content.SharedPreferences

object Preferences {

    const val FINGERPRINT_PREFERENCE = "FidoASMPreferences"
    const val LOCKSCREEN_PREFERENCE = "FidoLockscreenPreferences"
    const val PREFERENCE = "FIDO_ASM_PREFERENCE"

    fun create(c: Context, name: String): SharedPreferences {
        return c.getSharedPreferences(name, Context.MODE_PRIVATE)
    }

    fun setParam(preferences: SharedPreferences, paramName: String, paramValue: String) {
        val editor = preferences.edit()
        editor.putString(paramName, paramValue)
        editor.apply()
    }

    fun getParam(preferences: SharedPreferences, paramName: String): String? {
        return preferences.getString(paramName, "")
    }

    fun deleteParam(preferences: SharedPreferences, paramName: String) {
        preferences.edit().remove(paramName).apply()
    }
}
