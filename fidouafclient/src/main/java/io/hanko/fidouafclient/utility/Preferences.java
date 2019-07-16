package io.hanko.fidouafclient.utility;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

public class Preferences {

    public static String FINGERPRINT_PREFERENCE = "FidoASMPreferences";
    public static String LOCKSCREEN_PREFERENCE = "FidoLockscreenPreferences";

    public static SharedPreferences create(Context c, String name) {
        return c.getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    public static void setParam(final SharedPreferences preferences, final String paramName, final String paramValue) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(paramName, paramValue);
        editor.apply();
    }

    public static String getParam(final SharedPreferences preferences, final String paramName) {
        return preferences.getString(paramName, "");
    }

    public static Set<String> getParamSet(final SharedPreferences preferences, final String paramName) {
        return preferences.getStringSet(paramName, new HashSet<String>());
    }

    public static void setParamSet(final SharedPreferences preferences, final String paramName, final Set<String> paramValue) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putStringSet(paramName, paramValue);
        editor.commit();
    }
}
