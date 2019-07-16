package io.hanko.fidouafclient.authenticator.fingerprint;

import android.content.Context;
import android.content.SharedPreferences;

import com.google.gson.Gson;

import java.util.Set;

import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.utility.Crypto;
import io.hanko.fidouafclient.utility.Preferences;

public class Dereg {

    private SharedPreferences sharedPreferences;

    public Dereg(Context context) {
        sharedPreferences = Preferences.create(context, Preferences.FINGERPRINT_PREFERENCE);
    }

    public String dereg(final ASMRequestDereg asmRequestDereg) {
        Set<String> keyIds = Preferences.getParamSet(sharedPreferences, asmRequestDereg.args.appID);
        keyIds.remove(asmRequestDereg.args.keyID);
        Crypto.deleteKey(asmRequestDereg.args.keyID);

        ASMResponse asmResponse = new ASMResponse();
        asmResponse.statusCode = StatusCode.UAF_ASM_STATUS_OK.getID();
        return new Gson().toJson(asmResponse);
    }
}
