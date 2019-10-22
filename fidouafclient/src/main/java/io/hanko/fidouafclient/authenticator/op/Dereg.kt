package io.hanko.fidouafclient.authenticator.op

import android.content.Context
import io.hanko.fidouafclient.asm.msgs.StatusCode
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse
import io.hanko.fidouafclient.util.Crypto
import io.hanko.fidouafclient.util.Preferences
import io.hanko.fidouafclient.util.Util

class Dereg(context: Context) {

    private val sharedPreferences = Preferences.create(context, Preferences.PREFERENCE)

    fun dereg(asmRequestDereg: ASMRequestDereg): String {
        asmRequestDereg.args.map {
            Crypto.deleteKey(it.keyID, it.appID)
            Preferences.deleteParam(sharedPreferences, Crypto.getKeyStoreAlias(it.appID, it.keyID) ?: "")
        }

        val asmResponse = ASMResponse()
        asmResponse.statusCode = StatusCode.UAF_ASM_STATUS_OK.id
        return Util.objectMapper.writeValueAsString(asmResponse)
    }
}
