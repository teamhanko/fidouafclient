package io.hanko.fidouafclient.asm.msgs.request;

import com.google.gson.Gson;

import io.hanko.fidouafclient.client.msg.Extension;

public class ASMRequestReg extends ASMRequest {
    public short authenticatorIndex;
    public RegisterIn args;
    public Extension[] exts;

    public static ASMRequestReg fromJson(String json) {
        return new Gson().fromJson(json, ASMRequestReg.class);
    }
}
