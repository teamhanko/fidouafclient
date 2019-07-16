package io.hanko.fidouafclient.asm.msgs.request;

import com.google.gson.Gson;

import io.hanko.fidouafclient.client.msg.Extension;

public class ASMRequestDereg extends ASMRequest {
    public short authenticatorIndex;
    public DeregisterIn args;
    public Extension[] exts;

    public static ASMRequestDereg fromJson(String json) {
        return new Gson().fromJson(json, ASMRequestDereg.class);
    }
}
