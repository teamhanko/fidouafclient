package io.hanko.fidouafclient.asm.msgs.request;

import com.google.gson.Gson;

import io.hanko.fidouafclient.client.msg.Extension;

public class ASMRequestAuth extends ASMRequest {
    public short authenticatorIndex;
    public AuthenticateIn args;
    public Extension[] exts;

    public static ASMRequestAuth fromJson(String json) {
        return new Gson().fromJson(json, ASMRequestAuth.class);
    }
}
