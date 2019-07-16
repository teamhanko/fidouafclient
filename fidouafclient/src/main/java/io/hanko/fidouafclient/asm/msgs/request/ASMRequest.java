package io.hanko.fidouafclient.asm.msgs.request;

import com.google.gson.Gson;

import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.client.msg.Version;

public class ASMRequest {
    public Request requestType;
    public Version asmVersion;

    public ASMRequest(){}

    public static ASMRequest fromJson(String json) {
        ASMRequest request = new Gson().fromJson(json, ASMRequest.class);
        switch (request.requestType) {
            case Register: return ASMRequestReg.fromJson(json);
            case Authenticate: return ASMRequestAuth.fromJson(json);
            case Deregister: return ASMRequestDereg.fromJson(json);
            default: return request;
        }
    }
}
