package io.hanko.fidouafclient.utility;

public class GetAsmResponse {
    public Class<?> asmClass;
    public String keyId;

    GetAsmResponse(Class<?> asmClass, String keyId) {
        this.asmClass = asmClass;
        this.keyId = keyId;
    }
}