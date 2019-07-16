package io.hanko.fidouafclient.asm.msgs.response;

import io.hanko.fidouafclient.client.msg.Extension;

public class ASMResponse {
    public short statusCode; // id of type ASM-StatusCode
    public Extension[] exts;
}
