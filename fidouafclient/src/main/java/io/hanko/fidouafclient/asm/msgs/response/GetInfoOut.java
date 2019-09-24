package io.hanko.fidouafclient.asm.msgs.response;

public class GetInfoOut {
    public AuthenticatorInfo[] Authenticators;

    public GetInfoOut(AuthenticatorInfo authenticatorInfo) {
        Authenticators = new AuthenticatorInfo[] { authenticatorInfo };
    }
}
