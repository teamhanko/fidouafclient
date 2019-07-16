package io.hanko.fidouafclient.client.interfaces;

import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.utility.ErrorCode;

public interface AsmStart {
    void sendToAsm(String message, int requestCode,  Class<?> activity);
    void sendReturnIntent(UAFIntentType uafIntentType, ErrorCode errorCode, String message);
}
