package io.hanko.fidouafclient.client;

import android.content.Intent;
import android.os.Bundle;

import java.util.Objects;

import io.hanko.fidouafclient.client.msg.client.UAFIntentType;

public class ClientUtil {

    public static String expectedIntentType = "application/fido.uaf_client+json";

    public static boolean validateRequestIntent(Intent requestIntent) {
        Bundle extras = requestIntent.getExtras();

        // return false if not all necessary fields are available
        return !(extras == null || extras.isEmpty() || !extras.containsKey("UAFIntentType") || !Objects.equals(requestIntent.getType(), expectedIntentType));
    }

    public static UAFIntentType getReturnIntentType(Intent requestIntent) {
        String intentType = requestIntent.getStringExtra("UAFIntentType");


        UAFIntentType returnIntentType = null;
        if (intentType != null) {
            switch (intentType) {
                case "DISCOVER":
                    returnIntentType = UAFIntentType.DISCOVER_RESULT;
                    break;
                case "CHECK_POLICY":
                    returnIntentType = UAFIntentType.CHECK_POLICY_RESULT;
                    break;
                case "UAF_OPERATION":
                    returnIntentType = UAFIntentType.UAF_OPERATION_RESULT;
                    break;
                default:
                    break;
            }
        }

        return returnIntentType;
    }

    //public static boolean canFulfillPolicy(Policy policy) {
    //    for(MatchCriteria disallowed : policy.disallowed) {
    //        if (disallowed.aaid.length > 0) {
    //            return disallowed.aaid[0] == AuthenticatorConfig.authenticator_lockscreen.aaid || disallowed.aaid[0] == AuthenticatorConfig.authenticator_fingerprint.aaid;
    //        }
    //    }
    //}
}
