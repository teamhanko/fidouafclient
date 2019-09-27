package io.hanko.fidouafclient.client.op;

import android.content.Context;
import android.util.Log;

import com.google.gson.Gson;

import java.util.Objects;

import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg;
import io.hanko.fidouafclient.asm.msgs.request.DeregisterIn;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.client.MainActivity;
import io.hanko.fidouafclient.client.interfaces.AsmStart;
import io.hanko.fidouafclient.client.msg.DeregisterAuthenticator;
import io.hanko.fidouafclient.client.msg.UafDeregistrationRequest;
import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.utility.ErrorCode;
import io.hanko.fidouafclient.utility.FidoUafUtils;

public class Deregistration {

    private Gson gson;
    private AsmStart activity;
    private String facetId;
    private String channelBinding;
    private Context mContext;

    public Deregistration(Context context, final AsmStart activity, final String facetId, final String channelBinding) {
        this.activity = activity;
        this.mContext = context;
        this.facetId = facetId;
        this.channelBinding = channelBinding;
        this.gson = new Gson();
    }

    public void processRequests(final UafDeregistrationRequest[] deregistrationRequests) {
        String keyId = "";
        String aaid = "";

        for (UafDeregistrationRequest deregistrationRequest : deregistrationRequests) {
            for (DeregisterAuthenticator deregisterAuthenticator : deregistrationRequest.getAuthenticators()) {
                if (Objects.equals(deregisterAuthenticator.getAaid(), AuthenticatorConfig.authenticator_fingerprint.aaid) || Objects.equals(deregisterAuthenticator.getAaid(), AuthenticatorConfig.authenticator_lockscreen.aaid)) {
                    keyId = deregisterAuthenticator.getKeyID();
                    aaid = deregisterAuthenticator.getAaid();
                }
            }
        }

        DeregisterIn deregisterIn = new DeregisterIn();
        deregisterIn.appID = deregistrationRequests[0].getHeader().getAppID();
        deregisterIn.keyID = keyId;

        ASMRequestDereg asmRequestDereg = new ASMRequestDereg();
        asmRequestDereg.authenticatorIndex = 0;
        asmRequestDereg.requestType = Request.Deregister;
        asmRequestDereg.exts = null;
        asmRequestDereg.asmVersion = deregistrationRequests[0].getHeader().getUpv();
        asmRequestDereg.args = deregisterIn;

        try {
            activity.sendToAsm(gson.toJson(asmRequestDereg), MainActivity.ASM_DEREG_REQUEST_CODE, FidoUafUtils.getAsmFromAaid(mContext, aaid));
        } catch (Exception e) {
            Log.e("Deregistration", "Error while sending asmDeregRequest to ASM", e);
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null);
        }
    }
    
    public void processASMResponse() {
        activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, null);
    }
}
