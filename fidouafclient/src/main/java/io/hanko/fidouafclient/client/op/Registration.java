package io.hanko.fidouafclient.client.op;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg;
import io.hanko.fidouafclient.asm.msgs.request.RegisterIn;
import io.hanko.fidouafclient.asm.msgs.response.RegisterOut;
import io.hanko.fidouafclient.client.MainActivity;
import io.hanko.fidouafclient.client.interfaces.AsmStart;
import io.hanko.fidouafclient.client.interfaces.FacetIds;
import io.hanko.fidouafclient.client.msg.AuthenticatorRegistrationAssertion;
import io.hanko.fidouafclient.client.msg.ChannelBinding;
import io.hanko.fidouafclient.client.msg.FinalChallengeParams;
import io.hanko.fidouafclient.client.msg.RegistrationRequest;
import io.hanko.fidouafclient.client.msg.RegistrationResponse;
import io.hanko.fidouafclient.client.msg.UafRegistrationRequest;
import io.hanko.fidouafclient.client.msg.Version;
import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.utility.ErrorCode;
import io.hanko.fidouafclient.utility.FidoUafUtils;

public class Registration implements FacetIds {

    private String TAG = "Registration";
    private Gson gson;
    private AsmStart activity;
    private String facetId;
    private UafRegistrationRequest registrationRequest = null;
    private String appID;
    private String channelBinding;
    private FinalChallengeParams finalChallengeParams;
    private Context mContext;

    public Registration(Context context, final AsmStart activity, final String facetId, final String channelBinding) {
        this.activity = activity;
        this.mContext = context;
        this.facetId = facetId;
        this.channelBinding = channelBinding;
        this.gson = new Gson();
    }

    public void processRequests(final UafRegistrationRequest[] registrationRequests) {
        for (UafRegistrationRequest regReq : registrationRequests) {
            if (regReq.getHeader().upv.major == 1 && regReq.getHeader().upv.minor == 1) {
                registrationRequest = regReq;
                break;
            }
            if (regReq.getHeader().upv.major == 1 && regReq.getHeader().upv.minor == 0) {
                registrationRequest = regReq;
            }
        }

        if (registrationRequest == null) {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
        } else if (registrationRequest.getHeader().appID == null || registrationRequest.getHeader().appID.isEmpty() || Objects.equals(registrationRequest.getHeader().appID, facetId)) {
            appID = facetId;
            sendToAsm(true);
        } else if (registrationRequest.getHeader().appID.contains("https://")) {
            appID = registrationRequest.getHeader().appID;
            FidoUafUtils.GetTrustedFacetsTask getTrustedFacetsTask = new FidoUafUtils.GetTrustedFacetsTask(this);
            getTrustedFacetsTask.execute(registrationRequest.getHeader().appID);
        } else {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
        }
    }
    
    public void processASMResponse(final RegisterOut registerOut) {
        AuthenticatorRegistrationAssertion registrationAssertion = new AuthenticatorRegistrationAssertion();
        registrationAssertion.assertion = registerOut.assertion;
        registrationAssertion.assertionScheme = registerOut.assertionScheme;

        RegistrationResponse[] registrationResponse = new RegistrationResponse[1];
        registrationResponse[0] = new RegistrationResponse();
        registrationResponse[0].header = registrationRequest.getHeader();
        registrationResponse[0].fcParams = Base64.encodeToString(gson.toJson(finalChallengeParams).getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        registrationResponse[0].assertions = new AuthenticatorRegistrationAssertion[]{registrationAssertion};

        activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, gson.toJson(registrationResponse));
    }

    private void sendToAsm(final boolean isFacetIdValid) {
        if (isFacetIdValid) {
            finalChallengeParams = new FinalChallengeParams();
            finalChallengeParams.appID = appID;
            finalChallengeParams.challenge = registrationRequest.getChallenge();
            finalChallengeParams.facetID = facetId;
            finalChallengeParams.channelBinding = gson.fromJson(channelBinding, ChannelBinding.class);

            RegisterIn registerIn = new RegisterIn();
            registerIn.attestationType = 15880; // Attestation Surrogate
            registerIn.username = registrationRequest.getUsername();
            registerIn.appID = appID;
            registerIn.finalChallenge = Base64.encodeToString(gson.toJson(finalChallengeParams).getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            
            ASMRequestReg asmRequestReg = new ASMRequestReg();
            asmRequestReg.asmVersion = registrationRequest.getHeader().upv;
            asmRequestReg.requestType = Request.Register;
            asmRequestReg.authenticatorIndex = 0; // authenticator in this App will always have index = 0
            asmRequestReg.args = registerIn;

            try { // try-catch as workaround for Huawei smartphones, because they won´t call method
                activity.sendToAsm(gson.toJson(asmRequestReg), MainActivity.ASM_REG_REQUEST_CODE, FidoUafUtils.getAsmFromPolicy(mContext, registrationRequest.getPolicy()));
            } catch (Exception e) {
                Log.e(TAG, "Error while sending asmRegistrationRequest to ASM", e);
                activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null);
            }
        } else {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNTRUSTED_FACET_ID, null);
        }
    }

    @Override
    public void processTrustedFacetIds(final String trustedFacetJson) {
        sendToAsm(FidoUafUtils.isFacetIdValid(trustedFacetJson, new Version(1, 0), facetId));
    }
}
