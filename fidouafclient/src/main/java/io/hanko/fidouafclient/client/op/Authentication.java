package io.hanko.fidouafclient.client.op;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;

import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth;
import io.hanko.fidouafclient.asm.msgs.request.AuthenticateIn;
import io.hanko.fidouafclient.asm.msgs.response.AuthenticateOut;
import io.hanko.fidouafclient.client.MainActivity;
import io.hanko.fidouafclient.client.interfaces.AsmStart;
import io.hanko.fidouafclient.client.interfaces.FacetIds;
import io.hanko.fidouafclient.client.msg.AuthenticationRequest;
import io.hanko.fidouafclient.client.msg.AuthenticationResponse;
import io.hanko.fidouafclient.client.msg.AuthenticatorSignAssertion;
import io.hanko.fidouafclient.client.msg.ChannelBinding;
import io.hanko.fidouafclient.client.msg.FinalChallengeParams;
import io.hanko.fidouafclient.client.msg.MatchCriteria;
import io.hanko.fidouafclient.client.msg.Version;
import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.utility.ErrorCode;
import io.hanko.fidouafclient.utility.FidoUafUtils;
import io.hanko.fidouafclient.utility.GetAsmResponse;

public class Authentication implements FacetIds {

    private String TAG = "Authentication";
    private Gson gson;
    private AsmStart activity;
    private String facetId;
    private String channelBinding;
    private AuthenticationRequest authenticationRequest;
    private String appID;
    private FinalChallengeParams finalChallengeParams;
    private Context mContext;

    public Authentication(Context context, final AsmStart activity, final String facetId, final String channelBinding) {
        this.activity = activity;
        this.mContext = context;
        this.facetId = facetId;
        this.channelBinding = channelBinding;
        this.gson = new Gson();
    }

    public void processRequests(final AuthenticationRequest[] authenticationRequests) {
        for (AuthenticationRequest authReq : authenticationRequests) {
            if (authReq.header.upv.major == 1 && authReq.header.upv.minor == 0) {
                authenticationRequest = authReq;
            }
        }

        if (authenticationRequest == null) {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
        } else if (authenticationRequest.header.appID == null || authenticationRequest.header.appID.isEmpty() || Objects.equals(authenticationRequest.header.appID, facetId)) {
            appID = facetId;
            sendToAsm(true);
        } else if (authenticationRequest.header.appID.contains("https://")){
            appID = authenticationRequest.header.appID;
            FidoUafUtils.GetTrustedFacetsTask getTrustedFacetsTask = new FidoUafUtils.GetTrustedFacetsTask(this);
            getTrustedFacetsTask.execute(authenticationRequest.header.appID);
        } else {
            activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
        }
    }
    
    public void processASMResponse(final AuthenticateOut authenticateOut) {
        AuthenticatorSignAssertion authenticationAssertion = new AuthenticatorSignAssertion();
        authenticationAssertion.assertion = authenticateOut.assertion;
        authenticationAssertion.assertionScheme = authenticateOut.assertionScheme;

        AuthenticationResponse[] authenticationResponse = new AuthenticationResponse[1];
        authenticationResponse[0] = new AuthenticationResponse();
        authenticationResponse[0].header = authenticationRequest.header;
        authenticationResponse[0].fcParams = Base64.encodeToString(gson.toJson(finalChallengeParams).getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        authenticationResponse[0].assertions = new AuthenticatorSignAssertion[]{authenticationAssertion};

        activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_ERROR, gson.toJson(authenticationResponse));
    }

    private void sendToAsm(final boolean isFacetIdValid) {
        if (isFacetIdValid) {
            try { // try-catch as workaround for Huawei smartphones, because they won´t call AsmStart.sendToAsm
                ArrayList<String> keyIds = new ArrayList<>();

                for (MatchCriteria[] matchCriterias : authenticationRequest.policy.accepted) {
                    for (MatchCriteria matchCriteria : matchCriterias) {
                        if (matchCriteria.keyIDs != null && matchCriteria.keyIDs.length > 0) {
                            Collections.addAll(keyIds, matchCriteria.keyIDs);
                        }
                    }
                }

                finalChallengeParams = new FinalChallengeParams();
                finalChallengeParams.appID = appID;
                finalChallengeParams.challenge = authenticationRequest.challenge;
                finalChallengeParams.facetID = facetId;
                finalChallengeParams.channelBinding = gson.fromJson(channelBinding, ChannelBinding.class);

                GetAsmResponse response = FidoUafUtils.getAsmFromKeyId(mContext, appID, keyIds.toArray(new String[keyIds.size()]));

                AuthenticateIn authenticateIn = new AuthenticateIn();
                authenticateIn.appID = appID;
                authenticateIn.finalChallenge = Base64.encodeToString(gson.toJson(finalChallengeParams).getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                if (response == null) {
                    activity.sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, null);
                    return;
                }
                if (response.keyId != null) {
                    authenticateIn.keyIDs = new String[]{response.keyId};
                }
                if (authenticationRequest.transaction != null && authenticationRequest.transaction.length > 0) {
                    authenticateIn.transaction = authenticationRequest.transaction[0];
                } else {
                    authenticateIn.transaction = null;
                }

                ASMRequestAuth asmRequestAuth = new ASMRequestAuth();
                asmRequestAuth.asmVersion = authenticationRequest.header.upv;
                asmRequestAuth.requestType = Request.Authenticate;
                asmRequestAuth.authenticatorIndex = 0;
                asmRequestAuth.args = authenticateIn;

                activity.sendToAsm(gson.toJson(asmRequestAuth), MainActivity.ASM_AUTH_REQUEST_CODE, response.asmClass);
            } catch (Exception e) {
                Log.e(TAG, "Error while creating asmRequest or sending to ASM", e);
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
