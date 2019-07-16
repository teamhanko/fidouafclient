package io.hanko.fidouafclient.client;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.google.gson.Gson;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Objects;

import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseReg;
import io.hanko.fidouafclient.client.interfaces.AsmStart;
import io.hanko.fidouafclient.client.msg.AuthenticationRequest;
import io.hanko.fidouafclient.client.msg.DeregistrationRequest;
import io.hanko.fidouafclient.client.msg.RegistrationRequest;
import io.hanko.fidouafclient.client.msg.client.UAFIntentType;
import io.hanko.fidouafclient.client.msg.client.UAFMessage;
import io.hanko.fidouafclient.client.op.Authentication;
import io.hanko.fidouafclient.client.op.Deregistration;
import io.hanko.fidouafclient.client.op.Registration;
import io.hanko.fidouafclient.utility.ErrorCode;
import io.hanko.fidouafclient.utility.FidoUafUtils;

public class MainActivity extends AppCompatActivity implements AsmStart {

    private String TAG = "MainActivity";
    public static String componentName;
    public Gson gson;
    public static String facetId;
    public static int ASM_REG_REQUEST_CODE = 1111;
    public static int ASM_AUTH_REQUEST_CODE = 2222;
    public static int ASM_DEREG_REQUEST_CODE = 3333;

    private Registration registrationProcess;
    private Authentication authenticationProcess;
    private Deregistration deregistrationProcess;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setFinishOnTouchOutside(false);

        gson = new Gson();
        componentName = new ComponentName(getApplicationContext(), MainActivity.class).flattenToString();
        Intent callingIntent = getIntent();
        Bundle extras = callingIntent.getExtras();

        facetId = FidoUafUtils.getFacetID(getApplicationContext(), Binder.getCallingUid());

        try {
            if (extras.isEmpty()) { // if no extras is given even no UAFIntentType
                sendReturnIntent(null, ErrorCode.UNKNOWN, null);
            } else if (extras.containsKey("UAFIntentType")) {
                processUafRequest(extras);
            } else { // if extras don´t contains UAFIntentType
                sendReturnIntent(null, ErrorCode.UNKNOWN, null);
            }
        } catch (Exception ex) {
            if (extras != null) {
                Log.e("FidoClient.MainActivity", extras.toString());
            }
            sendReturnIntent(null, ErrorCode.UNKNOWN, null);
        }
    }

    private void processUafRequest(Bundle extras) {

        String uafIntentType = extras.getString("UAFIntentType");
        if (Objects.equals(uafIntentType, UAFIntentType.DISCOVER.name())) {
            // return Discover Data
            // TODO: 06.04.2017 return AuthenticatorDiscoveryData
        } else if (Objects.equals(uafIntentType, UAFIntentType.CHECK_POLICY.name())) {
            // TODO: 06.04.2017 check Policy against available Authenticators

            sendReturnIntent(UAFIntentType.CHECK_POLICY_RESULT, ErrorCode.NO_ERROR, null);
        } else if (Objects.equals(uafIntentType, UAFIntentType.UAF_OPERATION.name())) {
            String channelBinding = null;
            String message = null;
            if ((channelBinding = extras.getString("channelBindings")) != null && (message = extras.getString("message")) != null) {
                String uafOperationMessage = extractUafOperationMessage(message);
                processUafRequest(uafOperationMessage, channelBinding);
            } else {
                // no channelBinding and message are given, but are required
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null);
            }
        } else {
            // if unknown UAFIntentType
            sendReturnIntent(null, ErrorCode.UNKNOWN, null);
        }
    }

    private void processUafRequest(String uafOperationMessage, String channelBinding) {

        if (uafOperationMessage.contains("\"Reg\"")) {
            // process RegistrationRequest
            RegistrationRequest[] registrationRequests = gson.fromJson(uafOperationMessage, RegistrationRequest[].class);
            if (registrationRequests.length > 0) {
                registrationProcess = new Registration(this, this, facetId, channelBinding);
                registrationProcess.processRequests(registrationRequests);
            } else {
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
            }
        } else if (uafOperationMessage.contains("\"Auth\"")) {
            // process AuthenticationRequest
            AuthenticationRequest[] authenticationRequests = gson.fromJson(uafOperationMessage, AuthenticationRequest[].class);
            if (authenticationRequests.length > 0) {
                authenticationProcess = new Authentication(this, this, facetId, channelBinding);
                authenticationProcess.processRequests(authenticationRequests);
            } else {
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
            }
        } else if (uafOperationMessage.contains("\"Dereg\"")) {
            // process DeregistrationRequest
            DeregistrationRequest[] deregistrationRequests = gson.fromJson(uafOperationMessage, DeregistrationRequest[].class);
            if (deregistrationRequests.length > 0) {
                deregistrationProcess = new Deregistration(this, this, facetId, channelBinding);
                deregistrationProcess.processRequests(deregistrationRequests);
            } else {
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.PROTOCOL_ERROR, null);
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null);
        }
    }

    private String extractUafOperationMessage(String uafmessage) {
        return gson.fromJson(uafmessage, UAFMessage.class).uafProtocolMessage;
    }

    /**
     * return Intent to calling App
     *
     * @param resultCode
     * @param resultIntent
     */
    private void returnUafResponse(int resultCode, Intent resultIntent) {
        setResult(resultCode, resultIntent);
        finishAndRemoveTask();
    }

    /**
     * build an Intent which will be returned to calling App
     *
     * @param uafIntentType
     * @param errorCode
     * @param message
     */
    public void sendReturnIntent(UAFIntentType uafIntentType, ErrorCode errorCode, String message) {
        String uafIntentTypeString = uafIntentType == null ? "undefined" : uafIntentType.name();
        Intent resultIntent = new Intent();
        if (message != null) {
            JSONObject jsonObject = new JSONObject();
            try {
                jsonObject.put("uafProtocolMessage", message);
                resultIntent.putExtra("message", jsonObject.toString());
            } catch (JSONException e) {
                Log.e(TAG, e.getMessage());
                sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.UNKNOWN, null);
            }
        }
        resultIntent.putExtra("UAFIntentType", uafIntentTypeString);
        resultIntent.putExtra("componentName", componentName);
        resultIntent.putExtra("errorCode", errorCode.getID());
        returnUafResponse(RESULT_OK, resultIntent);
    }

    /**
     * send ASMRequest to ASM
     *
     * @param message
     * @param requestCode
     */
    public void sendToAsm(String message, int requestCode, Class<?> activity) {
//        Intent asmIntent = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        if (activity != null) {
            Intent asmIntent = new Intent(this, activity); // send Request to our ASM and don´t give the User the choice if there are more than our ASM
            asmIntent.setType("application/fido.uaf_asm+json");
            asmIntent.putExtra("message", message);

            startActivityForResult(asmIntent, requestCode);
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.NO_SUITABLE_AUTHENTICATOR, "");
        }
    }

    /**
     * get result from ASM and process ASMResponse accordingly by Operation
     *
     * @param requestCode
     * @param resultCode
     * @param data
     */
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (data != null) {
            // Operation is identified by requestCode
            String message = data.getStringExtra("message");
            ASMResponse asmResponse = gson.fromJson(message, ASMResponse.class);
            if (requestCode == ASM_REG_REQUEST_CODE) {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.getID())
                    registrationProcess.processASMResponse(gson.fromJson(message, ASMResponseReg.class).responseData);
                else
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null);
            } else if (requestCode == ASM_AUTH_REQUEST_CODE) {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.getID())
                    authenticationProcess.processASMResponse(gson.fromJson(message, ASMResponseAuth.class).responseData);
                else
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null);
            } else {
                if (asmResponse.statusCode == StatusCode.UAF_ASM_STATUS_OK.getID()) {
                    deregistrationProcess.processASMResponse();
                } else {
                    sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, convertStatusCodeToErrorCode(asmResponse.statusCode), null);
                }
            }
        } else {
            sendReturnIntent(UAFIntentType.UAF_OPERATION_RESULT, ErrorCode.USER_CANCELLED, null);
        }
    }

    private ErrorCode convertStatusCodeToErrorCode(short statusCode) {
        if (statusCode == StatusCode.UAF_ASM_STATUS_USER_CANCELLED.getID()) {
            return ErrorCode.USER_CANCELLED;
        } else if (statusCode == StatusCode.UAF_ASM_STATUS_OK.getID()) {
            return ErrorCode.NO_ERROR;
        } else if (statusCode == StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY.getID()) {
            return ErrorCode.KEY_DISAPPEARED_PERMANENTLY;
        } else {
            return ErrorCode.UNKNOWN;
        }
    }
}
