package io.hanko.fidouafclient.asm;


import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;

import com.google.gson.Gson;

import io.hanko.fidouafclient.R;
import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequest;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.authenticator.lockscreen.Auth;
import io.hanko.fidouafclient.authenticator.lockscreen.Dereg;
import io.hanko.fidouafclient.authenticator.lockscreen.Reg;

public class AsmLockscreenActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;
    public static String INTENT_MESSAGE = "message";
    private String TAG = "AsmLockscreenActivity";
    private Gson gson;
    private ASMRequest asmRequest;
    private String requestMessage;
    private KeyguardManager mKeyguardManager;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mKeyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

        gson = new Gson();
        Intent requestIntent = getIntent();
        requestMessage = requestIntent.getStringExtra(INTENT_MESSAGE);
        asmRequest = ASMRequest.fromJson(requestMessage);

        if (!mKeyguardManager.isDeviceSecure()) {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.screenlock)
                    .setMessage(R.string.screenlock_msg)
                    .setPositiveButton(R.string.button_go_to_settings, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            startActivity(new Intent(Settings.ACTION_SETTINGS));
                        }
                    }).show()
                    .setOnCancelListener(new DialogInterface.OnCancelListener() {
                        public void onCancel(DialogInterface dialog) {
                            sendErrorResponse(null);
                        }
                    });
        } else {
            if (asmRequest.requestType == Request.Deregister) {
                processDeregistration();
            } else {
                showAuthenticationScreen();
            }
        }
    }

    private void processRegistration() {
        ASMRequestReg asmRequestReg = (ASMRequestReg) asmRequest;
        Reg reg = new Reg(this);
        sendResponse(reg.reg(asmRequestReg));
    }

    private void processAuthentication() {
        ASMRequestAuth asmRequestAuth = (ASMRequestAuth) asmRequest;
        Auth auth = new Auth(this);
        sendResponse(auth.auth(asmRequestAuth));
    }

    private void processDeregistration() {
        ASMRequestDereg asmRequestDereg = (ASMRequestDereg) asmRequest;
        Dereg dereg = new Dereg(this);
        sendResponse(dereg.dereg(asmRequestDereg));
    }

    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            try {
                startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
            } catch (Exception ex) {
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
            }
        } else {
            sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if(resultCode == RESULT_OK) {
                if(asmRequest.requestType == Request.Register) {
                    processRegistration();
                } else if (asmRequest.requestType == Request.Authenticate) {
                    processAuthentication();
                } else {
                    sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
                }
            } else {
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_USER_CANCELLED);
            }
        }
    }

    private void sendErrorResponse(StatusCode statusCode) {
        ASMResponse asmResponse = new ASMResponse();
        if (statusCode != null) {
            asmResponse.statusCode = statusCode.getID();
        } else {
            asmResponse.statusCode = StatusCode.UAF_ASM_STATUS_ERROR.getID();
        }
        sendResponse(gson.toJson(asmResponse));
    }

    private void sendResponse(String asmResponse) {
        Intent responseIntent = new Intent();
        responseIntent.putExtra(INTENT_MESSAGE, asmResponse);
        setResult(RESULT_OK, responseIntent);
        finishAndRemoveTask();
    }
}
