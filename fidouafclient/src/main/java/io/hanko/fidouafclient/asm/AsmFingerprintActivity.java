package io.hanko.fidouafclient.asm;

import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.gson.Gson;

import java.security.Signature;
import java.util.HashSet;
import java.util.Set;

import io.hanko.fidouafclient.R;
import io.hanko.fidouafclient.asm.msgs.Request;
import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequest;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestDereg;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseGetInfo;
import io.hanko.fidouafclient.asm.msgs.response.AuthenticatorInfo;
import io.hanko.fidouafclient.asm.msgs.response.GetInfoOut;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.authenticator.fingerprint.Auth;
import io.hanko.fidouafclient.authenticator.fingerprint.Dereg;
import io.hanko.fidouafclient.authenticator.fingerprint.Reg;
import io.hanko.fidouafclient.utility.Crypto;
import io.hanko.fidouafclient.utility.Preferences;

import static io.hanko.fidouafclient.asm.FingerprintUiHelper.MY_PERMISSIONS_USE_FINGERPRINT;

public class AsmFingerprintActivity extends AppCompatActivity implements FingerprintUiHelper.Callback {

    private String TAG = "AsmFingerprintActivity";
    public static String INTENT_MESSAGE = "message";
    public Gson gson;
    private FingerprintManager mFingerprintManager;
    private FingerprintUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;
    private FingerprintUiHelper mFingerprintUiHelper;
    private View mFingerprintContent;
    private Button mCancelButton;
    private ProgressBar mProgressBar;
    private ASMRequest asmRequest;
    private String requestMessage;
    private FingerprintManager.CryptoObject mCryptoObject;
    private String newKeyId;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(null);
        setContentView(R.layout.fingerprint_dialog_container);

        setFinishOnTouchOutside(false);
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        SharedPreferences sharedPreferences = Preferences.create(this, Preferences.FINGERPRINT_PREFERENCE);

        gson = new Gson();
        mFingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        mFingerprintUiHelperBuilder = new FingerprintUiHelper.FingerprintUiHelperBuilder(mFingerprintManager);
        Intent requestIntent = getIntent();
        requestMessage = requestIntent.getStringExtra(INTENT_MESSAGE);
        asmRequest = ASMRequest.fromJson(requestMessage);

        mFingerprintContent = findViewById(R.id.fingerprint_container);
        mProgressBar = (ProgressBar) findViewById(R.id.progressBar);
        mCancelButton = (Button) findViewById(R.id.cancel_button);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_USER_CANCELLED);
            }
        });

        mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                (ImageView) findViewById(R.id.fingerprint_icon),
                (TextView) findViewById(R.id.fingerprint_status),
                this
        );

        if (asmRequest.requestType == Request.GetInfo) {
            ASMResponseGetInfo asmResponseGetInfo = new ASMResponseGetInfo();
            asmResponseGetInfo.responseData = new GetInfoOut(AuthenticatorInfo.Companion.fromAuthenticator(AuthenticatorConfig.INSTANCE.getAuthenticator(), mFingerprintManager.hasEnrolledFingerprints()));

            sendResponse(gson.toJson(asmResponseGetInfo));
            finish();
        } else if (asmRequest.requestType == Request.GetRegistrations) {
            sendResponse("");
            finish();
        }

        if (!mFingerprintUiHelper.isFingerprintAuthAvailable(this)) {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.fingerprint_not_enrolled)
                    .setMessage(R.string.fingerprint_not_enrolled_msg)
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
            if (asmRequest.requestType == Request.Register) {
                startRegistration(sharedPreferences);
                //ASMRequestReg asmRequestReg = gson.fromJson(requestMessage, ASMRequestReg.class);
                //newKeyId = Crypto.generateKeyID(asmRequestReg.args.appID);
//
                //if(Crypto.generateKeyPair(newKeyId)) {
                //    // TODO: we could skip the save, we can use `KeyStore.aliases` for this, but we have to distinguish between fingerprint and lockscreen and for already created keys this is not so easy
                //    // add newly created keyId to SharedPreferences, so we recognize it when it is used for authentication
                //    Set<String> keyIds = Preferences.getParamSet(sharedPreferences, asmRequestReg.args.appID);
                //    Set<String> newKeyIds = new HashSet<>(keyIds);
                //    newKeyIds.add(newKeyId);
                //    Preferences.setParamSet(sharedPreferences, asmRequestReg.args.appID, newKeyIds);
//
                //    Signature signature = Crypto.getSignatureInstance(newKeyId);
                //    if (signature != null) {
                //        mCryptoObject = new FingerprintManager.CryptoObject(signature);
                //        mFingerprintContent.setVisibility(View.VISIBLE);
                //        mFingerprintUiHelper.startListening(mCryptoObject, this);
                //    } else {
                //        sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
                //    }
                //} else {
                //    sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
                //}
            } else if (asmRequest.requestType == Request.Authenticate) {
                startAuthentication(sharedPreferences);
                /*try {
                    ASMRequestAuth asmRequestAuth = gson.fromJson(requestMessage, ASMRequestAuth.class);
                    Signature signature = Crypto.getSignatureInstance(Auth.getKeyId(asmRequestAuth, Preferences.create(this, Preferences.FINGERPRINT_PREFERENCE)));
                    if (signature != null) {
                        mCryptoObject = new FingerprintManager.CryptoObject(signature);
                        mFingerprintUiHelper.startListening(mCryptoObject, this);
                    } else {
                        sendErrorResponse(StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY);
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error while creating CryptoObject", e);
                    sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
                }*/
            } else if (asmRequest.requestType == Request.Deregister) {
                processDeregistration();
            } else { // TODO: process other RequestTypes (getInfo, openSettings, etc.)
                sendErrorResponse(null);
            }
        }
    }

    private void startRegistration(SharedPreferences sharedPreferences) {
        ASMRequestReg asmRequestReg = gson.fromJson(requestMessage, ASMRequestReg.class);
        newKeyId = Crypto.generateKeyID(asmRequestReg.args.appID);

        if(Crypto.generateKeyPair(newKeyId)) {
            // TODO: we could skip the save, we can use `KeyStore.aliases` for this, but we have to distinguish between fingerprint and lockscreen and for already created keys this is not so easy
            // add newly created keyId to SharedPreferences, so we recognize it when it is used for authentication
            Set<String> keyIds = Preferences.getParamSet(sharedPreferences, asmRequestReg.args.appID);
            Set<String> newKeyIds = new HashSet<>(keyIds);
            newKeyIds.add(newKeyId);
            Preferences.setParamSet(sharedPreferences, asmRequestReg.args.appID, newKeyIds);

            Signature signature = Crypto.getSignatureInstance(newKeyId);
            if (signature != null) {
                mCryptoObject = new FingerprintManager.CryptoObject(signature);
                mFingerprintContent.setVisibility(View.VISIBLE);
                mFingerprintUiHelper.startListening(mCryptoObject, this);
            } else {
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
            }
        } else {
            sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
        }
    }

    private void startAuthentication(SharedPreferences sharedPreferences) {
        try {
            ASMRequestAuth asmRequestAuth = gson.fromJson(requestMessage, ASMRequestAuth.class);
            // TODO: we could skip the get keyId from sharedPreferences, we could use `KeyStore.aliases` for this
            Signature signature = Crypto.getSignatureInstance(Auth.getKeyId(asmRequestAuth, sharedPreferences));
            if (signature != null) {
                mCryptoObject = new FingerprintManager.CryptoObject(signature);
                mFingerprintUiHelper.startListening(mCryptoObject, this);
            } else {
                sendErrorResponse(StatusCode.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error while creating CryptoObject", e);
            sendErrorResponse(StatusCode.UAF_ASM_STATUS_ERROR);
        }
    }

    private void processRegistration(FingerprintManager.CryptoObject cryptoObject) {
        ASMRequestReg asmRequestReg = gson.fromJson(requestMessage, ASMRequestReg.class);
        Reg reg = new Reg(this);
        String response = reg.reg(asmRequestReg, cryptoObject, newKeyId);
        sendResponse(response);
    }

    private void processAuthentication(FingerprintManager.CryptoObject cryptoObject) {
        ASMRequestAuth asmRequestAuth = gson.fromJson(requestMessage, ASMRequestAuth.class);
        Auth auth = new Auth(this);
        String response = auth.auth(asmRequestAuth, cryptoObject);
        sendResponse(response);
    }

    private void processDeregistration() {
        ASMRequestDereg asmRequestDereg = gson.fromJson(requestMessage, ASMRequestDereg.class);
        Dereg dereg = new Dereg(this);
        sendResponse(dereg.dereg(asmRequestDereg));
    }

    private void sendErrorResponse(StatusCode statusCode) {
        mFingerprintUiHelper.stopListening();
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

    @Override
    public void onAuthenticated(FingerprintManager.CryptoObject cryptoObject) {
        if (asmRequest.requestType == Request.Register) {
            processRegistration(cryptoObject);
        } else {
            processAuthentication(cryptoObject);
        }
    }

    @Override
    public void onError() {
        sendErrorResponse(null);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        switch (requestCode) {
            case MY_PERMISSIONS_USE_FINGERPRINT: {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.length > 0
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    this.onCreate(null);
                } else {
                    new AlertDialog.Builder(this)
                            .setTitle(R.string.requested_permission)
                            .setTitle(R.string.requested_permission)
                            .setMessage(R.string.fingerprint_permission)
                            .setCancelable(true)
                            .setNeutralButton(R.string.button_done, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    dialog.cancel();
                                }
                            })
                            .setOnCancelListener(new DialogInterface.OnCancelListener() {
                                public void onCancel(DialogInterface dialog) {
                                    sendErrorResponse(null);
                                }
                            }).show();
                }
            }
        }
    }
}
