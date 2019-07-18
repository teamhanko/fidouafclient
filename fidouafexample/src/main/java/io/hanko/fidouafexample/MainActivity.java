package io.hanko.fidouafexample;

import android.content.Intent;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import org.json.JSONException;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {

    private static int REQUEST_CODE = 1000;
    private static String TAG = "MainActivity";

    private String uafRegisterRequest = "{\"uafProtocolMessage\":\"[{\\\"username\\\":\\\"example@example.com\\\",\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"appID\\\":\\\"https:\\/\\/example.com\\\",\\\"op\\\":\\\"Reg\\\"},\\\"challenge\\\":\\\"KDfXZs6VzxUgbSZOJFrkvr2v457ePFcP0IsWOvnooikF\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"0018#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0002\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0003\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"]}], [{\\\"aaid\\\":[\\\"A4A4#0003\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]\"}";
    // private String keyId = "<replace-with-generated-keyid>"; // replace with generated keyId from client
    private String keyId = "RCFnd69x3DuooocFPxiCNW97BSCnxK1ECBh8-YtS3NM";
    private String uafAuthenticateRequest = "{\"uafProtocolMessage\":\"[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"appID\\\":\\\"https:\\/\\/example.com\\\",\\\"op\\\":\\\"Auth\\\"},\\\"challenge\\\":\\\"rNmfRjYqwu97rFeYwGNDyPsv2c3D0J8VFyIurvvIxO0F\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"0018#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0002\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0003\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"],\\\"keyIDs\\\":[\\\"<keyid>\\\"]}], [{\\\"aaid\\\":[\\\"A4A4#0003\\\"],\\\"keyIDs\\\":[\\\"<keyid>\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]\"}";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button registerButton = findViewById(R.id.buttonRegister);
        Button authenticateButton = findViewById(R.id.buttonAuthenticate);

        registerButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startFidoClient(uafRegisterRequest);
            }
        });

        authenticateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startFidoClient(uafAuthenticateRequest.replaceAll("<keyid>", keyId));
            }
        });
    }

    private void startFidoClient(String message) {
        Intent intent = new Intent(MainActivity.this, io.hanko.fidouafclient.client.MainActivity.class);
        intent.setType("application/fido.uaf_client+json");
        intent.putExtra("UAFIntentType", "UAF_OPERATION");
        intent.putExtra("channelBindings", "{}");
        intent.putExtra("message", message);

        startActivityForResult(intent, REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode == RESULT_OK && requestCode == REQUEST_CODE) {
            short errorCode = data.getShortExtra("errorCode", (short) 0xFF);
            if (errorCode == 0x00) {
                try {
                    JSONObject jsonObject = new JSONObject(data.getStringExtra("message"));
                    String uafResponse = jsonObject.getString("uafProtocolMessage");

                    Log.i(TAG, "uafResponse: " + uafResponse);
                } catch (JSONException ex) {
                    Log.e(TAG, "Error", ex);
                }
            }
        }
    }
}
