package io.hanko.fidouafexample

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import io.hanko.fidouafclient.client.msg.client.ErrorCode
import kotlinx.android.synthetic.main.activity_main.*
import org.json.JSONException
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    companion object {
        private val REQUEST_CODE: Int = 1000
        private val TAG: String = "FidoUafClient"
    }

    private val uafRegisterProtocolMessage = "[{\\\"username\\\":\\\"example@example.com\\\",\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":1},\\\"appID\\\":\\\"\\\",\\\"op\\\":\\\"Reg\\\"},\\\"challenge\\\":\\\"KDfXZs6VzxUgbSZOJFrkvr2v457ePFcP0IsWOvnooikF\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"006F#0001\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]"
    private val uafAuthenticationProtocolMessage = "[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":1},\\\"appID\\\":\\\"\\\",\\\"op\\\":\\\"Auth\\\"},\\\"challenge\\\":\\\"rNmfRjYqwu97rFeYwGNDyPsv2c3D0J8VFyIurvvIxO0F\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"006F#0001\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]"
    private val uafDeregisterProtocolMessage = "[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":1},\\\"appID\\\":\\\"\\\",\\\"op\\\":\\\"Dereg\\\"},\\\"authenticators\\\":[{\\\"aaid\\\":\\\"\\\", \\\"keyID\\\":\\\"\\\"}]}]"


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        buttonRegister.setOnClickListener { startFidoClient(uafMessage(uafRegisterProtocolMessage)) }
        buttonAuthenticate.setOnClickListener { startFidoClient(uafMessage(uafAuthenticationProtocolMessage)) }
        buttonDeregister.setOnClickListener { startFidoClient(uafMessage(uafDeregisterProtocolMessage)) }
    }

    private fun startFidoClient(message: String) {
        val intent = Intent(this, io.hanko.fidouafclient.FidoUafClient::class.java)
        intent.type = "application/fido.uaf_client+json"
        intent.putExtra("UAFIntentType", "UAF_OPERATION")
        intent.putExtra("channelBindings", "{}")
        intent.putExtra("message", message)

        startActivityForResult(intent, REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (resultCode == RESULT_OK && requestCode == REQUEST_CODE) {
            val errorCode = data?.getShortExtra("errorCode", 0xFF.toShort())
            textViewResultErrorCodeContent.text = ErrorCode.values().find { it.id == errorCode }?.toString()
            if (errorCode == 0x00.toShort()) {
                try {
                    val jsonObject = JSONObject(data.getStringExtra("message"))
                    val uafResponse = jsonObject.getString("uafProtocolMessage")

                    textViewResultContent.text = uafResponse

                    Log.i(TAG, "uafResponse: $uafResponse")
                } catch (ex: JSONException) {
                    Log.e(TAG, "Error", ex)
                }
            } else {
                textViewResultContent.text = ""
                Log.e(TAG, "ErrorCode: $errorCode")
            }
        } else {
            Log.e(TAG, "ResultCode: $resultCode")
        }
    }

    private fun uafMessage(protocolMessage: String): String {
        return "{\"uafProtocolMessage\":\"$protocolMessage\"}"
    }
}
