package io.hanko.fidouafexample

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Log
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.hanko.fidouafclient.client.msg.MatchCriteria
import io.hanko.fidouafclient.client.msg.UafRegistrationRequest
import io.hanko.fidouafclient.utility.ForceIntDeserializer
import io.hanko.fidouafclient.utility.ForceLongDeserializer
import io.hanko.fidouafclient.utility.ForceStringDeserializer
import io.hanko.fidouafclient.utility.MatchCriteriaDeserializer
import kotlinx.android.synthetic.main.activity_main.*
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException

class MainActivity : AppCompatActivity() {

    companion object {
        private val REQUEST_CODE: Int = 1000
        private val TAG: String = "MainActivity"
    }

    private val uafRegisterRequest = "{\"uafProtocolMessage\":\"[{\\\"username\\\":\\\"example@example.com\\\",\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"appID\\\":\\\"https:\\/\\/example.com\\\",\\\"op\\\":\\\"Reg\\\"},\\\"challenge\\\":\\\"KDfXZs6VzxUgbSZOJFrkvr2v457ePFcP0IsWOvnooikF\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"0018#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0002\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0003\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"]}], [{\\\"aaid\\\":[\\\"A4A4#0003\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]\"}"
    // private String keyId = "<replace-with-generated-keyid>"; // replace with generated keyId from client
    private val keyId = "RCFnd69x3DuooocFPxiCNW97BSCnxK1ECBh8-YtS3NM"
    private val uafAuthenticateRequest = "{\"uafProtocolMessage\":\"[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"appID\\\":\\\"https:\\/\\/example.com\\\",\\\"op\\\":\\\"Auth\\\"},\\\"challenge\\\":\\\"rNmfRjYqwu97rFeYwGNDyPsv2c3D0J8VFyIurvvIxO0F\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"0018#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0001\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0002\\\"]}],[{\\\"aaid\\\":[\\\"C3C3#0003\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"]}],[{\\\"aaid\\\":[\\\"A4A4#0001\\\"],\\\"keyIDs\\\":[\\\"<keyid>\\\"]}], [{\\\"aaid\\\":[\\\"A4A4#0003\\\"],\\\"keyIDs\\\":[\\\"<keyid>\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"FFFF#FFFF\\\"]}]}}]\"}"

    private val matchCriteriaString_P1 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\": [\"A4A4#0001\"]}]]}}]"
    private val matchCriteriaString_P2 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1], \"assertionSchemes\":[\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F1_1 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": {}}}]"
    private val matchCriteriaString_F1_2 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": null}}]"
    private val matchCriteriaString_F1_3 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": []}}]"
    private val matchCriteriaString_F2 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": {}}}]"
    private val matchCriteriaString_F3 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [\"aaid\":\"A4A4#0001\"]}}]"
    private val matchCriteriaString_F4 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [28688]}}]"
    private val matchCriteriaString_F5 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[45232]]}}]"
    private val matchCriteriaString_F6 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\": \"A4A4#0001\"}]]}}]"
    private val matchCriteriaString_F7 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\": [\"A4A4#0001\", 42]}]]}}]"
    private val matchCriteriaString_F8 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"vendorID\": [\"A4A4\", 42]}]]}}]"
    private val matchCriteriaString_F9 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"vendorID\": 42, \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]]}]}}]"
    private val matchCriteriaString_F10 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"keyIDs\": {}, \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F11 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"keyIDs\": [0xdeadbeef], \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F12 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"keyIDs\": [\"mNxQs+Agq9GexsFq7t4VX/QR-sPYJKSZ2zdiUcJCab=\"], \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F13 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"userVerification\": \"1023\", \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F14 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"keyProtection\": \"10\", \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F15 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"matcherProtection\": \"4\", \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F16 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"attachmentHint\": \"2\", \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F17 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"tcDisplay\": \"0\", \"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F18 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": {}, \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F19 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1, \"4\"], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_F20 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1], \"assertionSchemes\": {}}]]}}]"
    private val matchCriteriaString_F21 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\", 0xdeadbeef]}]]}}]"
    private val matchCriteriaString_F22 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"], \"attestationTypes\":{}}]]}}]"
    private val matchCriteriaString_F23 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [1], \"assertionSchemes\": [\"UAFV1TLV\"], \"attestationTypes\":[15880, \"15880\"]}]]}}]"
    private val matchCriteriaString_F24 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\":[\"A4A4#0001\"], \"authenticatorVersion\":\"42\"}]]}}]"
    private val matchCriteriaString_F25 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\":[\"A4A4#0001\"], \"exts\":{}}]]}}]"
    private val matchCriteriaString_F26 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\":[\"A4A4#0001\"], \"exts\":[[],{\"id\":\"unknown-id\",\"data\":\"\",\"fail_if_unknown\":false}]}]]}}]"
    private val matchCriteriaString_P28 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\": [\"A4A4#0001\"], \"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_P29 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"assertionSchemes\": [\"UAFV1TLV\"]}]]}}]"
    private val matchCriteriaString_P30 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1},\"op\": \"Reg\",\"appID\": \"\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"authenticationAlgorithms\": [2]}]]}}]"

    private val extensionString_P1 = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 1} ,\"exts\": [{\"id\": \"unknown_id\", \"data\": \"\", \"fail_if_unknown\": false}],\"op\": \"Reg\",\"appID\": \"https://uaf.example.com\"},\"challenge\": \"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\": \"hello@test.com\",\"policy\": {\"accepted\": [[{\"aaid\": [\"A4A4#0001\"]}]]}}]"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        buttonRegister.setOnClickListener { startFidoClient(uafRegisterRequest); }
        buttonAuthenticate.setOnClickListener { startFidoClient(uafAuthenticateRequest.replace("<keyid>", keyId)); }

//        testDeserialization()
//        startFidoClient("{\"uafProtocolMessage\": \"${matchCriteriaString_P30.replace("\"", "\\\"")}\"}")
    }

    private fun testDeserialization() {
        val objectMapper = ObjectMapper()
                .registerKotlinModule()
                .registerModule(
                        SimpleModule()
                                .addDeserializer(String::class.java, ForceStringDeserializer())
                                .addDeserializer(Int::class.java, ForceIntDeserializer())
                                .addDeserializer(Long::class.java, ForceLongDeserializer())
                                .addDeserializer(MatchCriteria::class.java, MatchCriteriaDeserializer())
                )

        try {
            val uafRegistrationRequests = objectMapper.readValue(extensionString_P1, Array<UafRegistrationRequest>::class.java)
            Log.w(TAG, "MatchCriteria parsed successful")
        } catch (ex: IOException) {
            Log.w(TAG, "Exception while parsing matchCriteria", ex)
        }
    }

    private fun startFidoClient(message: String) {
        val intent = Intent(this, io.hanko.fidouafclient.client.MainActivity::class.java)
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
            if (errorCode == 0x00.toShort()) {
                try {
                    val jsonObject = JSONObject(data.getStringExtra("message"))
                    val uafResponse = jsonObject.getString("uafProtocolMessage")

                    Log.i(TAG, "uafResponse: $uafResponse")
                } catch (ex: JSONException) {
                    Log.e(TAG, "Error", ex)
                }
            } else {
                Log.e(TAG, "ErrorCode: $errorCode")
            }
        } else {
            Log.e(TAG, "ResultCode: $resultCode")
        }
    }
}
