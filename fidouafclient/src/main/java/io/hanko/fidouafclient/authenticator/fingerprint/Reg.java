package io.hanko.fidouafclient.authenticator.fingerprint;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestReg;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseReg;
import io.hanko.fidouafclient.asm.msgs.response.RegisterOut;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.client.crypto.SHA;
import io.hanko.fidouafclient.client.tlv.TagsEnum;
import io.hanko.fidouafclient.client.tlv.UnsignedUtil;
import io.hanko.fidouafclient.utility.Crypto;
import io.hanko.fidouafclient.utility.Preferences;

@RequiresApi(api = Build.VERSION_CODES.M)
public class Reg {

    private String TAG = "Authenticator_Fingerprint_Reg";
    private Gson gson;
    private SharedPreferences sharedPreferences;

    public Reg(Context context) {
        gson = new Gson();
        sharedPreferences = Preferences.create(context, Preferences.FINGERPRINT_PREFERENCE);
    }

    /**
     *
     * @param asmRequestReg
     * @return stringified ASMResponse json
     */
    public String reg(final ASMRequestReg asmRequestReg, FingerprintManager.CryptoObject cryptoObject, String keyId) {

        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_REG_ASSERTION.id));
            byte[] uafV1Krd = getUafV1Krd(keyId, asmRequestReg.args.finalChallenge);
            byte[] attestationTag = getAttestationTag(uafV1Krd, cryptoObject);

            outputStream.write(UnsignedUtil.encodeInt(uafV1Krd.length + attestationTag.length));
            outputStream.write(uafV1Krd);
            outputStream.write(attestationTag);

            byte[] assertion = outputStream.toByteArray();

            RegisterOut registerOut = new RegisterOut();
            registerOut.assertionScheme = "UAFV1TLV";
            registerOut.assertion = Base64.encodeToString(assertion, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

            ASMResponseReg asmResponseReg = new ASMResponseReg();
            asmResponseReg.statusCode = StatusCode.UAF_ASM_STATUS_OK.getID();
            asmResponseReg.responseData = registerOut;
            asmResponseReg.exts = null;

            return gson.toJson(asmResponseReg);
        } catch (IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Error while reg", e);
        }
        return generateErrorResponse();
    }

    private byte[] getUafV1Krd(String keyId, String finalChallenge) throws IOException, NoSuchAlgorithmException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(getAaidTag());
        outputStream.write(getAsserionInfoTag());
        outputStream.write(getFinalChallengeTag(finalChallenge));
        outputStream.write(getKeyIdTag(keyId));
        outputStream.write(getCountersTag());
        outputStream.write(getPublicKeyTag(keyId));

        byte[] value = outputStream.toByteArray();

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        arrayOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_KRD.id));
        arrayOutputStream.write(UnsignedUtil.encodeInt(value.length));
        arrayOutputStream.write(value);

        return arrayOutputStream.toByteArray();
    }

    private byte[] getAttestationTag(byte[] signedData, FingerprintManager.CryptoObject cryptoObject) throws IOException {

        // TAG_SIGNATURE
        ByteArrayOutputStream signatureOutputStream = new ByteArrayOutputStream();
        signatureOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_SIGNATURE.id));
        byte [] sig = Crypto.getSignature(cryptoObject, signedData);
        signatureOutputStream.write(UnsignedUtil.encodeInt(sig.length));
        signatureOutputStream.write(sig);

        byte[] signatureTag = signatureOutputStream.toByteArray();

        // TAG_ATTESTATION_BASIC_SURROGATE
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id));
        outputStream.write(UnsignedUtil.encodeInt(signatureTag.length));
        outputStream.write(signatureTag);

        return outputStream.toByteArray();
    }

    private byte[] getAaidTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AAID.id));
        byte[] value = AuthenticatorConfig.authenticator_fingerprint.aaid.getBytes();
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getKeyIdTag(String keyID) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_KEYID.id));
        byte[] value = Base64.decode(keyID, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getFinalChallengeTag(String finalChallenge) throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_FINAL_CHALLENGE.id));
        byte[] value = SHA.sha(finalChallenge.getBytes(), "SHA-256");
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getCountersTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_COUNTERS.id));
        outputStream.write(UnsignedUtil.encodeInt(8));
        outputStream.write(UnsignedUtil.encodeInt32(0));
        outputStream.write(UnsignedUtil.encodeInt32(0));

        return outputStream.toByteArray();
    }

    private byte[] getPublicKeyTag(String keyId) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_PUB_KEY.id));
        byte[] value = Crypto.getPublicKeyForKeyId(keyId).getEncoded();
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getAsserionInfoTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));
        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator_fingerprint version
        // 1 byte = For Registration this must be 0x01 indicating that the user has explicitly verified the action.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature.
        // 2 byte = Public Key algorithm and encoding of the newly generated UAuth.pub key.
        byte[] value = {0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00};
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private String generateErrorResponse() {
        ASMResponse asmResponse = new ASMResponse();
        asmResponse.statusCode = StatusCode.UAF_ASM_STATUS_ERROR.getID();
        return gson.toJson(asmResponse);
    }
}
