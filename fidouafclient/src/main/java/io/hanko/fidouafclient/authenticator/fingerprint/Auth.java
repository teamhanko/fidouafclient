package io.hanko.fidouafclient.authenticator.fingerprint;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Set;

import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth;
import io.hanko.fidouafclient.asm.msgs.response.AuthenticateOut;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.client.crypto.SHA;
import io.hanko.fidouafclient.client.msg.Transaction;
import io.hanko.fidouafclient.client.tlv.TagsEnum;
import io.hanko.fidouafclient.client.tlv.UnsignedUtil;
import io.hanko.fidouafclient.utility.Crypto;
import io.hanko.fidouafclient.utility.Preferences;

public class Auth {

    private String TAG = "Authenticator_Fingerprint_Auth";
    private Gson gson;
    private FingerprintManager.CryptoObject mCryptoObject;

    private SharedPreferences sharedPreferences;

    public Auth(Context context) {
        gson = new Gson();
        sharedPreferences = Preferences.create(context, Preferences.FINGERPRINT_PREFERENCE);
    }

    public String auth(final ASMRequestAuth asmRequestAuth, FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;

        try {
            String keyID = getKeyId(asmRequestAuth, sharedPreferences);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id));
            byte[] uafV1SignedData = getUafV1SignedDataTag(keyID, asmRequestAuth);
            byte[] signatureTag = getSignatureTag(uafV1SignedData);

            outputStream.write(UnsignedUtil.encodeInt(uafV1SignedData.length + signatureTag.length));
            outputStream.write(uafV1SignedData);
            outputStream.write(signatureTag);

            byte[] assertion = outputStream.toByteArray();

            AuthenticateOut authenticateOut = new AuthenticateOut();
            authenticateOut.assertionScheme = "UAFV1TLV";
            authenticateOut.assertion = Base64.encodeToString(assertion, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

            ASMResponseAuth asmResponseAuth = new ASMResponseAuth();
            asmResponseAuth.statusCode = StatusCode.UAF_ASM_STATUS_OK.getID();
            asmResponseAuth.responseData = authenticateOut;
            asmResponseAuth.exts = null;

            return gson.toJson(asmResponseAuth);
        } catch (Exception e) {
            Log.e(TAG, "Error while auth", e);
        }
        return generateErrorResponse();
    }

    public static String getKeyId(final ASMRequestAuth asmRequestAuth, SharedPreferences sharedPreferences) {
        String keyID;

        Set<String> storedKeyIds = Preferences.getParamSet(sharedPreferences, asmRequestAuth.args.appID);

        if (storedKeyIds.size() > 0) {
            if (asmRequestAuth.args.keyIDs.length > 0) {
                String requestKeyID = asmRequestAuth.args.keyIDs[0];
                if (storedKeyIds.contains(requestKeyID)) {
                    keyID = requestKeyID;
                } else {
                    keyID = storedKeyIds.iterator().next();
                }
            } else {
                keyID = storedKeyIds.iterator().next();
            }
        } else {
            return null;
        }

        return keyID;
    }

    private byte[] getUafV1SignedDataTag(String keyId, ASMRequestAuth asmRequestAuth) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(getAaidTag());
        outputStream.write(getAssertionInfoTag(asmRequestAuth.args.transaction));
        outputStream.write(getAuthenticatorNonceTag());
        outputStream.write(getFinalChallengeTag(asmRequestAuth.args.finalChallenge));
        outputStream.write(getTransactionContentHashTag(asmRequestAuth.args.transaction));
        outputStream.write(getKeyIdTag(keyId));
        outputStream.write(getCountersTag());

        byte[] value = outputStream.toByteArray();

        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        arrayOutputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_SIGNED_DATA.id));
        arrayOutputStream.write(UnsignedUtil.encodeInt(value.length));
        arrayOutputStream.write(value);

        return arrayOutputStream.toByteArray();
    }

    private byte[] getAaidTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AAID.id));
        byte[] value = AuthenticatorConfig.INSTANCE.getAuthenticator().getAaid().getBytes();
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getAssertionInfoTag(Transaction transaction) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));

        byte authenticationMode;
        if (transaction != null) {
            authenticationMode = 0x02;
        } else {
            authenticationMode = 0x01;
        }

        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator_fingerprint version
        // 1 byte = Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature.
        byte[] value = {0x01, 0x00, authenticationMode, 0x01, 0x00};

        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getAuthenticatorNonceTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_AUTHENTICATOR_NONCE.id));
        byte[] value = new byte[8];
        new SecureRandom().nextBytes(value);
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

    private byte[] getTransactionContentHashTag(Transaction transaction) throws IOException, NoSuchAlgorithmException {
        // TODO: show TransactionContent in ASMActivity
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id));
        if (transaction != null) {
            byte[] value = SHA.sha(Base64.decode(transaction.getContent(), Base64.URL_SAFE), "SHA-256");
            outputStream.write(UnsignedUtil.encodeInt(value.length));
            outputStream.write(value);
        } else {
            outputStream.write(UnsignedUtil.encodeInt(0));
        }

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

    private byte[] getCountersTag() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_COUNTERS.id));
        outputStream.write(UnsignedUtil.encodeInt(4));
        outputStream.write(UnsignedUtil.encodeInt32(0));

        return outputStream.toByteArray();
    }

    private byte[] getSignatureTag (byte[] signedData) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_SIGNATURE.id));
        byte[] value = Crypto.getSignature(mCryptoObject, signedData);
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
