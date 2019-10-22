package io.hanko.fidouafclient.authenticator.op;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import io.hanko.fidouafclient.asm.msgs.StatusCode;
import io.hanko.fidouafclient.asm.msgs.request.ASMRequestAuth;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponse;
import io.hanko.fidouafclient.asm.msgs.response.ASMResponseAuth;
import io.hanko.fidouafclient.asm.msgs.response.AuthenticateOut;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorMetadata;
import io.hanko.fidouafclient.authenticator.util.SHA;
import io.hanko.fidouafclient.client.msg.Transaction;
import io.hanko.fidouafclient.authenticator.util.tlv.TagsEnum;
import io.hanko.fidouafclient.authenticator.util.tlv.UnsignedUtil;
import io.hanko.fidouafclient.util.Crypto;
import io.hanko.fidouafclient.util.Util;

public class Auth {

    private String TAG = "Authenticator";

    public String auth(final ASMRequestAuth asmRequestAuth) {
        try {
            String keyID = getKeyId(asmRequestAuth);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id));
            byte[] uafV1SignedData = getUafV1SignedDataTag(keyID, asmRequestAuth);
            byte[] signatureTag = getSignatureTag(uafV1SignedData, asmRequestAuth.getArgs().getAppID(), keyID);

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

            return Util.INSTANCE.getObjectMapper().writeValueAsString(asmResponseAuth);
        } catch (Exception e) {
            Log.e(TAG, "Authentication signature could not be generated", e);
        }
        return generateErrorResponse();
    }

    private static String getKeyId(final ASMRequestAuth asmRequestAuth) {
        List<String> keyAliases = Crypto.INSTANCE.getStoredKeyIds(asmRequestAuth.getArgs().getAppID(), asmRequestAuth.getArgs().getKeyIDs());
        if (keyAliases != null && !keyAliases.isEmpty()) {
            return keyAliases.get(0);
        } else {
            return null;
        }
    }

    private byte[] getUafV1SignedDataTag(String keyId, ASMRequestAuth asmRequestAuth) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(getAaidTag());
        outputStream.write(getAssertionInfoTag(asmRequestAuth.getArgs().getTransaction()));
        outputStream.write(getAuthenticatorNonceTag());
        outputStream.write(getFinalChallengeTag(asmRequestAuth.getArgs().getFinalChallenge()));
        outputStream.write(getTransactionContentHashTag(asmRequestAuth.getArgs().getTransaction()));
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
        byte[] value = AuthenticatorMetadata.INSTANCE.getAuthenticator().getAaid().getBytes();
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
        // 2 byte = Vendor assigned authenticator_fingerprint version // 0x01 0x00 = 1
        // 1 byte = Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature. // 0x02 0x00 = 2
        byte[] value = {0x01, 0x00, authenticationMode, 0x02, 0x00};

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
        byte[] value = SHA.INSTANCE.sha(finalChallenge.getBytes(), "SHA-256");
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    private byte[] getTransactionContentHashTag(Transaction transaction) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id));
        if (transaction != null) {
            byte[] value = SHA.INSTANCE.sha(Base64.decode(transaction.getContent(), Base64.URL_SAFE), "SHA-256");
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

    private byte[] getSignatureTag (byte[] signedData, String appId, String keyId) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(UnsignedUtil.encodeInt(TagsEnum.TAG_SIGNATURE.id));
        byte[] value = Crypto.INSTANCE.getSignatureForKeyID(keyId, signedData, appId);
        outputStream.write(UnsignedUtil.encodeInt(value.length));
        outputStream.write(value);

        return outputStream.toByteArray();
    }


    private String generateErrorResponse() {
        try {
            ASMResponse asmResponse = new ASMResponse();
            asmResponse.statusCode = StatusCode.UAF_ASM_STATUS_ERROR.getID();
            return Util.INSTANCE.getObjectMapper().writeValueAsString(asmResponse);
        } catch (Exception ex) {
            Log.e(TAG, "Could not generate error response.", ex);
            return "";
        }
    }
}
