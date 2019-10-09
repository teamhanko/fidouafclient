package io.hanko.fidouafclient.utility;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

public class Crypto {

    private static String KEYSTORE = "AndroidKeyStore";
    private static String TAG = "Crypto";

    public static boolean generateKeyPair(final String keyId) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
            KeyGenParameterSpec.Builder keyGenSpecBuilder = new KeyGenParameterSpec.Builder(
                    keyId,
                    KeyProperties.PURPOSE_SIGN
            ).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keyGenSpecBuilder.setInvalidatedByBiometricEnrollment(false);
            }

            keyPairGenerator.initialize(keyGenSpecBuilder.build());
            keyPairGenerator.generateKeyPair();
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.e(TAG, "Error while generating KeyPair for fingerprint", e);
            return false;
        }
    }

    public static boolean generateKeyPairForLockscreen(final String keyId) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyId,
                            KeyProperties.PURPOSE_SIGN
                    ).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(5)
                            .build()
            );

            keyPairGenerator.generateKeyPair();
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            Log.e(TAG, "Error while generating KeyPair for lockscreen", e);
            return false;
        }
    }

    @Nullable
    public static String generateKeyID(final String appId) {
        byte[] bytes = new byte[30];
        new SecureRandom().nextBytes(bytes);
        String tmp = appId + Base64.encodeToString(bytes, Base64.DEFAULT);

        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
            messageDigest.update(tmp.getBytes());
            return Base64.encodeToString(messageDigest.digest(), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error while generating KeyID", e);
            return null;
        }
    }

    @Nullable
    public static PublicKey getPublicKeyForKeyId(final String keyId) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry(keyId, null);
            return ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
            Log.e(TAG, "Error while getting public key", e);
        }
        return null;
    }

    public static void deleteKey(final String keyId) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(keyId);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Error while deleting key", e);
        }
    }

    @Nullable
    public static byte[] getSignatureForKeyID(final String keyId, final byte[] signedData) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);

            KeyStore.Entry entry = keyStore.getEntry(keyId, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                return null;
            }

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            signature.update(signedData);
            return signature.sign();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | InvalidKeyException | SignatureException e) {
            Log.e(TAG, "Error while getting signature for keyId", e);
        }
        return null;
    }

    public static Signature getSignatureInstance(final String keyId) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyId, null);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            return signature;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | InvalidKeyException e) {
            Log.e(TAG, "Error while getting Signature Instance", e);
        }
        return null;
    }

    public static byte[] getSignature(FingerprintManager.CryptoObject cryptoObject, byte[] signedData) {
        try {
            Signature signature = cryptoObject.getSignature();
            signature.update(signedData);
            return signature.sign();
        } catch (SignatureException e) {
            Log.e(TAG, "Error while getting signature from crypto object", e);
            return null;
        }
    }
}
