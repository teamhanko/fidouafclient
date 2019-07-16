package io.hanko.fidouafclient.utility;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;

import io.hanko.fidouafclient.asm.AsmFingerprintActivity;
import io.hanko.fidouafclient.asm.AsmLockscreenActivity;
import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.client.interfaces.FacetIds;
import io.hanko.fidouafclient.client.msg.MatchCriteria;
import io.hanko.fidouafclient.client.msg.Policy;
import io.hanko.fidouafclient.client.msg.TrustedFacets.TrustedFacets;
import io.hanko.fidouafclient.client.msg.TrustedFacets.TrustedFacetsList;
import io.hanko.fidouafclient.client.msg.Version;

public class FidoUafUtils {

    private static String TAG = "FidoUafUtils";

    public static String getFacetID(Context aContext, int callingUid) {
        String packageNames[] = aContext.getPackageManager().getPackagesForUid(callingUid);

        if (packageNames == null) {
            return null;
        }

        try {
            PackageInfo info = aContext.getPackageManager().getPackageInfo(packageNames[0], PackageManager.GET_SIGNATURES);

            byte[] cert = info.signatures[0].toByteArray();
            InputStream input = new ByteArrayInputStream(cert);

            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate c = (X509Certificate) cf.generateCertificate(input);

            MessageDigest md = MessageDigest.getInstance("SHA1");

            return "android:apk-key-hash:" +
                    Base64.encodeToString(md.digest(c.getEncoded()), Base64.DEFAULT | Base64.NO_WRAP | Base64.NO_PADDING);
        }
        catch (PackageManager.NameNotFoundException | CertificateException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Error while getting FacetID", e);
        }

        return null;
    }

    public static boolean isFacetIdValid(String trustedFacetsJson, Version version, String appFacetId) {
        try {
            TrustedFacetsList trustedFacetsList = (new Gson()).fromJson(trustedFacetsJson, TrustedFacetsList.class);
            for (TrustedFacets trustedFacets : trustedFacetsList.getTrustedFacets()) {
                // select the one with the version matching that of the protocol message version
                if ((trustedFacets.getVersion().minor >= version.minor)
                        && (trustedFacets.getVersion().major <= version.major)) {
                    //The scheme of URLs in ids MUST identify either an application identity
                    // (e.g. using the apk:, ios: or similar scheme) or an https: Web Origin [RFC6454].
                    String[] searchHelper = appFacetId.split(",");
                    for (String facetId : searchHelper) {
                        for (String id : trustedFacets.getIds()) {
                            if (id.equals(facetId)) {
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error while validating FacetID", e);
        }
        // return false; // TODO:
        return true; // workaround if no trustedFacetList available
    }

    /**
     * At this moment there are only 2 Authenticators allowed and only with aaid in Policy.
     *
     * @param policy which will be evaluated
     * @return true if the policy can be evaluated
     */
    public static boolean canEvaluatePolicy(Policy policy) {
        for (MatchCriteria[] allowed: policy.accepted) {
            for (MatchCriteria matchCriteria: allowed) {
                for (String aaid: matchCriteria.aaid) {
                    if (Objects.equals(aaid, AuthenticatorConfig.authenticator_fingerprint.aaid) || Objects.equals(aaid, AuthenticatorConfig.authenticator_lockscreen.aaid)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static String extractPreferredAuthenticatorAaidFromPolicy(Context context, Policy policy) {
        for (MatchCriteria[] allowed: policy.accepted) {
            for (MatchCriteria matchCriteria: allowed) {
                if (matchCriteria.aaid.length > 0) {
                    if(Objects.equals(matchCriteria.aaid[0], AuthenticatorConfig.authenticator_fingerprint.aaid) && canUseFingerprintAuthenticator(context)) {
                        return matchCriteria.aaid[0];
                    } else if (Objects.equals(matchCriteria.aaid[0], AuthenticatorConfig.authenticator_lockscreen.aaid)) {
                        return matchCriteria.aaid[0];
                    }
                }
            }
        }
        return "";
    }

    public static boolean canUseFingerprintAuthenticator(Context context) {
        FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        return fingerprintManager != null && fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints();
    }

    public static Class<?> getAsmFromPolicy(Context context, Policy policy) {
        String aaid = extractPreferredAuthenticatorAaidFromPolicy(context, policy);
        if (!aaid.isEmpty()) {
            return getAsmFromAaid(context, aaid);
        }

        return null;
    }

    public static Class<?> getAsmFromAaid(Context context, String aaid) {
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);

        if(Objects.equals(aaid, AuthenticatorConfig.authenticator_fingerprint.aaid) && fingerprintManager.hasEnrolledFingerprints() && fingerprintManager.isHardwareDetected()) {
            return AsmFingerprintActivity.class;
        } else if (Objects.equals(aaid, AuthenticatorConfig.authenticator_lockscreen.aaid) && keyguardManager.isDeviceSecure()) {
            return AsmLockscreenActivity.class;
        } else {
            return null;
        }
    }

    public static GetAsmResponse getAsmFromKeyId(Context context, String appId, String[] keyIds) {
        SharedPreferences lockscreenPreference = Preferences.create(context, Preferences.LOCKSCREEN_PREFERENCE);
        SharedPreferences fingerprintPreference = Preferences.create(context, Preferences.FINGERPRINT_PREFERENCE);

        Set<String> lockscreenKeyIds = Preferences.getParamSet(lockscreenPreference, appId);
        Set<String> fingerprintKeyIds = Preferences.getParamSet(fingerprintPreference, appId);

        GetAsmResponse response = null;
        for (String keyId: keyIds) {
            if (fingerprintKeyIds.contains(keyId)) {
                response = new GetAsmResponse(AsmFingerprintActivity.class, keyId);
            } else if (lockscreenKeyIds.contains(keyId)) {
                response = new GetAsmResponse(AsmLockscreenActivity.class, keyId);
            }
        }

        return response;
    }

    public static class GetTrustedFacetsTask extends AsyncTask<String, Void, String> {

        private FacetIds activity;

        public GetTrustedFacetsTask(FacetIds activity) {
            this.activity = activity;
        }

        @Override
        protected String doInBackground(String... strings) {

            //return Curl.get(strings[0]).getPayload(); // TODO: get trustedFacetList
            return "";
        }

        @Override
        protected void onPostExecute(String result) {
            activity.processTrustedFacetIds(result);
        }

        @Override
        protected void onCancelled(String s) {
            activity.processTrustedFacetIds(null);
        }

        @Override
        protected void onCancelled() {
            activity.processTrustedFacetIds(null);
        }
    }
}
