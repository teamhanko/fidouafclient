package io.hanko.fidouafclient.client.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA {

    public static String sha1(String base) {
        return sha(base, "SHA-1");
    }

    public static String sha256(String base) {
        return sha(base, "SHA-256");
    }

    public static String sha(String base, String alg) {
        try {
            MessageDigest digest = MessageDigest.getInstance(alg);
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();

            for (byte aHash : hash) {
                String hex = Integer.toHexString(0xff & aHash);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] sha(byte[] base, String alg) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(alg);
        return digest.digest(base);
    }
}
