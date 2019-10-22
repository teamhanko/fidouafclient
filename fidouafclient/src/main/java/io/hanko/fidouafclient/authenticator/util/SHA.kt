package io.hanko.fidouafclient.authenticator.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

object SHA {

    fun sha(base: ByteArray, alg: String): ByteArray {
        val digest = MessageDigest.getInstance(alg)
        return digest.digest(base)
    }
}
