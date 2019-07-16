package io.hanko.fidouafclient.authenticator.config;

import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.client.msg.Version;

public class AuthenticatorConfig {

    private static Version[] supportedVersions = { new Version(1,0) };
    private static short[] attestationTypes = { 0x3E08 };

    public static Authenticator authenticator_fingerprint = new Authenticator(
            "Hanko Fido UAF Authenticator (Fingerprint)",
            "A4A4#0001",
            "UAF Fingerprint Client/Authenticator from Hanko",
            supportedVersions,
            "UAFV1TLV",
            (short) 0x02, // UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
            attestationTypes,
            0x02, // USER_VERIFY_FINGERPRINT
            (short) (0x02 | 0x04), // KEY_PROTECTION_HARDWARE | KEY_PROTECTION_TEE
            (short) 0x02, // MATCHER_PROTECTION_TEE
            0x01, // ATTACHMENT_HINT_INTERNAL
            false,
            (short) 0x01, // TRANSACTION_CONFIRMATION_DISPLAY_ANY
            "text/plain",
            null,
            "",
            null
    );

    public static Authenticator authenticator_lockscreen = new Authenticator(
            "Hanko FIDO UAF Authenticator (Lockscreen)",
            "A4A4#0003",
            "UAF Lockscreen Client/Authenticator from Hanko",
            supportedVersions,
            "UAFV1TLV",
            (short) 0x02,  // UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
            attestationTypes,
            0x02 | 0x04 | 0x80, // USER_VERIFY_FINGERPRINT (0x02) || USER_VERIFY_PASSCODE (0x04) || USER_VERIFY_PATTERN (0x80)
            (short) (0x02 | 0x04), // KEY_PROTECTION_HARDWARE | KEY_PROTECTION_TEE
            (short) 0x02, // MATCHER_PROTECTION_TEE
            0x01, // ATTACHMENT_HINT_INTERNAL
            false,
            (short) 0x01, // TRANSACTION_CONFIRMATION_DISPLAY_ANY
            "text/plain",
            null,
            "",
            null
    );
}
