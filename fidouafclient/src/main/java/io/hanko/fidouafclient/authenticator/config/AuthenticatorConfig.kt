package io.hanko.fidouafclient.authenticator.config;

import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.client.msg.Version;

object AuthenticatorConfig {

    val supportedVersions = listOf(Version(1, 0), Version(1, 0))
    val attestationTypes: List<Short> = listOf(0x3E08) // 15880 => Surrogate

    val authenticator = Authenticator(
            title = "Hanko Fido UAF Authenticator",
            aaid = "A4A4#0001",
            description = "UAF Fingerprint Client/Authenticator Combo from Hanko",
            supportedUAFVersions = supportedVersions,
            assertionScheme = "UAFV1TLV",
            authenticationAlgorithm = 0x02, // UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
            attestationTypes = attestationTypes,
            userVerification = 0x02, // USER_VERIFY_FINGERPRINT
            keyProtection = 0x02 or 0x04, // KEY_PROTECTION_HARDWARE | KEY_PROTECTION_TEE
            matcherProtection = 0x02, // MATCHER_PROTECTION_TEE
            attachmentHint = 0x01, // ATTACHMENT_HINT_INTERNAL
            isSecondFactorOnly = false,
            tcDisplay = 0x01, // TRANSACTION_CONFIRMATION_DISPLAY_ANY
            tcDisplayContentType = "text/plain",
            tcDisplayPNGCharacteristics = null,
            icon = "",
            supportedExtensionIDs = emptyList()
    )
}
