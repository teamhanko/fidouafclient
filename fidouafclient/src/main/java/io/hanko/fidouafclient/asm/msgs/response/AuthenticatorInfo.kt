package io.hanko.fidouafclient.asm.msgs.response;

import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.client.msg.DisplayPNGCharacteristicsDescriptor;
import io.hanko.fidouafclient.client.msg.Version;

class AuthenticatorInfo (
    val authenticatorIndex: Short,
    val asmVersions: List<Version>,
    val isUserEnrolled: Boolean,
    val hasSettings: Boolean,
    val aaid: String,
    val assertionScheme: String,
    val authenticationAlgorithm: Short,
    val attestationTypes: List<Short>,
    val userVerification: Long,
    val keyProtection: Short,
    val matcherProtection: Short,
    val attachmentHint: Long,
    val isSecondFactorOnly: Boolean,
    val isRoamingAuthenticator: Boolean,
    val supportedExtensionIDs: List<String>,
    val tcDisplay: Short,
    val tcDisplayContentType: String,
    val tcDisplayPNGCharacteristics: List<DisplayPNGCharacteristicsDescriptor>,
    val title: String,
    val description: String,
    val icon: String
) {
    companion object {
        fun fromAuthenticator(authenticator: Authenticator, isUserEnrolled: Boolean): AuthenticatorInfo {
            return AuthenticatorInfo(
                    authenticatorIndex = 1,
                    asmVersions = listOf(Version(1, 1)),
                    isUserEnrolled = isUserEnrolled,
                    hasSettings = false,
                    aaid = authenticator.aaid,
                    assertionScheme = authenticator.assertionScheme,
                    authenticationAlgorithm = authenticator.authenticationAlgorithm,
                    attestationTypes = authenticator.attestationTypes,
                    userVerification = authenticator.userVerification,
                    keyProtection = authenticator.keyProtection,
                    matcherProtection = authenticator.matcherProtection,
                    attachmentHint = authenticator.attachmentHint,
                    isSecondFactorOnly = authenticator.isSecondFactorOnly,
                    isRoamingAuthenticator = false,
                    supportedExtensionIDs = authenticator.supportedExtensionIDs,
                    tcDisplay = authenticator.tcDisplay,
                    tcDisplayContentType = authenticator.tcDisplayContentType,
                    tcDisplayPNGCharacteristics = authenticator.tcDisplayPNGCharacteristics?.let { listOf(it) } ?: emptyList(),
                    title = authenticator.title,
                    description = authenticator.description,
                    icon = authenticator.icon
            )
        }
    }
}
