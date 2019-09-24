package io.hanko.fidouafclient.asm.msgs.response;

import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.client.msg.DisplayPNGCharacteristicsDescriptor;
import io.hanko.fidouafclient.client.msg.Version;

public class AuthenticatorInfo {
    public short authenticatorIndex;
    public Version[] asmVersions;
    public boolean isUserEnrolled;
    public boolean hasSettings;
    public String aaid;
    public String assertionScheme;
    public short authenticationAlgorithm;
    public short[] attestationTypes;
    public long userVerification;
    public short keyProtection;
    public short matcherProtection;
    public long attachmentHint;
    public boolean isSecondFactorOnly;
    public boolean isRoamingAuthenticator;
    public String[] supportedExtensionIDs;
    public short tcDisplay;
    public String tcDisplayContentType;
    public DisplayPNGCharacteristicsDescriptor[] tcDisplayPNGCharacteristics;
    public String title;
    public String description;
    public String icon;

    public static AuthenticatorInfo fromAuthenticator(Authenticator authenticator, boolean isUserEnrolled) {
        AuthenticatorInfo authenticatorInfo = new AuthenticatorInfo();
        authenticatorInfo.authenticatorIndex = 1;
        authenticatorInfo.asmVersions = new Version[]{new Version(1, 1)};
        authenticatorInfo.isUserEnrolled = true; // TODO
        authenticatorInfo.hasSettings = false;
        authenticatorInfo.aaid = authenticator.aaid;
        authenticatorInfo.assertionScheme = authenticator.assertionScheme;
        authenticatorInfo.authenticationAlgorithm = authenticator.authenticationAlgorithm;
        authenticatorInfo.attestationTypes = authenticator.attestationTypes;
        authenticatorInfo.userVerification = authenticator.userVerification;
        authenticatorInfo.keyProtection = authenticator.keyProtection;
        authenticatorInfo.matcherProtection = authenticator.matcherProtection;
        authenticatorInfo.attachmentHint = authenticator.attachmentHint;
        authenticatorInfo.isSecondFactorOnly = authenticator.isSecondFactorOnly;
        authenticatorInfo.isRoamingAuthenticator = false;
        authenticatorInfo.supportedExtensionIDs = new String[]{};
        authenticatorInfo.tcDisplay = authenticator.tcDisplay;
        authenticatorInfo.tcDisplayContentType = authenticator.tcDisplayContentType;
        if (authenticator.tcDisplayPNGCharacteristics != null)
            authenticatorInfo.tcDisplayPNGCharacteristics = new DisplayPNGCharacteristicsDescriptor[] { authenticator.tcDisplayPNGCharacteristics };
        else
            authenticatorInfo.tcDisplayPNGCharacteristics = null;

        authenticatorInfo.title = authenticator.title;
        authenticatorInfo.description = authenticator.description;
        authenticatorInfo.icon = authenticator.icon;

        return authenticatorInfo;
    }
}
